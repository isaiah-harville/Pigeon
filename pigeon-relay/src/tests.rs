// Tests for the blind-mailbox invariants, exercised without a socket.
// Declared from `main.rs` as `#[cfg(test)] mod tests;` so it can reach the
// crate-private mailbox operations.

use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use tokio::sync::mpsc;

use crate::coordinator_store::{CoordinatorConfig, CoordinatorStore};
use crate::group_store::{GroupStore, GroupStoreConfig};
use crate::mailbox::{
    ack, expire_mailboxes, flush_queue, publish, register_push, register_subscriber,
    remove_subscriber, switch_subscription, verify_ownership,
};
use crate::protocol::{
    gate_protocol_message, select_protocol, ClientMsg, ProtocolGate, ServerMsg,
    PROTOCOL_MAX_VERSION, PROTOCOL_MIN_VERSION,
};
use crate::push::PushRegistry;
use crate::state::{
    is_valid_address, AppState, Config, Store, MAX_CIPHERTEXT_LEN, PUBKEY_LEN,
    SUBSCRIBER_CHANNEL_CAPACITY,
};

fn state(ttl_secs: u64, max_queue: usize) -> AppState {
    bounded_state(ttl_secs, max_queue, usize::MAX, usize::MAX)
}

/// A relay with explicit capacity ceilings, for the bounds tests.
fn bounded_state(
    ttl_secs: u64,
    max_queue: usize,
    max_mailboxes: usize,
    max_total_bytes: usize,
) -> AppState {
    AppState {
        mailboxes: Arc::new(Mutex::new(Store::default())),
        cfg: Config {
            ttl_secs,
            max_queue,
            max_mailboxes,
            max_total_bytes,
        },
        counter: Arc::new(AtomicU64::new(1)),
        // No gateway: deposits never attempt a push in these tests.
        push: Arc::new(PushRegistry::new(None, Duration::from_secs(30))),
        groups: Arc::new(Mutex::new(GroupStore::bounded(GroupStoreConfig {
            ttl_secs,
            max_groups: 16,
            max_capabilities_per_group: 128,
            max_entry_bytes: MAX_CIPHERTEXT_LEN,
            max_entries_per_group: max_queue,
            max_total_bytes,
            max_fetch_batch_bytes: MAX_CIPHERTEXT_LEN,
        }))),
        group_subscribers: Arc::new(Mutex::new(std::collections::HashMap::new())),
        coordinator: Arc::new(Mutex::new(CoordinatorStore::new(
            CoordinatorConfig {
                max_candidates_per_epoch: 256,
                max_candidate_bytes: MAX_CIPHERTEXT_LEN,
                max_total_bytes,
                max_fetch_batch_bytes: MAX_CIPHERTEXT_LEN,
                ttl_secs,
            },
            SigningKey::from_bytes(&[99; 32]),
        ))),
    }
}

fn channel() -> (mpsc::Sender<ServerMsg>, mpsc::Receiver<ServerMsg>) {
    mpsc::channel(SUBSCRIBER_CHANNEL_CAPACITY)
}

#[test]
fn protocol_negotiation_selects_the_highest_overlap() {
    assert_eq!(
        select_protocol(1, PROTOCOL_MAX_VERSION),
        Some(PROTOCOL_MAX_VERSION)
    );
    assert_eq!(
        select_protocol(PROTOCOL_MIN_VERSION, PROTOCOL_MIN_VERSION),
        Some(1)
    );
}

#[test]
fn protocol_negotiation_rejects_disjoint_and_invalid_ranges() {
    assert_eq!(select_protocol(2, 3), None);
    assert_eq!(select_protocol(1, 0), None);
}

#[test]
fn hello_and_compatible_frames_use_the_documented_json_shape() {
    let hello: ClientMsg = serde_json::from_str(
        r#"{"type":"hello","min_protocol_version":1,"max_protocol_version":1}"#,
    )
    .unwrap();
    assert!(matches!(hello, ClientMsg::Hello { .. }));
    assert_eq!(
        serde_json::to_string(&ServerMsg::Compatible {
            protocol_version: 1,
            relay_version: "0.2.0".into(),
            min_protocol_version: 1,
            max_protocol_version: 1,
        })
        .unwrap(),
        r#"{"type":"compatible","protocol_version":1,"relay_version":"0.2.0","min_protocol_version":1,"max_protocol_version":1}"#
    );
}

#[test]
fn incompatible_frame_identifies_the_relay_release_and_protocol_range() {
    assert_eq!(
        serde_json::to_string(&ServerMsg::Incompatible {
            relay_version: "0.2.0".into(),
            min_protocol_version: 2,
            max_protocol_version: 3,
        })
        .unwrap(),
        r#"{"type":"incompatible","relay_version":"0.2.0","min_protocol_version":2,"max_protocol_version":3}"#
    );
}

#[test]
fn mailbox_operations_are_rejected_until_protocol_negotiation_succeeds() {
    let mut negotiated = false;
    let publish: ClientMsg =
        serde_json::from_str(r#"{"type":"publish","recipient":"00","ciphertext":"Y2lwaGVy"}"#)
            .unwrap();

    assert!(matches!(
        gate_protocol_message(publish, &mut negotiated),
        ProtocolGate::Reply(ServerMsg::Error { .. })
    ));
    assert!(!negotiated);

    let incompatible: ClientMsg = serde_json::from_str(
        r#"{"type":"hello","min_protocol_version":2,"max_protocol_version":3}"#,
    )
    .unwrap();
    assert!(matches!(
        gate_protocol_message(incompatible, &mut negotiated),
        ProtocolGate::Reply(ServerMsg::Incompatible { .. })
    ));
    assert!(!negotiated);
}

#[test]
fn compatible_hello_unlocks_mailbox_operations() {
    let mut negotiated = false;
    let hello: ClientMsg = serde_json::from_str(
        r#"{"type":"hello","min_protocol_version":1,"max_protocol_version":1}"#,
    )
    .unwrap();
    assert!(matches!(
        gate_protocol_message(hello, &mut negotiated),
        ProtocolGate::Reply(ServerMsg::Compatible {
            protocol_version: 1,
            ..
        })
    ));
    assert!(negotiated);

    let auth: ClientMsg = serde_json::from_str(r#"{"type":"auth","signature":"c2ln"}"#).unwrap();
    assert!(matches!(
        gate_protocol_message(auth, &mut negotiated),
        ProtocolGate::Proceed(ClientMsg::Auth { .. })
    ));
}

/// A syntactically valid 32-byte mailbox address (64 hex chars).
fn addr(byte: u8) -> String {
    hex::encode([byte; PUBKEY_LEN])
}

fn queue_len(state: &AppState, mailbox: &str) -> usize {
    state
        .mailboxes
        .lock()
        .unwrap()
        .get(mailbox)
        .map_or(0, |m| m.queue.len())
}

fn total_bytes(state: &AppState) -> usize {
    state.mailboxes.lock().unwrap().total_bytes()
}

fn mailbox_count(state: &AppState) -> usize {
    state.mailboxes.lock().unwrap().len()
}

fn subscriber_count(state: &AppState, mailbox: &str) -> usize {
    state
        .mailboxes
        .lock()
        .unwrap()
        .get(mailbox)
        .map_or(0, |m| m.subscribers.len())
}

#[test]
fn valid_address_requires_exactly_32_bytes() {
    assert!(is_valid_address(&addr(0xAB)));
    assert!(!is_valid_address("dead")); // too short
    assert!(!is_valid_address(&"ab".repeat(33))); // 33 bytes
    assert!(!is_valid_address(&"zz".repeat(32))); // not hex
}

#[test]
fn publish_rejects_invalid_recipient() {
    let st = state(3600, 100);
    let (tx, mut rx) = channel();
    publish(&st, &tx, "nothex".into(), "Y2lwaGVy".into());
    assert!(matches!(rx.try_recv().unwrap(), ServerMsg::Error { .. }));
    assert_eq!(st.mailboxes.lock().unwrap().len(), 0);
}

#[test]
fn publish_rejects_empty_and_oversized_ciphertext() {
    let st = state(3600, 100);
    let (tx, mut rx) = channel();
    publish(&st, &tx, addr(1), String::new());
    assert!(matches!(rx.try_recv().unwrap(), ServerMsg::Error { .. }));
    publish(&st, &tx, addr(1), "a".repeat(MAX_CIPHERTEXT_LEN + 1));
    assert!(matches!(rx.try_recv().unwrap(), ServerMsg::Error { .. }));
    assert_eq!(queue_len(&st, &addr(1)), 0);
}

#[test]
fn publish_is_addressed_to_one_mailbox() {
    let st = state(3600, 100);
    let (tx, mut rx) = channel();
    publish(&st, &tx, addr(1), "Y2lwaGVy".into());
    assert!(matches!(
        rx.try_recv().unwrap(),
        ServerMsg::Published { .. }
    ));
    assert_eq!(queue_len(&st, &addr(1)), 1);
    assert_eq!(queue_len(&st, &addr(2)), 0); // never lands in another mailbox
}

#[test]
fn publish_fans_out_live_and_still_queues() {
    let st = state(3600, 100);
    let (ptx, _prx) = channel();
    let (stx, mut srx) = channel();
    register_subscriber(&st, &addr(1), 7, stx);
    publish(&st, &ptx, addr(1), "Y2lwaGVy".into());
    assert!(matches!(
        srx.try_recv().unwrap(),
        ServerMsg::Envelope { .. }
    ));
    assert_eq!(queue_len(&st, &addr(1)), 1); // retained until acked
}

#[test]
fn flush_queue_replays_everything_stored() {
    let st = state(3600, 100);
    let (ptx, _prx) = channel();
    publish(&st, &ptx, addr(1), "b25l".into());
    publish(&st, &ptx, addr(1), "dHdv".into());
    let (ftx, mut frx) = channel();
    flush_queue(&st, &addr(1), &ftx);
    let mut count = 0;
    while let Ok(ServerMsg::Envelope { .. }) = frx.try_recv() {
        count += 1;
    }
    assert_eq!(count, 2);
}

#[test]
fn ack_deletes_only_the_named_envelope() {
    let st = state(3600, 100);
    let (ptx, mut prx) = channel();
    publish(&st, &ptx, addr(1), "b25l".into());
    publish(&st, &ptx, addr(1), "dHdv".into());
    let id = match prx.try_recv().unwrap() {
        ServerMsg::Published { id } => id,
        _ => panic!("expected a Published reply"),
    };
    ack(&st, &addr(1), &id);
    assert_eq!(queue_len(&st, &addr(1)), 1);
    ack(&st, &addr(1), "deadbeef"); // unknown id is a no-op
    assert_eq!(queue_len(&st, &addr(1)), 1);
}

#[test]
fn max_queue_drops_oldest() {
    let st = state(3600, 2);
    let (tx, _rx) = channel();
    for i in 0..5 {
        publish(&st, &tx, addr(1), format!("e{i}"));
    }
    assert_eq!(queue_len(&st, &addr(1)), 2);
}

#[test]
fn expire_drops_old_envelopes_and_reclaims_empty_mailboxes() {
    let st = state(3600, 100);
    let (tx, _rx) = channel();
    publish(&st, &tx, addr(1), "b25l".into());
    // A cutoff just past the deposit's timestamp retires it.
    expire_mailboxes(&st, crate::state::now() + 1);
    assert_eq!(mailbox_count(&st), 0);
    assert_eq!(total_bytes(&st), 0);
}

#[test]
fn verify_ownership_accepts_valid_and_rejects_forgery() {
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let mailbox = hex::encode(sk.verifying_key().to_bytes());
    let nonce = [9u8; 32];
    let sig_b64 = B64.encode(sk.sign(&nonce).to_bytes());

    assert!(verify_ownership(&mailbox, &nonce, &sig_b64));
    assert!(!verify_ownership(&mailbox, &[0u8; 32], &sig_b64)); // wrong nonce
    let other = hex::encode(
        SigningKey::from_bytes(&[8u8; 32])
            .verifying_key()
            .to_bytes(),
    );
    assert!(!verify_ownership(&other, &nonce, &sig_b64)); // wrong key
    assert!(!verify_ownership(&mailbox, &nonce, "not base64!!")); // malformed sig
    assert!(!verify_ownership("xyz", &nonce, &sig_b64)); // malformed address
}

#[test]
fn publish_prunes_dead_subscribers() {
    let st = state(3600, 100);
    let (ptx, _prx) = channel();
    let (stx, srx) = channel();
    register_subscriber(&st, &addr(1), 1, stx);
    drop(srx); // receiver gone -> live send fails
    publish(&st, &ptx, addr(1), "b25l".into());
    assert_eq!(subscriber_count(&st, &addr(1)), 0);
}

#[test]
fn register_push_requires_authentication() {
    // No authenticated mailbox: a token must never be bound (the auth gate fires
    // before anything else), so only the mailbox owner can ever attach a token.
    let st = state(3600, 100);
    let (tx, mut rx) = channel();
    register_push(&st, &tx, None, "aabbccdd".into());
    assert!(matches!(rx.try_recv().unwrap(), ServerMsg::Error { .. }));
}

#[test]
fn register_push_rejected_when_no_gateway() {
    // A relay with no APNs gateway (every self-hosted / third-party relay)
    // refuses registration outright rather than hoarding tokens it can't use.
    let st = state(3600, 100);
    let (tx, mut rx) = channel();
    register_push(&st, &tx, Some(&addr(1)), "aabbccdd".into());
    match rx.try_recv().unwrap() {
        ServerMsg::Error { message } => assert_eq!(message, "push not supported"),
        other => panic!("expected an Error reply, got {other:?}"),
    }
}

#[test]
fn remove_subscriber_removes_by_conn_id() {
    let st = state(3600, 100);
    let (s1, _r1) = channel();
    let (s2, _r2) = channel();
    register_subscriber(&st, &addr(1), 1, s1);
    register_subscriber(&st, &addr(1), 2, s2);
    remove_subscriber(&st, &addr(1), 1);
    assert_eq!(subscriber_count(&st, &addr(1)), 1);
}

#[test]
fn switching_mailbox_drops_the_previous_subscription() {
    let st = state(3600, 100);
    let (tx, _rx) = channel();
    switch_subscription(&st, None, &addr(1), 7, tx.clone());
    switch_subscription(&st, Some(&addr(1)), &addr(2), 7, tx);
    assert_eq!(subscriber_count(&st, &addr(1)), 0);
    assert_eq!(subscriber_count(&st, &addr(2)), 1);
}

#[test]
fn re_authenticating_the_same_mailbox_keeps_one_subscription() {
    let st = state(3600, 100);
    let (tx, _rx) = channel();
    switch_subscription(&st, None, &addr(1), 7, tx.clone());
    switch_subscription(&st, Some(&addr(1)), &addr(1), 7, tx);
    assert_eq!(subscriber_count(&st, &addr(1)), 1);
}

#[test]
fn deposits_to_a_new_mailbox_are_refused_at_the_mailbox_cap() {
    let st = bounded_state(3600, 100, 2, usize::MAX);
    let (tx, mut rx) = channel();
    publish(&st, &tx, addr(1), "b25l".into());
    publish(&st, &tx, addr(2), "b25l".into());
    while rx.try_recv().is_ok() {} // drain the two `published` replies

    publish(&st, &tx, addr(3), "b25l".into());
    assert!(matches!(rx.try_recv().unwrap(), ServerMsg::Error { .. }));
    assert_eq!(mailbox_count(&st), 2);
    assert_eq!(queue_len(&st, &addr(3)), 0);

    // An existing mailbox still accepts deposits at the cap.
    publish(&st, &tx, addr(1), "dHdv".into());
    assert_eq!(queue_len(&st, &addr(1)), 2);
}

#[test]
fn the_global_byte_ceiling_evicts_from_the_largest_mailbox() {
    // Room for ~10 four-byte envelopes across the whole relay.
    let st = bounded_state(3600, 100, 100, 40);
    let (tx, _rx) = channel();

    publish(&st, &tx, addr(1), "b25l".into()); // one quiet mailbox
    for _ in 0..20 {
        publish(&st, &tx, addr(2), "Zmxvb2Q=".into()); // one flooding mailbox
    }

    assert!(total_bytes(&st) <= 40);
    // The flooder paid for its own pressure; the quiet mailbox kept its mail.
    assert_eq!(queue_len(&st, &addr(1)), 1);
    assert!(queue_len(&st, &addr(2)) < 20);
}

#[test]
fn byte_accounting_tracks_deposits_acks_and_expiry() {
    let st = state(3600, 100);
    let (tx, _rx) = channel();
    publish(&st, &tx, addr(1), "b25l".into()); // 4 bytes
    publish(&st, &tx, addr(1), "dHdvdHdv".into()); // 8 bytes
    assert_eq!(total_bytes(&st), 12);

    let first = state_first_id(&st, &addr(1));
    ack(&st, &addr(1), &first);
    assert_eq!(total_bytes(&st), 8);

    expire_mailboxes(&st, crate::state::now() + 1);
    assert_eq!(total_bytes(&st), 0);
}

#[test]
fn a_backed_up_subscriber_is_kept_but_never_buffered_past_the_bound() {
    let st = state(3600, usize::MAX);
    let (publisher, _pub_rx) = channel();
    let (sub, mut sub_rx) = channel();
    register_subscriber(&st, &addr(1), 1, sub);

    // Never drain `sub_rx` during the burst: the channel fills, and the relay
    // stops buffering rather than growing without limit.
    let burst = SUBSCRIBER_CHANNEL_CAPACITY + 10;
    for _ in 0..burst {
        publish(&st, &publisher, addr(1), "b25l".into());
    }

    // The subscription survives — a healthy socket that fell behind must keep
    // receiving once it catches up, and the skipped envelopes are still queued.
    assert_eq!(subscriber_count(&st, &addr(1)), 1);
    assert_eq!(queue_len(&st, &addr(1)), burst);

    let mut buffered = 0;
    while sub_rx.try_recv().is_ok() {
        buffered += 1;
    }
    assert_eq!(buffered, SUBSCRIBER_CHANNEL_CAPACITY);

    // Caught up: live delivery resumes.
    publish(&st, &publisher, addr(1), "bmV3".into());
    assert!(matches!(
        sub_rx.try_recv().unwrap(),
        ServerMsg::Envelope { .. }
    ));
}

#[test]
fn a_disconnected_subscriber_is_dropped() {
    let st = state(3600, usize::MAX);
    let (publisher, _pub_rx) = channel();
    let (sub, sub_rx) = channel();
    register_subscriber(&st, &addr(1), 1, sub);
    drop(sub_rx); // the connection went away

    publish(&st, &publisher, addr(1), "b25l".into());
    assert_eq!(subscriber_count(&st, &addr(1)), 0);
}

/// The id of the oldest envelope in a mailbox.
fn state_first_id(state: &AppState, mailbox: &str) -> String {
    state.mailboxes.lock().unwrap().get(mailbox).unwrap().queue[0]
        .id
        .clone()
}
