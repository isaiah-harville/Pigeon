// Tests for the blind-mailbox invariants, exercised without a socket.
// Declared beside the mailbox service so it can reach the
// crate-private mailbox operations.

use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use tokio::sync::mpsc;

use super::protocol::{
    gate_protocol_message, select_protocol, ClientMsg, ProtocolGate, ServerMsg,
    PROTOCOL_MAX_VERSION, PROTOCOL_MIN_VERSION,
};
use crate::mailbox::{
    ack as mailbox_ack, flush_queue as mailbox_flush_queue, publish as mailbox_publish,
    register_push as mailbox_register_push, register_subscriber as mailbox_register_subscriber,
    remove_subscriber as mailbox_remove_subscriber,
    switch_subscription as mailbox_switch_subscription, verify_ownership, Service,
};
use crate::push::PushRegistry;
use crate::{
    app::SUBSCRIBER_CHANNEL_CAPACITY,
    mailbox::store::{is_valid_address, Config, MAX_CIPHERTEXT_LEN, PUBKEY_LEN},
};

struct TestState {
    mailbox: Service,
    message_ids: AtomicU64,
    push: Arc<PushRegistry>,
}

fn state(ttl_secs: u64, max_queue: usize) -> TestState {
    bounded_state(ttl_secs, max_queue, usize::MAX, usize::MAX)
}

/// A relay with explicit capacity ceilings, for the bounds tests.
fn bounded_state(
    ttl_secs: u64,
    max_queue: usize,
    max_mailboxes: usize,
    max_total_bytes: usize,
) -> TestState {
    TestState {
        mailbox: Service::new(Config {
            ttl_secs,
            max_queue,
            max_mailboxes,
            max_total_bytes,
        }),
        message_ids: AtomicU64::new(1),
        // No gateway: deposits never attempt a push in these tests.
        push: Arc::new(PushRegistry::new(None, Duration::from_secs(30))),
    }
}

fn publish(state: &TestState, tx: &mpsc::Sender<ServerMsg>, recipient: String, ciphertext: String) {
    mailbox_publish(
        &state.mailbox,
        &state.message_ids,
        &state.push,
        tx,
        recipient,
        ciphertext,
        None,
    );
}

fn register_push(
    state: &TestState,
    tx: &mpsc::Sender<ServerMsg>,
    mailbox: Option<&str>,
    token: String,
) {
    mailbox_register_push(&state.push, tx, mailbox, false, token);
}

fn register_subscriber(
    state: &TestState,
    mailbox: &str,
    connection_id: u64,
    tx: mpsc::Sender<ServerMsg>,
) {
    mailbox_register_subscriber(&state.mailbox, mailbox, connection_id, tx);
}

fn switch_subscription(
    state: &TestState,
    previous: Option<&str>,
    mailbox: &str,
    connection_id: u64,
    tx: mpsc::Sender<ServerMsg>,
) {
    mailbox_switch_subscription(&state.mailbox, previous, mailbox, connection_id, tx);
}

fn flush_queue(state: &TestState, mailbox: &str, tx: &mpsc::Sender<ServerMsg>) {
    mailbox_flush_queue(&state.mailbox, mailbox, tx);
}

fn ack(state: &TestState, mailbox: &str, id: &str) {
    mailbox_ack(&state.mailbox, mailbox, id);
}

fn remove_subscriber(state: &TestState, mailbox: &str, connection_id: u64) {
    mailbox_remove_subscriber(&state.mailbox, mailbox, connection_id);
}

fn expire_mailboxes(state: &TestState, cutoff: u64) {
    state.mailbox.expire(cutoff);
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
        Some(2)
    );
}

#[test]
fn protocol_negotiation_rejects_disjoint_and_invalid_ranges() {
    assert_eq!(select_protocol(1, 1), None);
    assert_eq!(select_protocol(1, 0), None);
}

#[test]
fn hello_and_compatible_frames_use_the_documented_json_shape() {
    let hello: ClientMsg = serde_json::from_str(
        r#"{"type":"hello","min_protocol_version":2,"max_protocol_version":2}"#,
    )
    .unwrap();
    assert!(matches!(hello, ClientMsg::Hello { .. }));
    assert_eq!(
        serde_json::to_string(&ServerMsg::Compatible {
            protocol_version: 2,
            relay_version: "0.2.0".into(),
            min_protocol_version: 2,
            max_protocol_version: 2,
        })
        .unwrap(),
        r#"{"type":"compatible","protocol_version":2,"relay_version":"0.2.0","min_protocol_version":2,"max_protocol_version":2}"#
    );
}

#[test]
fn publish_receipt_echoes_request_id_after_storage() {
    let state = state(60, 10);
    let (tx, mut rx) = mpsc::channel(4);
    mailbox_publish(
        &state.mailbox,
        &state.message_ids,
        &state.push,
        &tx,
        "aa".repeat(32),
        "ciphertext".into(),
        Some("request-42".into()),
    );
    assert!(
        matches!(rx.try_recv().unwrap(), ServerMsg::Published { request_id: Some(value), .. } if value == "request-42")
    );
}

#[test]
fn publish_error_echoes_valid_request_id_without_storing() {
    let state = state(60, 10);
    let (tx, mut rx) = mpsc::channel(4);
    mailbox_publish(
        &state.mailbox,
        &state.message_ids,
        &state.push,
        &tx,
        "bad".into(),
        "ciphertext".into(),
        Some("request-43".into()),
    );
    assert!(
        matches!(rx.try_recv().unwrap(), ServerMsg::Error { request_id: Some(value), .. } if value == "request-43")
    );
    mailbox_publish(
        &state.mailbox,
        &state.message_ids,
        &state.push,
        &tx,
        "aa".repeat(32),
        "ciphertext".into(),
        Some("x".repeat(129)),
    );
    assert!(matches!(
        rx.try_recv().unwrap(),
        ServerMsg::Error {
            request_id: None,
            ..
        }
    ));
    assert!(state
        .mailbox
        .store
        .lock()
        .unwrap()
        .get(&"aa".repeat(32))
        .is_none());
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
        r#"{"type":"hello","min_protocol_version":1,"max_protocol_version":1}"#,
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
        r#"{"type":"hello","min_protocol_version":2,"max_protocol_version":2}"#,
    )
    .unwrap();
    assert!(matches!(
        gate_protocol_message(hello, &mut negotiated),
        ProtocolGate::Reply(ServerMsg::Compatible {
            protocol_version: 2,
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

fn queue_len(state: &TestState, mailbox: &str) -> usize {
    state
        .mailbox
        .store
        .lock()
        .unwrap()
        .get(mailbox)
        .map_or(0, |m| m.queue.len())
}

fn total_bytes(state: &TestState) -> usize {
    state.mailbox.store.lock().unwrap().total_bytes()
}

fn mailbox_count(state: &TestState) -> usize {
    state.mailbox.store.lock().unwrap().len()
}

fn subscriber_count(state: &TestState, mailbox: &str) -> usize {
    state
        .mailbox
        .store
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
    assert_eq!(st.mailbox.store.lock().unwrap().len(), 0);
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
