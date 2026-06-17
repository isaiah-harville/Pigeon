// Tests for the blind-mailbox invariants, exercised without a socket.
// Declared from `main.rs` as `#[cfg(test)] mod tests;` so it can reach the
// crate-private mailbox operations.

use super::*;
use ed25519_dalek::{Signer, SigningKey};

fn state(ttl_secs: u64, max_queue: usize) -> AppState {
    AppState {
        mailboxes: Arc::new(Mutex::new(HashMap::new())),
        cfg: Config {
            ttl_secs,
            max_queue,
        },
        counter: Arc::new(AtomicU64::new(1)),
    }
}

fn channel() -> (
    mpsc::UnboundedSender<ServerMsg>,
    mpsc::UnboundedReceiver<ServerMsg>,
) {
    mpsc::unbounded_channel()
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
    st.mailboxes
        .lock()
        .unwrap()
        .get_mut(&addr(1))
        .unwrap()
        .queue[0]
        .ts = 0;
    expire_mailboxes(&st, 100); // cutoff 100 > ts 0 -> dropped
    assert_eq!(st.mailboxes.lock().unwrap().len(), 0);
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
fn remove_subscriber_removes_by_conn_id() {
    let st = state(3600, 100);
    let (s1, _r1) = channel();
    let (s2, _r2) = channel();
    register_subscriber(&st, &addr(1), 1, s1);
    register_subscriber(&st, &addr(1), 2, s2);
    remove_subscriber(&st, &addr(1), 1);
    assert_eq!(subscriber_count(&st, &addr(1)), 1);
}
