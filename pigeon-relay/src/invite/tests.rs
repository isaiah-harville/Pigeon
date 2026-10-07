use super::{Config, Store, StoreError};
use tokio::sync::mpsc;

use crate::mailbox::protocol::ServerMsg;

fn config() -> Config {
    Config {
        ttl_secs: 60,
        max_mailboxes: 2,
        max_entries_per_mailbox: 2,
        max_entry_bytes: 32,
        max_total_bytes: 64,
        max_deposits_per_minute: 2,
    }
}

#[test]
fn acknowledged_deposit_survives_restart_until_owner_ack() {
    let directory = tempfile::tempdir().unwrap();
    let address = [7; 32];
    let mut store = Store::open(directory.path(), config(), 1).unwrap();
    let id = store.deposit(address, "opaque".into(), 1).unwrap();
    drop(store);
    let mut restored = Store::open(directory.path(), config(), 2).unwrap();
    assert_eq!(restored.fetch(address).unwrap()[0].id, id);
    assert_eq!(restored.fetch(address).unwrap()[0].ciphertext, "opaque");
    restored.ack(address, &id).unwrap();
    drop(restored);
    assert!(Store::open(directory.path(), config(), 3)
        .unwrap()
        .fetch(address)
        .unwrap()
        .is_empty());
}

#[test]
fn quota_and_rate_rejections_do_not_evict_acknowledged_ciphertext() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = Store::open(directory.path(), config(), 1).unwrap();
    let address = [7; 32];
    let first = store.deposit(address, "first".into(), 1).unwrap();
    store.deposit(address, "second".into(), 1).unwrap();
    assert_eq!(
        store.deposit(address, "third".into(), 1),
        Err(StoreError::AtCapacity)
    );
    assert_eq!(store.fetch(address).unwrap().len(), 2);
    assert!(store
        .fetch(address)
        .unwrap()
        .iter()
        .any(|envelope| envelope.id == first));
    store.expire(62).unwrap();
    assert!(store.fetch(address).unwrap().is_empty());
}

#[test]
fn authenticated_subscriber_receives_live_durable_deposit() {
    let directory = tempfile::tempdir().unwrap();
    let service = super::Service::open(directory.path(), config(), 1).unwrap();
    let address = [7; 32];
    let (tx, mut rx) = mpsc::channel(4);
    assert!(service.subscribe(address, 42, tx));
    assert!(matches!(rx.try_recv().unwrap(), ServerMsg::Ok { .. }));
    let id = service.deposit(address, "opaque".into(), 2).unwrap();
    assert!(
        matches!(rx.try_recv().unwrap(), ServerMsg::Envelope { id: received, ciphertext, .. }
        if received == id && ciphertext == "opaque")
    );
    drop(service);
    assert_eq!(
        Store::open(directory.path(), config(), 3)
            .unwrap()
            .fetch(address)
            .unwrap()[0]
            .id,
        id
    );
}

#[test]
fn closed_subscriber_does_not_panic_or_poison_invite_store() {
    let directory = tempfile::tempdir().unwrap();
    let service = super::Service::open(directory.path(), config(), 1).unwrap();
    let address = [7; 32];
    service.deposit(address, "opaque".into(), 1).unwrap();
    let (tx, rx) = mpsc::channel(4);
    drop(rx);

    assert!(!service.subscribe(address, 42, tx));
    assert_eq!(service.0.lock().unwrap().fetch(address).unwrap().len(), 1);
}

#[test]
fn total_byte_quota_counts_utf8_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let mut limits = config();
    limits.max_total_bytes = 8;
    limits.max_entries_per_mailbox = 3;
    limits.max_deposits_per_minute = 10;
    let mut store = Store::open(directory.path(), limits, 1).unwrap();
    store.deposit([7; 32], "🕊".into(), 1).unwrap();
    store.deposit([7; 32], "🕊".into(), 1).unwrap();
    assert_eq!(
        store.deposit([7; 32], "🕊".into(), 1),
        Err(StoreError::AtCapacity)
    );
}

#[test]
fn one_invite_inbox_has_at_most_two_backlog_readers() {
    let directory = tempfile::tempdir().unwrap();
    let service = super::Service::open(directory.path(), config(), 1).unwrap();
    let address = [7; 32];
    service.deposit(address, "opaque".into(), 1).unwrap();
    let (first_tx, _first_rx) = mpsc::channel(4);
    let (second_tx, _second_rx) = mpsc::channel(4);
    let (third_tx, mut third_rx) = mpsc::channel(4);
    assert!(service.subscribe(address, 1, first_tx));
    assert!(service.subscribe(address, 2, second_tx));
    assert!(!service.subscribe(address, 3, third_tx.clone()));
    assert!(third_rx.try_recv().is_err());
    service.unsubscribe(address, 1);
    assert!(service.subscribe(address, 3, third_tx));
    assert!(matches!(third_rx.try_recv().unwrap(), ServerMsg::Ok { .. }));
    assert!(matches!(
        third_rx.try_recv().unwrap(),
        ServerMsg::Envelope { .. }
    ));
}
