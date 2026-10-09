use ed25519_dalek::SigningKey;
use tempfile::tempdir;

use super::store::{Config, Store, StoreError};
use crate::durable::{CoordinatorJournal, DurableError, COORDINATOR_DATABASE};

fn store() -> Store {
    Store::new(store_config(), SigningKey::from_bytes(&[77; 32]))
}

#[test]
fn coordinator_receipts_form_one_signed_append_only_chain() {
    let mut store = store();
    let first = store
        .submit([1; 32], [9; 32], 7, b"first".to_vec(), 1)
        .unwrap();
    let second = store
        .submit([1; 32], [9; 32], 7, b"second".to_vec(), 2)
        .unwrap();

    assert_eq!(first.sequence, 1);
    assert_eq!(second.sequence, 2);
    assert_eq!(second.prior_receipt_hash, first.receipt_hash());
    assert!(first.verify(store.verifying_key()));
    assert!(second.verify(store.verifying_key()));
    assert_eq!(store.fetch([1; 32], 0).len(), 2);
}

#[test]
fn coordinator_duplicate_candidate_keeps_one_sequence() {
    let mut store = store();
    let first = store
        .submit([2; 32], [9; 32], 4, b"same".to_vec(), 1)
        .unwrap();
    let replay = store
        .submit([2; 32], [9; 32], 4, b"same".to_vec(), 2)
        .unwrap();

    assert_eq!(first, replay);
    assert_eq!(store.fetch([2; 32], 0).len(), 1);
}

#[test]
fn coordinator_bounds_candidates_per_epoch_and_bytes() {
    let mut store = store();
    store.submit([3; 32], [1; 32], 9, vec![0; 4], 1).unwrap();
    store.submit([3; 32], [1; 32], 9, vec![1; 4], 1).unwrap();
    assert_eq!(
        store.submit([3; 32], [1; 32], 9, vec![2; 4], 1),
        Err(StoreError::CapabilityEpochCapacity)
    );
    store.submit([3; 32], [2; 32], 9, vec![3; 4], 1).unwrap();
    assert_eq!(
        store.submit([3; 32], [2; 32], 9, vec![9; 4], 1),
        Err(StoreError::EpochCapacity)
    );
    assert_eq!(
        store.submit([4; 32], [1; 32], 1, vec![0; 1025], 1),
        Err(StoreError::OversizedCandidate)
    );
}

#[test]
fn coordinator_expiry_reclaims_opaque_candidates_without_reusing_sequences() {
    let mut store = store();
    let first = store
        .submit([5; 32], [9; 32], 1, b"old".to_vec(), 1)
        .unwrap();
    store.expire_at(62);
    assert!(store.fetch([5; 32], 0).is_empty());
    let next = store
        .submit([5; 32], [9; 32], 2, b"new".to_vec(), 62)
        .unwrap();
    assert_eq!(next.sequence, first.sequence + 1);
}

#[test]
fn expired_head_only_logs_do_not_consume_active_log_capacity() {
    let mut limits = store_config();
    limits.max_logs = 1;
    let mut store = Store::new(limits, SigningKey::from_bytes(&[77; 32]));
    let first = store
        .submit([5; 32], [9; 32], 1, b"old".to_vec(), 1)
        .unwrap();
    store.expire_at(62);
    store
        .submit([6; 32], [9; 32], 1, b"other".to_vec(), 62)
        .unwrap();
    assert_eq!(
        store.submit([5; 32], [9; 32], 2, b"blocked".to_vec(), 62),
        Err(StoreError::AtCapacity)
    );
    store.expire_at(123);
    let resumed = store
        .submit([5; 32], [9; 32], 2, b"resumed".to_vec(), 123)
        .unwrap();
    assert_eq!(resumed.sequence, first.sequence + 1);
    assert_eq!(resumed.prior_receipt_hash, first.receipt_hash());
}

#[test]
fn durable_head_only_logs_do_not_block_restart_at_capacity() {
    let directory = tempdir().unwrap();
    let signer = SigningKey::from_bytes(&[77; 32]);
    let mut limits = store_config();
    limits.max_logs = 1;
    let journal =
        CoordinatorJournal::open(directory.path(), signer.verifying_key().to_bytes()).unwrap();
    let mut store = Store::durable(limits.clone(), signer, journal, 1).unwrap();
    let first = store
        .submit([5; 32], [9; 32], 1, b"old".to_vec(), 1)
        .unwrap();
    drop(store);

    let signer = SigningKey::from_bytes(&[77; 32]);
    let journal =
        CoordinatorJournal::open(directory.path(), signer.verifying_key().to_bytes()).unwrap();
    let mut restored = Store::durable(limits, signer, journal, 62).unwrap();
    restored
        .submit([6; 32], [9; 32], 1, b"other".to_vec(), 62)
        .unwrap();
    restored.expire_at(123);
    let resumed = restored
        .submit([5; 32], [9; 32], 2, b"resumed".to_vec(), 123)
        .unwrap();
    assert_eq!(resumed.sequence, first.sequence + 1);
    assert_eq!(resumed.prior_receipt_hash, first.receipt_hash());
}

#[test]
fn durable_coordinator_chain_survives_restart_and_rejects_a_new_signer() {
    let directory = tempdir().unwrap();
    let signer = SigningKey::from_bytes(&[77; 32]);
    let journal =
        CoordinatorJournal::open(directory.path(), signer.verifying_key().to_bytes()).unwrap();
    let mut original = Store::durable(store_config(), signer, journal, 1).unwrap();
    let first = original
        .submit([8; 32], [9; 32], 1, b"first".to_vec(), 1)
        .unwrap();
    drop(original);

    let signer = SigningKey::from_bytes(&[77; 32]);
    let journal =
        CoordinatorJournal::open(directory.path(), signer.verifying_key().to_bytes()).unwrap();
    let mut restored = Store::durable(store_config(), signer, journal, 2).unwrap();
    let second = restored
        .submit([8; 32], [9; 32], 2, b"second".to_vec(), 2)
        .unwrap();
    assert_eq!(second.sequence, first.sequence + 1);
    assert_eq!(second.prior_receipt_hash, first.receipt_hash());
    drop(restored);

    assert!(matches!(
        CoordinatorJournal::open(
            directory.path(),
            SigningKey::from_bytes(&[78; 32]).verifying_key().to_bytes(),
        ),
        Err(DurableError::CoordinatorKeyMismatch)
    ));
}

#[test]
fn durable_coordinator_rejects_a_tampered_receipt_on_restart() {
    let directory = tempdir().unwrap();
    let signer = SigningKey::from_bytes(&[77; 32]);
    let journal =
        CoordinatorJournal::open(directory.path(), signer.verifying_key().to_bytes()).unwrap();
    let mut store = Store::durable(store_config(), signer, journal, 1).unwrap();
    store
        .submit([8; 32], [9; 32], 1, b"first".to_vec(), 1)
        .unwrap();
    drop(store);

    let connection =
        rusqlite::Connection::open(directory.path().join(COORDINATOR_DATABASE)).unwrap();
    connection
        .execute("UPDATE candidates SET signature = zeroblob(64)", [])
        .unwrap();
    drop(connection);

    let signer = SigningKey::from_bytes(&[77; 32]);
    let journal =
        CoordinatorJournal::open(directory.path(), signer.verifying_key().to_bytes()).unwrap();
    assert!(matches!(
        Store::durable(store_config(), signer, journal, 2),
        Err(DurableError::Corrupt("invalid coordinator receipt chain"))
    ));
}

fn store_config() -> Config {
    Config {
        max_logs: 4,
        max_candidates_per_log: 8,
        max_candidates_per_epoch: 3,
        max_candidates_per_capability_per_epoch: 2,
        max_candidate_bytes: 1024,
        max_total_bytes: 4096,
        max_fetch_batch_bytes: 2048,
        ttl_secs: 60,
    }
}
