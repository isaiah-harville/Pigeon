use ed25519_dalek::SigningKey;

use crate::coordinator_store::{CoordinatorConfig, CoordinatorError, CoordinatorStore};

fn store() -> CoordinatorStore {
    CoordinatorStore::new(
        CoordinatorConfig {
            max_candidates_per_epoch: 3,
            max_candidate_bytes: 1024,
            max_total_bytes: 4096,
            max_fetch_batch_bytes: 2048,
            ttl_secs: 60,
        },
        SigningKey::from_bytes(&[77; 32]),
    )
}

#[test]
fn coordinator_receipts_form_one_signed_append_only_chain() {
    let mut store = store();
    let first = store.submit([1; 32], 7, b"first".to_vec(), 1).unwrap();
    let second = store.submit([1; 32], 7, b"second".to_vec(), 2).unwrap();

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
    let first = store.submit([2; 32], 4, b"same".to_vec(), 1).unwrap();
    let replay = store.submit([2; 32], 4, b"same".to_vec(), 2).unwrap();

    assert_eq!(first, replay);
    assert_eq!(store.fetch([2; 32], 0).len(), 1);
}

#[test]
fn coordinator_bounds_candidates_per_epoch_and_bytes() {
    let mut store = store();
    for byte in 0..3 {
        store.submit([3; 32], 9, vec![byte; 4], 1).unwrap();
    }
    assert_eq!(
        store.submit([3; 32], 9, vec![9; 4], 1),
        Err(CoordinatorError::EpochCapacity)
    );
    assert_eq!(
        store.submit([4; 32], 1, vec![0; 1025], 1),
        Err(CoordinatorError::OversizedCandidate)
    );
}

#[test]
fn coordinator_expiry_reclaims_opaque_candidates_without_reusing_sequences() {
    let mut store = store();
    let first = store.submit([5; 32], 1, b"old".to_vec(), 1).unwrap();
    store.expire_at(62);
    assert!(store.fetch([5; 32], 0).is_empty());
    let next = store.submit([5; 32], 2, b"new".to_vec(), 62).unwrap();
    assert_eq!(next.sequence, first.sequence + 1);
}
