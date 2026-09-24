use ed25519_dalek::{Signer, SigningKey};
use pigeon_core::{
    CoordinatorChain, CoordinatorChainError, CoordinatorReceipt, coordinator_receipt_transcript,
    select_canonical_candidate, wire_proto,
};
use prost::Message;
use sha2::{Digest, Sha256};

fn candidate(
    signer: &SigningKey,
    coordination_id: [u8; 32],
    sequence: u64,
    prior: [u8; 32],
    base_epoch: u64,
    candidate: &[u8],
) -> Vec<u8> {
    let entry_hash: [u8; 32] = Sha256::digest(candidate).into();
    let transcript =
        coordinator_receipt_transcript(coordination_id, sequence, prior, base_epoch, entry_hash);
    wire_proto::CoordinatorCandidate {
        receipt: Some(wire_proto::CoordinatorReceipt {
            version: 1,
            coordination_id: coordination_id.to_vec(),
            sequence,
            prior_receipt_hash: prior.to_vec(),
            claimed_base_epoch: base_epoch,
            entry_hash: entry_hash.to_vec(),
            signature: signer.sign(&transcript).to_bytes().to_vec(),
        }),
        candidate: candidate.to_vec(),
    }
    .encode_to_vec()
}

#[test]
fn invalid_first_candidate_does_not_block_first_valid_commit() {
    let signer = SigningKey::from_bytes(&[1; 32]);
    let coordination_id = [2; 32];
    let first = candidate(&signer, coordination_id, 1, [0; 32], 7, b"invalid");
    let first_receipt = CoordinatorReceipt::decode_candidate(&first).unwrap().0;
    let second = candidate(
        &signer,
        coordination_id,
        2,
        first_receipt.receipt_hash(),
        7,
        b"valid",
    );
    let mut chain = CoordinatorChain::new(coordination_id, signer.verifying_key().to_bytes());

    let canonical = select_canonical_candidate(&mut chain, [&first[..], &second[..]], |bytes| {
        bytes == b"valid"
    })
    .unwrap();

    assert_eq!(canonical.candidate, b"valid");
    assert_eq!(canonical.sequence, 2);
    assert_eq!(canonical.skipped_invalid, 1);
}

#[test]
fn conflicting_valid_receipts_freeze_the_chain() {
    let signer = SigningKey::from_bytes(&[3; 32]);
    let coordination_id = [4; 32];
    let left = candidate(&signer, coordination_id, 1, [0; 32], 1, b"left");
    let right = candidate(&signer, coordination_id, 1, [0; 32], 1, b"right");
    let mut chain = CoordinatorChain::new(coordination_id, signer.verifying_key().to_bytes());
    let (left_receipt, left_candidate) = CoordinatorReceipt::decode_candidate(&left).unwrap();
    chain.accept(&left_receipt, &left_candidate).unwrap();
    let (right_receipt, right_candidate) = CoordinatorReceipt::decode_candidate(&right).unwrap();

    assert_eq!(
        chain.accept(&right_receipt, &right_candidate),
        Err(CoordinatorChainError::Fork)
    );
    assert!(chain.is_frozen());
}

#[test]
fn delayed_equivocation_evidence_still_freezes_the_chain() {
    let signer = SigningKey::from_bytes(&[7; 32]);
    let coordination_id = [8; 32];
    let first = candidate(&signer, coordination_id, 1, [0; 32], 1, b"first");
    let (first_receipt, first_body) = CoordinatorReceipt::decode_candidate(&first).unwrap();
    let second = candidate(
        &signer,
        coordination_id,
        2,
        first_receipt.receipt_hash(),
        2,
        b"second",
    );
    let (second_receipt, second_body) = CoordinatorReceipt::decode_candidate(&second).unwrap();
    let fork = candidate(&signer, coordination_id, 1, [0; 32], 1, b"fork");
    let (fork_receipt, fork_body) = CoordinatorReceipt::decode_candidate(&fork).unwrap();
    let mut chain = CoordinatorChain::new(coordination_id, signer.verifying_key().to_bytes());
    chain.accept(&first_receipt, &first_body).unwrap();
    chain.accept(&second_receipt, &second_body).unwrap();

    assert_eq!(
        chain.accept(&fork_receipt, &fork_body),
        Err(CoordinatorChainError::Fork)
    );
    assert!(chain.is_frozen());
}

#[test]
fn forged_or_gapped_receipts_fail_closed() {
    let signer = SigningKey::from_bytes(&[5; 32]);
    let coordination_id = [6; 32];
    let encoded = candidate(&signer, coordination_id, 2, [0; 32], 1, b"gap");
    let (receipt, body) = CoordinatorReceipt::decode_candidate(&encoded).unwrap();
    let mut chain = CoordinatorChain::new(coordination_id, signer.verifying_key().to_bytes());
    assert_eq!(
        chain.accept(&receipt, &body),
        Err(CoordinatorChainError::MissingReceipt)
    );

    let mut forged = receipt.clone();
    forged.signature[0] ^= 1;
    assert_eq!(
        chain.accept(&forged, &body),
        Err(CoordinatorChainError::InvalidReceipt)
    );
}
