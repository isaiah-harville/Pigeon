use ed25519_dalek::{Signature, VerifyingKey};
use prost::Message;
use sha2::{Digest, Sha256};

use crate::wire::{MAX_MLS_OBJECT_BYTES, PROTOCOL_VERSION, proto};

pub const COORDINATOR_RECEIPT_DOMAIN: &[u8] = b"pigeon.relay.coordinator.receipt.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoordinatorBinding {
    pub coordination_id: [u8; 32],
    pub public_key: [u8; 32],
}

impl CoordinatorBinding {
    pub const fn new(coordination_id: [u8; 32], public_key: [u8; 32]) -> Self {
        Self {
            coordination_id,
            public_key,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinatorReceipt {
    pub coordination_id: [u8; 32],
    pub sequence: u64,
    pub prior_receipt_hash: [u8; 32],
    pub claimed_base_epoch: u64,
    pub entry_hash: [u8; 32],
    pub signature: [u8; 64],
}

impl CoordinatorReceipt {
    pub fn decode_candidate(bytes: &[u8]) -> Result<(Self, Vec<u8>), CoordinatorChainError> {
        if bytes.len() > MAX_MLS_OBJECT_BYTES {
            return Err(CoordinatorChainError::ResourceLimit);
        }
        let candidate = proto::CoordinatorCandidate::decode(bytes)
            .map_err(|_| CoordinatorChainError::Malformed)?;
        if candidate.candidate.is_empty() || candidate.candidate.len() > MAX_MLS_OBJECT_BYTES {
            return Err(CoordinatorChainError::ResourceLimit);
        }
        let receipt = candidate.receipt.ok_or(CoordinatorChainError::Malformed)?;
        if receipt.version != PROTOCOL_VERSION {
            return Err(CoordinatorChainError::Malformed);
        }
        let decoded = Self {
            coordination_id: fixed(&receipt.coordination_id)?,
            sequence: receipt.sequence,
            prior_receipt_hash: fixed(&receipt.prior_receipt_hash)?,
            claimed_base_epoch: receipt.claimed_base_epoch,
            entry_hash: fixed(&receipt.entry_hash)?,
            signature: fixed(&receipt.signature)?,
        };
        Ok((decoded, candidate.candidate))
    }

    pub fn verify(&self, key: [u8; 32], candidate: &[u8]) -> bool {
        if Sha256::digest(candidate).as_slice() != self.entry_hash {
            return false;
        }
        let Ok(key) = VerifyingKey::from_bytes(&key) else {
            return false;
        };
        let signature = Signature::from_bytes(&self.signature);
        key.verify_strict(&self.signing_transcript(), &signature)
            .is_ok()
    }

    pub fn receipt_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.signing_transcript());
        hasher.update(self.signature);
        hasher.finalize().into()
    }

    fn signing_transcript(&self) -> Vec<u8> {
        coordinator_receipt_transcript(
            self.coordination_id,
            self.sequence,
            self.prior_receipt_hash,
            self.claimed_base_epoch,
            self.entry_hash,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinatorChainError {
    Fork,
    Frozen,
    InvalidReceipt,
    Malformed,
    MissingReceipt,
    NoValidCandidate,
    ResourceLimit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinatorChain {
    coordination_id: [u8; 32],
    verifying_key: [u8; 32],
    last_sequence: u64,
    receipt_head: [u8; 32],
    last_prior_hash: [u8; 32],
    accepted_receipts: BTreeMap<u64, ([u8; 32], [u8; 32])>,
    frozen: bool,
}

impl CoordinatorChain {
    pub fn new(coordination_id: [u8; 32], verifying_key: [u8; 32]) -> Self {
        Self {
            coordination_id,
            verifying_key,
            last_sequence: 0,
            receipt_head: [0; 32],
            last_prior_hash: [0; 32],
            accepted_receipts: BTreeMap::new(),
            frozen: false,
        }
    }

    pub fn accept(
        &mut self,
        receipt: &CoordinatorReceipt,
        candidate: &[u8],
    ) -> Result<bool, CoordinatorChainError> {
        if self.frozen {
            return Err(CoordinatorChainError::Frozen);
        }
        if receipt.coordination_id != self.coordination_id
            || !receipt.verify(self.verifying_key, candidate)
        {
            return Err(CoordinatorChainError::InvalidReceipt);
        }
        let receipt_hash = receipt.receipt_hash();
        if receipt.sequence <= self.last_sequence {
            let Some((accepted_prior, accepted_hash)) =
                self.accepted_receipts.get(&receipt.sequence)
            else {
                return Err(CoordinatorChainError::InvalidReceipt);
            };
            if receipt_hash == *accepted_hash {
                return Ok(false);
            }
            if receipt.prior_receipt_hash == *accepted_prior {
                self.frozen = true;
                return Err(CoordinatorChainError::Fork);
            }
            return Err(CoordinatorChainError::InvalidReceipt);
        }
        if receipt.sequence != self.last_sequence + 1
            || receipt.prior_receipt_hash != self.receipt_head
        {
            return Err(CoordinatorChainError::MissingReceipt);
        }
        self.last_sequence = receipt.sequence;
        self.last_prior_hash = receipt.prior_receipt_hash;
        self.receipt_head = receipt_hash;
        self.accepted_receipts
            .insert(receipt.sequence, (receipt.prior_receipt_hash, receipt_hash));
        while self.accepted_receipts.len() > 256 {
            self.accepted_receipts.pop_first();
        }
        Ok(true)
    }

    pub fn is_frozen(&self) -> bool {
        self.frozen
    }

    pub fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    pub fn receipt_head(&self) -> [u8; 32] {
        self.receipt_head
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        proto::CoordinatorChainState {
            version: PROTOCOL_VERSION,
            coordination_id: self.coordination_id.to_vec(),
            verifying_key: self.verifying_key.to_vec(),
            last_sequence: self.last_sequence,
            receipt_head: self.receipt_head.to_vec(),
            last_prior_hash: self.last_prior_hash.to_vec(),
            accepted_receipts: self
                .accepted_receipts
                .iter()
                .map(|(sequence, (prior_receipt_hash, receipt_hash))| {
                    proto::CoordinatorChainEntry {
                        sequence: *sequence,
                        prior_receipt_hash: prior_receipt_hash.to_vec(),
                        receipt_hash: receipt_hash.to_vec(),
                    }
                })
                .collect(),
            frozen: self.frozen,
        }
        .encode_to_vec()
    }

    pub(crate) fn decode(
        bytes: &[u8],
        coordination_id: [u8; 32],
        verifying_key: [u8; 32],
    ) -> Result<Self, CoordinatorChainError> {
        if bytes.len() > MAX_MLS_OBJECT_BYTES {
            return Err(CoordinatorChainError::ResourceLimit);
        }
        let state = proto::CoordinatorChainState::decode(bytes)
            .map_err(|_| CoordinatorChainError::Malformed)?;
        let entry_count = state.accepted_receipts.len();
        if state.version != PROTOCOL_VERSION
            || fixed::<32>(&state.coordination_id)? != coordination_id
            || fixed::<32>(&state.verifying_key)? != verifying_key
            || entry_count > 256
        {
            return Err(CoordinatorChainError::Malformed);
        }
        let accepted_receipts = state
            .accepted_receipts
            .into_iter()
            .map(|entry| {
                Ok((
                    entry.sequence,
                    (
                        fixed::<32>(&entry.prior_receipt_hash)?,
                        fixed::<32>(&entry.receipt_hash)?,
                    ),
                ))
            })
            .collect::<Result<BTreeMap<_, _>, CoordinatorChainError>>()?;
        if accepted_receipts.len() != entry_count {
            return Err(CoordinatorChainError::Malformed);
        }
        let chain = Self {
            coordination_id,
            verifying_key,
            last_sequence: state.last_sequence,
            receipt_head: fixed(&state.receipt_head)?,
            last_prior_hash: fixed(&state.last_prior_hash)?,
            accepted_receipts,
            frozen: state.frozen,
        };
        chain.validate_checkpoint()?;
        Ok(chain)
    }

    fn validate_checkpoint(&self) -> Result<(), CoordinatorChainError> {
        if self.last_sequence == 0 {
            return (self.receipt_head == [0; 32]
                && self.last_prior_hash == [0; 32]
                && self.accepted_receipts.is_empty())
            .then_some(())
            .ok_or(CoordinatorChainError::Malformed);
        }
        let Some((last_sequence, (last_prior, last_hash))) =
            self.accepted_receipts.last_key_value()
        else {
            return Err(CoordinatorChainError::Malformed);
        };
        if *last_sequence != self.last_sequence
            || *last_prior != self.last_prior_hash
            || *last_hash != self.receipt_head
            || self
                .accepted_receipts
                .iter()
                .zip(self.accepted_receipts.iter().skip(1))
                .any(
                    |((left_sequence, (_, left_hash)), (right_sequence, (right_prior, _)))| {
                        *right_sequence != left_sequence + 1 || right_prior != left_hash
                    },
                )
        {
            return Err(CoordinatorChainError::Malformed);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalCandidate {
    pub candidate: Vec<u8>,
    pub sequence: u64,
    pub skipped_invalid: usize,
}

pub fn select_canonical_candidate<'a, I, F>(
    chain: &mut CoordinatorChain,
    encoded_candidates: I,
    mut validates: F,
) -> Result<CanonicalCandidate, CoordinatorChainError>
where
    I: IntoIterator<Item = &'a [u8]>,
    F: FnMut(&[u8]) -> bool,
{
    let mut candidates = encoded_candidates
        .into_iter()
        .map(CoordinatorReceipt::decode_candidate)
        .collect::<Result<Vec<_>, _>>()?;
    candidates.sort_unstable_by_key(|(receipt, _)| receipt.sequence);
    let mut skipped_invalid = 0;
    for (receipt, candidate) in candidates {
        if !chain.accept(&receipt, &candidate)? {
            continue;
        }
        if validates(&candidate) {
            return Ok(CanonicalCandidate {
                candidate,
                sequence: receipt.sequence,
                skipped_invalid,
            });
        }
        skipped_invalid += 1;
    }
    Err(CoordinatorChainError::NoValidCandidate)
}

pub fn coordinator_receipt_transcript(
    coordination_id: [u8; 32],
    sequence: u64,
    prior_receipt_hash: [u8; 32],
    claimed_base_epoch: u64,
    entry_hash: [u8; 32],
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(COORDINATOR_RECEIPT_DOMAIN.len() + 112);
    transcript.extend_from_slice(COORDINATOR_RECEIPT_DOMAIN);
    transcript.extend_from_slice(&coordination_id);
    transcript.extend_from_slice(&sequence.to_be_bytes());
    transcript.extend_from_slice(&prior_receipt_hash);
    transcript.extend_from_slice(&claimed_base_epoch.to_be_bytes());
    transcript.extend_from_slice(&entry_hash);
    transcript
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], CoordinatorChainError> {
    bytes
        .try_into()
        .map_err(|_| CoordinatorChainError::Malformed)
}
use std::collections::BTreeMap;
