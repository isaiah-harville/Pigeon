// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! Append-only ordering for opaque MLS handshake candidates.

use std::collections::{HashMap, VecDeque};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

pub const COORDINATOR_RECEIPT_DOMAIN: &[u8] = b"pigeon.relay.coordinator.receipt.v1";

#[derive(Clone, Debug)]
pub struct Config {
    pub max_candidates_per_epoch: usize,
    pub max_candidate_bytes: usize,
    pub max_total_bytes: usize,
    pub max_fetch_batch_bytes: usize,
    pub ttl_secs: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreError {
    AtCapacity,
    EpochCapacity,
    OversizedCandidate,
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
    #[cfg(test)]
    pub fn verify(&self, key: VerifyingKey) -> bool {
        let Ok(signature) = ed25519_dalek::Signature::from_slice(&self.signature) else {
            return false;
        };
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
        receipt_transcript(
            self.coordination_id,
            self.sequence,
            self.prior_receipt_hash,
            self.claimed_base_epoch,
            self.entry_hash,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinatorCandidate {
    pub receipt: CoordinatorReceipt,
    pub candidate: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Debug, Default)]
struct CoordinatorLog {
    next_sequence: u64,
    receipt_head: [u8; 32],
    candidates: VecDeque<CoordinatorCandidate>,
}

#[derive(Debug)]
pub struct Store {
    config: Config,
    signer: SigningKey,
    logs: HashMap<[u8; 32], CoordinatorLog>,
    total_bytes: usize,
}

impl Store {
    pub fn new(config: Config, signer: SigningKey) -> Self {
        Self {
            config,
            signer,
            logs: HashMap::new(),
            total_bytes: 0,
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signer.verifying_key()
    }

    pub fn submit(
        &mut self,
        coordination_id: [u8; 32],
        claimed_base_epoch: u64,
        candidate: Vec<u8>,
        now: u64,
    ) -> Result<CoordinatorReceipt, StoreError> {
        if candidate.is_empty() || candidate.len() > self.config.max_candidate_bytes {
            return Err(StoreError::OversizedCandidate);
        }
        self.expire_at(now);
        let log = self
            .logs
            .entry(coordination_id)
            .or_insert_with(|| CoordinatorLog {
                next_sequence: 1,
                ..CoordinatorLog::default()
            });
        if let Some(existing) = log
            .candidates
            .iter()
            .find(|entry| entry.candidate == candidate)
        {
            return Ok(existing.receipt.clone());
        }
        if log
            .candidates
            .iter()
            .filter(|entry| entry.receipt.claimed_base_epoch == claimed_base_epoch)
            .count()
            >= self.config.max_candidates_per_epoch
        {
            return Err(StoreError::EpochCapacity);
        }
        if self.total_bytes.saturating_add(candidate.len()) > self.config.max_total_bytes {
            return Err(StoreError::AtCapacity);
        }
        let sequence = log.next_sequence;
        log.next_sequence = log
            .next_sequence
            .checked_add(1)
            .ok_or(StoreError::AtCapacity)?;
        let entry_hash: [u8; 32] = Sha256::digest(&candidate).into();
        let transcript = receipt_transcript(
            coordination_id,
            sequence,
            log.receipt_head,
            claimed_base_epoch,
            entry_hash,
        );
        let receipt = CoordinatorReceipt {
            coordination_id,
            sequence,
            prior_receipt_hash: log.receipt_head,
            claimed_base_epoch,
            entry_hash,
            signature: self.signer.sign(&transcript).to_bytes(),
        };
        log.receipt_head = receipt.receipt_hash();
        self.total_bytes += candidate.len();
        log.candidates.push_back(CoordinatorCandidate {
            receipt: receipt.clone(),
            candidate,
            timestamp: now,
        });
        Ok(receipt)
    }

    pub fn fetch(
        &self,
        coordination_id: [u8; 32],
        after_sequence: u64,
    ) -> Vec<CoordinatorCandidate> {
        self.logs
            .get(&coordination_id)
            .map(|log| {
                let mut bytes = 0_usize;
                log.candidates
                    .iter()
                    .filter(|entry| entry.receipt.sequence > after_sequence)
                    .take_while(|entry| {
                        let next = bytes.saturating_add(entry.candidate.len());
                        if next > self.config.max_fetch_batch_bytes {
                            false
                        } else {
                            bytes = next;
                            true
                        }
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn expire_at(&mut self, now: u64) {
        let cutoff = now.saturating_sub(self.config.ttl_secs);
        let mut freed = 0;
        for log in self.logs.values_mut() {
            while log
                .candidates
                .front()
                .is_some_and(|entry| entry.timestamp < cutoff)
            {
                if let Some(entry) = log.candidates.pop_front() {
                    freed += entry.candidate.len();
                }
            }
        }
        self.total_bytes = self.total_bytes.saturating_sub(freed);
    }
}

pub fn receipt_transcript(
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
