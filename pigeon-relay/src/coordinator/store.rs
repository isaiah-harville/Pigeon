// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! Append-only ordering for opaque MLS handshake candidates.

use std::collections::{HashMap, VecDeque};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::durable::{fail_stop, CandidateWrite, CoordinatorJournal, DurableError, LogRecord};

pub const COORDINATOR_RECEIPT_DOMAIN: &[u8] = b"pigeon.relay.coordinator.receipt.v1";

#[derive(Clone, Debug)]
pub struct Config {
    pub max_logs: usize,
    pub max_candidates_per_log: usize,
    pub max_candidates_per_epoch: usize,
    pub max_candidates_per_capability_per_epoch: usize,
    pub max_candidate_bytes: usize,
    pub max_total_bytes: usize,
    pub max_fetch_batch_bytes: usize,
    pub ttl_secs: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreError {
    AtCapacity,
    EpochCapacity,
    CapabilityEpochCapacity,
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
    submitter_capability_id: [u8; 32],
}

#[derive(Debug, Default)]
struct CoordinatorLog {
    next_sequence: u64,
    receipt_head: [u8; 32],
    candidates: VecDeque<CoordinatorCandidate>,
}

pub struct Store {
    config: Config,
    signer: SigningKey,
    logs: HashMap<[u8; 32], CoordinatorLog>,
    total_bytes: usize,
    /// Write-through durable copy; `None` keeps the store memory-only.
    journal: Option<CoordinatorJournal>,
}

impl Store {
    pub fn new(config: Config, signer: SigningKey) -> Self {
        Self {
            config,
            signer,
            logs: HashMap::new(),
            total_bytes: 0,
            journal: None,
        }
    }

    /// Restores every receipt log from `journal` and writes through each newly
    /// signed receipt. The journal is bound to this signer's public key.
    pub fn durable(
        config: Config,
        signer: SigningKey,
        journal: CoordinatorJournal,
        now: u64,
    ) -> Result<Self, DurableError> {
        let cutoff = now.saturating_sub(config.ttl_secs);
        let mut store = Self::new(config, signer);
        let records = journal.load(cutoff)?;
        if records
            .iter()
            .filter(|record| !record.candidates.is_empty())
            .count()
            > store.config.max_logs
        {
            return Err(DurableError::Corrupt(
                "coordinator log count exceeds configured limit",
            ));
        }
        for record in records {
            validate_log(
                &record,
                &store.config,
                store.total_bytes,
                store.signer.verifying_key(),
            )?;
            let candidates: VecDeque<CoordinatorCandidate> = record
                .candidates
                .into_iter()
                .map(|candidate| CoordinatorCandidate {
                    receipt: CoordinatorReceipt {
                        coordination_id: record.coordination_id,
                        sequence: candidate.sequence,
                        prior_receipt_hash: candidate.prior_receipt_hash,
                        claimed_base_epoch: candidate.claimed_base_epoch,
                        entry_hash: candidate.entry_hash,
                        signature: candidate.signature,
                    },
                    candidate: candidate.candidate,
                    timestamp: candidate.timestamp,
                    submitter_capability_id: candidate.submitter_capability_id,
                })
                .collect();
            store.total_bytes += candidates
                .iter()
                .map(|entry| entry.candidate.len())
                .sum::<usize>();
            store.logs.insert(
                record.coordination_id,
                CoordinatorLog {
                    next_sequence: record.next_sequence,
                    receipt_head: record.receipt_head,
                    candidates,
                },
            );
        }
        store.journal = Some(journal);
        store.expire_at(now);
        Ok(store)
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signer.verifying_key()
    }

    pub fn submit(
        &mut self,
        coordination_id: [u8; 32],
        capability_id: [u8; 32],
        claimed_base_epoch: u64,
        candidate: Vec<u8>,
        now: u64,
    ) -> Result<CoordinatorReceipt, StoreError> {
        if candidate.is_empty() || candidate.len() > self.config.max_candidate_bytes {
            return Err(StoreError::OversizedCandidate);
        }
        self.expire_memory(now);
        if self
            .logs
            .get(&coordination_id)
            .is_none_or(|log| log.candidates.is_empty())
            && self
                .logs
                .values()
                .filter(|log| !log.candidates.is_empty())
                .count()
                >= self.config.max_logs
        {
            return Err(StoreError::AtCapacity);
        }
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
            .filter(|entry| {
                entry.receipt.claimed_base_epoch == claimed_base_epoch
                    && entry.submitter_capability_id == capability_id
            })
            .count()
            >= self.config.max_candidates_per_capability_per_epoch
        {
            return Err(StoreError::CapabilityEpochCapacity);
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
        if log.candidates.len() >= self.config.max_candidates_per_log {
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
        if let Some(journal) = self.journal.as_mut() {
            // The receipt is signed but not yet visible to anyone: persist it
            // before it can be returned or fetched.
            let write = CandidateWrite {
                sequence,
                prior_receipt_hash: receipt.prior_receipt_hash,
                claimed_base_epoch,
                entry_hash,
                signature: receipt.signature,
                candidate: &candidate,
                timestamp: now,
                submitter_capability_id: capability_id,
            };
            if let Err(error) = journal.record_candidate(
                &coordination_id,
                log.next_sequence,
                &log.receipt_head,
                &write,
            ) {
                fail_stop(error);
            }
        }
        self.total_bytes += candidate.len();
        log.candidates.push_back(CoordinatorCandidate {
            receipt: receipt.clone(),
            candidate,
            timestamp: now,
            submitter_capability_id: capability_id,
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
                        if bytes > 0 && next > self.config.max_fetch_batch_bytes {
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
        if let Some(journal) = self.journal.as_mut() {
            if let Err(error) = journal.expire(now.saturating_sub(self.config.ttl_secs)) {
                fail_stop(error);
            }
        }
        self.expire_memory(now);
    }

    fn expire_memory(&mut self, now: u64) {
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

fn validate_log(
    record: &LogRecord,
    config: &Config,
    existing_bytes: usize,
    verifying_key: VerifyingKey,
) -> Result<(), DurableError> {
    if record.next_sequence == 0 || record.candidates.len() > config.max_candidates_per_log {
        return Err(DurableError::Corrupt("invalid coordinator log bounds"));
    }
    let mut prior_sequence = None;
    let mut prior_hash = None;
    let mut bytes = existing_bytes;
    let mut aggregate_per_epoch = HashMap::<u64, usize>::new();
    let mut per_capability_epoch = HashMap::<(u64, [u8; 32]), usize>::new();
    for candidate in &record.candidates {
        if candidate.sequence == 0
            || candidate.sequence >= record.next_sequence
            || candidate.candidate.is_empty()
            || candidate.candidate.len() > config.max_candidate_bytes
            || Sha256::digest(&candidate.candidate).as_slice() != candidate.entry_hash
        {
            return Err(DurableError::Corrupt("invalid coordinator candidate"));
        }
        let receipt = CoordinatorReceipt {
            coordination_id: record.coordination_id,
            sequence: candidate.sequence,
            prior_receipt_hash: candidate.prior_receipt_hash,
            claimed_base_epoch: candidate.claimed_base_epoch,
            entry_hash: candidate.entry_hash,
            signature: candidate.signature,
        };
        let signature = ed25519_dalek::Signature::from_bytes(&candidate.signature);
        if verifying_key
            .verify_strict(&receipt.signing_transcript(), &signature)
            .is_err()
            || prior_sequence.is_some_and(|sequence| candidate.sequence != sequence + 1)
            || prior_hash.is_some_and(|hash| candidate.prior_receipt_hash != hash)
        {
            return Err(DurableError::Corrupt("invalid coordinator receipt chain"));
        }
        prior_sequence = Some(candidate.sequence);
        prior_hash = Some(receipt.receipt_hash());
        bytes = bytes.saturating_add(candidate.candidate.len());
        if bytes > config.max_total_bytes {
            return Err(DurableError::Corrupt(
                "coordinator bytes exceed configured limit",
            ));
        }
        let epoch_count = aggregate_per_epoch
            .entry(candidate.claimed_base_epoch)
            .or_default();
        *epoch_count += 1;
        let capability_count = per_capability_epoch
            .entry((
                candidate.claimed_base_epoch,
                candidate.submitter_capability_id,
            ))
            .or_default();
        *capability_count += 1;
        if *epoch_count > config.max_candidates_per_epoch
            || *capability_count > config.max_candidates_per_capability_per_epoch
        {
            return Err(DurableError::Corrupt(
                "coordinator quota exceeds configured limit",
            ));
        }
    }
    if prior_hash.is_some_and(|hash| hash != record.receipt_head) {
        return Err(DurableError::Corrupt("coordinator receipt head mismatch"));
    }
    Ok(())
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
