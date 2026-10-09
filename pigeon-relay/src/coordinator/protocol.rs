// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! JSON representations of relay-signed coordinator receipts and candidates.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::Serialize;

use super::store::{CoordinatorCandidate, CoordinatorReceipt};

#[derive(Clone, Debug, Serialize)]
pub struct ReceiptWire {
    pub coordination_id: String,
    pub sequence: u64,
    pub prior_receipt_hash: String,
    pub claimed_base_epoch: u64,
    pub entry_hash: String,
    pub signature: String,
}

impl From<CoordinatorReceipt> for ReceiptWire {
    fn from(receipt: CoordinatorReceipt) -> Self {
        Self {
            coordination_id: hex::encode(receipt.coordination_id),
            sequence: receipt.sequence,
            prior_receipt_hash: hex::encode(receipt.prior_receipt_hash),
            claimed_base_epoch: receipt.claimed_base_epoch,
            entry_hash: hex::encode(receipt.entry_hash),
            signature: B64.encode(receipt.signature),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CandidateWire {
    pub receipt: ReceiptWire,
    pub candidate: String,
    pub timestamp: u64,
}

impl From<CoordinatorCandidate> for CandidateWire {
    fn from(candidate: CoordinatorCandidate) -> Self {
        Self {
            receipt: candidate.receipt.into(),
            candidate: B64.encode(candidate.candidate),
            timestamp: candidate.timestamp,
        }
    }
}
