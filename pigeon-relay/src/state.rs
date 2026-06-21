// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! Shared relay state: the in-memory mailbox map and the per-process config.
//! Storage is intentionally ephemeral — a relay is a transient rendezvous, not
//! durable storage.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;

use crate::protocol::ServerMsg;
use crate::push::PushRegistry;

/// Raw length of an Ed25519 public key / mailbox address, in bytes.
pub const PUBKEY_LEN: usize = 32;
/// Upper bound on a single stored ciphertext (base64 chars). Bounds memory and
/// blunts trivial flooding; well above a fragmented Pigeon envelope.
pub const MAX_CIPHERTEXT_LEN: usize = 256 * 1024;

#[derive(Clone)]
pub struct Config {
    /// How long an undelivered envelope is retained before expiry.
    pub ttl_secs: u64,
    /// Maximum envelopes held per mailbox (oldest dropped past this).
    pub max_queue: usize,
}

#[derive(Clone)]
pub struct StoredEnvelope {
    pub id: String,
    /// Opaque base64 ciphertext. The relay never decodes or inspects it.
    pub ciphertext: String,
    pub ts: u64,
}

/// A live, authenticated reader of a mailbox.
pub struct Subscriber {
    pub conn_id: u64,
    pub tx: mpsc::UnboundedSender<ServerMsg>,
}

#[derive(Default)]
pub struct Mailbox {
    pub queue: VecDeque<StoredEnvelope>,
    pub subscribers: Vec<Subscriber>,
}

#[derive(Clone)]
pub struct AppState {
    pub mailboxes: Arc<Mutex<HashMap<String, Mailbox>>>,
    pub cfg: Config,
    /// Monotonic counter for connection ids and envelope ids.
    pub counter: Arc<AtomicU64>,
    /// Opt-in APNs wake-up registry. Inert (refuses registration, never pushes)
    /// unless an APNs gateway is configured — i.e. only the official relay.
    pub push: Arc<PushRegistry>,
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Whether `hex_str` decodes to exactly a 32-byte public key.
pub fn is_valid_address(hex_str: &str) -> bool {
    matches!(hex::decode(hex_str), Ok(bytes) if bytes.len() == PUBKEY_LEN)
}
