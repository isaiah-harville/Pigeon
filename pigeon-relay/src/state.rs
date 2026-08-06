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

/// Capacity of a subscriber's outbound channel, in messages. Bounded so a
/// reader that stops draining cannot make the relay buffer without limit: once
/// the channel is full, live deliveries to that reader are skipped rather than
/// queued in memory. Nothing is lost — the mailbox queue is the durable path and
/// an unacked envelope stays there until the client drains it.
pub const SUBSCRIBER_CHANNEL_CAPACITY: usize = 256;

#[derive(Clone)]
pub struct Config {
    /// How long an undelivered envelope is retained before expiry.
    pub ttl_secs: u64,
    /// Maximum envelopes held per mailbox (oldest dropped past this).
    pub max_queue: usize,
    /// Maximum number of mailboxes held at once. Deposits addressed to a *new*
    /// mailbox are refused past this; existing mailboxes keep working.
    pub max_mailboxes: usize,
    /// Maximum total stored ciphertext across all mailboxes, in bytes. The hard
    /// memory ceiling: past it, each deposit evicts the oldest envelope from the
    /// largest mailbox until the store is back under the cap.
    pub max_total_bytes: usize,
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
    pub tx: mpsc::Sender<ServerMsg>,
}

#[derive(Default)]
pub struct Mailbox {
    pub queue: VecDeque<StoredEnvelope>,
    pub subscribers: Vec<Subscriber>,
}

impl Mailbox {
    /// Stored ciphertext held by this mailbox, in bytes.
    fn bytes(&self) -> usize {
        self.queue.iter().map(|e| e.ciphertext.len()).sum()
    }
}

/// The outcome of a deposit.
#[derive(Debug, PartialEq, Eq)]
pub enum Deposit {
    Stored,
    /// Refused: the relay is already holding `max_mailboxes` mailboxes and this
    /// deposit addresses a new one.
    AtCapacity,
}

/// The mailbox map plus its running byte total, so the global memory ceiling can
/// be enforced without walking every queue on each deposit. All mutation goes
/// through these methods — that is what keeps `total_bytes` honest.
#[derive(Default)]
pub struct Store {
    mailboxes: HashMap<String, Mailbox>,
    total_bytes: usize,
}

impl Store {
    /// Number of mailboxes held. Inspection only — the relay never logs or
    /// reports these, so they exist for the bounds tests.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.mailboxes.len()
    }

    /// Total stored ciphertext across all mailboxes, in bytes.
    #[cfg(test)]
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn get(&self, mailbox: &str) -> Option<&Mailbox> {
        self.mailboxes.get(mailbox)
    }

    /// The mailbox's subscriber list, created if the mailbox is new. Subscribers
    /// carry no stored bytes, so this cannot desynchronize `total_bytes`.
    pub fn subscribers_mut(&mut self, mailbox: &str) -> &mut Vec<Subscriber> {
        &mut self
            .mailboxes
            .entry(mailbox.to_string())
            .or_default()
            .subscribers
    }

    /// Stores an envelope, enforcing (in order) the mailbox-count cap, the
    /// per-mailbox queue cap, and the global byte ceiling.
    pub fn deposit(&mut self, mailbox: &str, envelope: StoredEnvelope, cfg: &Config) -> Deposit {
        if !self.mailboxes.contains_key(mailbox) && self.mailboxes.len() >= cfg.max_mailboxes {
            return Deposit::AtCapacity;
        }

        let size = envelope.ciphertext.len();
        let entry = self.mailboxes.entry(mailbox.to_string()).or_default();
        entry.queue.push_back(envelope);
        self.total_bytes += size;

        let mut dropped = 0;
        while entry.queue.len() > cfg.max_queue {
            if let Some(old) = entry.queue.pop_front() {
                dropped += old.ciphertext.len();
            }
        }
        self.total_bytes -= dropped;

        while self.total_bytes > cfg.max_total_bytes && self.evict_from_largest() {}
        Deposit::Stored
    }

    /// Drops the oldest envelope from whichever mailbox is holding the most
    /// bytes. Taking from the largest — rather than the globally oldest — means
    /// pressure falls on whoever is consuming the most storage, so one flooding
    /// address cannot evict everyone else's mail. Returns whether anything was
    /// evicted.
    fn evict_from_largest(&mut self) -> bool {
        let Some(address) = self
            .mailboxes
            .iter()
            .filter(|(_, m)| !m.queue.is_empty())
            .max_by_key(|(_, m)| m.bytes())
            .map(|(address, _)| address.clone())
        else {
            return false;
        };
        let Some(mailbox) = self.mailboxes.get_mut(&address) else {
            return false;
        };
        if let Some(old) = mailbox.queue.pop_front() {
            self.total_bytes -= old.ciphertext.len();
        }
        if mailbox.queue.is_empty() && mailbox.subscribers.is_empty() {
            self.mailboxes.remove(&address);
        }
        true
    }

    /// Drops a connection's subscription, reclaiming the mailbox if that leaves
    /// it empty. Unlike `subscribers_mut`, this never creates a mailbox — a
    /// disconnect must not resurrect one that expiry already reclaimed.
    pub fn remove_subscriber(&mut self, mailbox: &str, conn_id: u64) {
        let Some(entry) = self.mailboxes.get_mut(mailbox) else {
            return;
        };
        entry.subscribers.retain(|s| s.conn_id != conn_id);
        if entry.queue.is_empty() && entry.subscribers.is_empty() {
            self.mailboxes.remove(mailbox);
        }
    }

    /// Deletes an acknowledged envelope.
    pub fn ack(&mut self, mailbox: &str, id: &str) {
        if let Some(entry) = self.mailboxes.get_mut(mailbox) {
            let before: usize = entry.bytes();
            entry.queue.retain(|e| e.id != id);
            self.total_bytes -= before - entry.bytes();
        }
    }

    /// Drops envelopes older than `cutoff` and reclaims mailboxes with no queue
    /// and no live subscribers.
    pub fn expire(&mut self, cutoff: u64) {
        let mut freed = 0;
        self.mailboxes.retain(|_, mailbox| {
            let before = mailbox.bytes();
            mailbox.queue.retain(|e| e.ts >= cutoff);
            freed += before - mailbox.bytes();
            !(mailbox.queue.is_empty() && mailbox.subscribers.is_empty())
        });
        self.total_bytes -= freed;
    }
}

#[derive(Clone)]
pub struct AppState {
    pub mailboxes: Arc<Mutex<Store>>,
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
