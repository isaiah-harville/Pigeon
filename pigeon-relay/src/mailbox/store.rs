// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! Bounded storage for identity-addressed opaque ciphertext: an in-memory
//! query path written through to a SQLite journal.

use std::collections::{HashMap, VecDeque};

use tokio::sync::mpsc;

use super::protocol::ServerMsg;
use crate::durable::{fail_stop, MailboxEnvelopeRecord, MailboxJournal};

pub const PUBKEY_LEN: usize = 32;
pub const MAX_CIPHERTEXT_LEN: usize = 256 * 1024;

#[derive(Clone, Debug)]
pub struct Config {
    pub ttl_secs: u64,
    pub max_queue: usize,
    pub max_mailboxes: usize,
    pub max_total_bytes: usize,
}

#[derive(Clone)]
pub struct StoredEnvelope {
    pub id: String,
    pub ciphertext: String,
    pub ts: u64,
}

pub struct Subscriber {
    pub conn_id: u64,
    pub tx: mpsc::Sender<ServerMsg>,
}

#[derive(Default)]
pub struct Mailbox {
    /// Read-only outside this module so `bytes` stays exact; mutate through
    /// `push`, `pop_front`, and `retain`.
    pub queue: VecDeque<StoredEnvelope>,
    pub subscribers: Vec<Subscriber>,
    /// Sum of queued ciphertext lengths, kept in step with `queue`.
    bytes: usize,
}

impl Mailbox {
    fn bytes(&self) -> usize {
        self.bytes
    }

    fn push(&mut self, envelope: StoredEnvelope) {
        self.bytes += envelope.ciphertext.len();
        self.queue.push_back(envelope);
    }

    fn pop_front(&mut self) -> Option<StoredEnvelope> {
        let envelope = self.queue.pop_front()?;
        self.bytes -= envelope.ciphertext.len();
        Some(envelope)
    }

    /// Keeps envelopes matching `keep`; returns the bytes released.
    fn retain(&mut self, mut keep: impl FnMut(&StoredEnvelope) -> bool) -> usize {
        let before = self.bytes;
        let mut kept = 0;
        self.queue.retain(|envelope| {
            let retained = keep(envelope);
            if retained {
                kept += envelope.ciphertext.len();
            }
            retained
        });
        self.bytes = kept;
        before - kept
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Deposit {
    Stored,
    AtCapacity,
}

#[derive(Default)]
pub struct Store {
    mailboxes: HashMap<String, Mailbox>,
    total_bytes: usize,
    /// Write-through persistence. `None` only in unit tests of the bounds.
    journal: Option<MailboxJournal>,
}

impl Store {
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.mailboxes.len()
    }

    #[cfg(test)]
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn get(&self, mailbox: &str) -> Option<&Mailbox> {
        self.mailboxes.get(mailbox)
    }

    pub fn subscribers_mut(&mut self, mailbox: &str) -> &mut Vec<Subscriber> {
        &mut self
            .mailboxes
            .entry(mailbox.to_string())
            .or_default()
            .subscribers
    }

    pub fn deposit(&mut self, mailbox: &str, envelope: StoredEnvelope, config: &Config) -> Deposit {
        if !self.mailboxes.contains_key(mailbox) && self.mailboxes.len() >= config.max_mailboxes {
            return Deposit::AtCapacity;
        }
        let record = self.journal.as_ref().map(|_| MailboxEnvelopeRecord {
            mailbox: mailbox.to_owned(),
            id: envelope.id.clone(),
            ciphertext: envelope.ciphertext.clone(),
            timestamp: envelope.ts,
        });
        let evicted = self.insert(mailbox, envelope, config);
        // Durable before the caller replies `published`; a failed write stops
        // the relay rather than acknowledge a deposit a restart would lose.
        if let (Some(journal), Some(record)) = (self.journal.as_mut(), record) {
            if let Err(error) = journal.deposit(&record, &evicted) {
                fail_stop(error);
            }
        }
        Deposit::Stored
    }

    /// Applies the queue and byte bounds; returns the (mailbox, id) of every
    /// envelope dropped to make room.
    fn insert(
        &mut self,
        mailbox: &str,
        envelope: StoredEnvelope,
        config: &Config,
    ) -> Vec<(String, String)> {
        let size = envelope.ciphertext.len();
        let entry = self.mailboxes.entry(mailbox.to_string()).or_default();
        entry.push(envelope);
        self.total_bytes += size;

        let mut evicted = Vec::new();
        let mut dropped = 0;
        while entry.queue.len() > config.max_queue {
            if let Some(old) = entry.pop_front() {
                dropped += old.ciphertext.len();
                evicted.push((mailbox.to_owned(), old.id));
            }
        }
        self.total_bytes -= dropped;

        while self.total_bytes > config.max_total_bytes {
            match self.evict_from_largest() {
                Some(dropped) => evicted.push(dropped),
                None => break,
            }
        }
        evicted
    }

    fn evict_from_largest(&mut self) -> Option<(String, String)> {
        let address = self
            .mailboxes
            .iter()
            .filter(|(_, mailbox)| !mailbox.queue.is_empty())
            .max_by_key(|(_, mailbox)| mailbox.bytes())
            .map(|(address, _)| address.clone())?;
        let mailbox = self.mailboxes.get_mut(&address)?;
        let old = mailbox.pop_front()?;
        self.total_bytes -= old.ciphertext.len();
        if mailbox.queue.is_empty() && mailbox.subscribers.is_empty() {
            self.mailboxes.remove(&address);
        }
        Some((address, old.id))
    }

    /// Rebuilds memory from the journal after a restart, re-applying today's
    /// bounds. Returns the largest envelope id seen, so new ids never collide
    /// with persisted ones.
    pub fn restore(
        journal: MailboxJournal,
        records: Vec<MailboxEnvelopeRecord>,
        config: &Config,
    ) -> (Self, u64) {
        let mut store = Self::default();
        let mut max_id = 0;
        let mut evicted = Vec::new();
        for record in records {
            if !is_valid_address(&record.mailbox) {
                continue;
            }
            max_id = max_id.max(u64::from_str_radix(&record.id, 16).unwrap_or(0));
            if !store.mailboxes.contains_key(&record.mailbox)
                && store.mailboxes.len() >= config.max_mailboxes
            {
                evicted.push((record.mailbox, record.id));
                continue;
            }
            let envelope = StoredEnvelope {
                id: record.id,
                ciphertext: record.ciphertext,
                ts: record.timestamp,
            };
            evicted.extend(store.insert(&record.mailbox, envelope, config));
        }
        for (mailbox, id) in &evicted {
            if let Err(error) = journal.ack(mailbox, id) {
                fail_stop(error);
            }
        }
        store.journal = Some(journal);
        (store, max_id)
    }

    pub fn remove_subscriber(&mut self, mailbox: &str, conn_id: u64) {
        let Some(entry) = self.mailboxes.get_mut(mailbox) else {
            return;
        };
        entry
            .subscribers
            .retain(|subscriber| subscriber.conn_id != conn_id);
        if entry.queue.is_empty() && entry.subscribers.is_empty() {
            self.mailboxes.remove(mailbox);
        }
    }

    pub fn ack(&mut self, mailbox: &str, id: &str) {
        if let Some(entry) = self.mailboxes.get_mut(mailbox) {
            self.total_bytes -= entry.retain(|envelope| envelope.id != id);
        }
        if let Some(journal) = &self.journal {
            if let Err(error) = journal.ack(mailbox, id) {
                fail_stop(error);
            }
        }
    }

    pub fn expire(&mut self, cutoff: u64) {
        let mut freed = 0;
        self.mailboxes.retain(|_, mailbox| {
            freed += mailbox.retain(|envelope| envelope.ts >= cutoff);
            !(mailbox.queue.is_empty() && mailbox.subscribers.is_empty())
        });
        self.total_bytes -= freed;
        if let Some(journal) = &self.journal {
            if let Err(error) = journal.expire(cutoff) {
                fail_stop(error);
            }
        }
    }
}

pub fn is_valid_address(value: &str) -> bool {
    matches!(hex::decode(value), Ok(bytes) if bytes.len() == PUBKEY_LEN)
}
