// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! Bounded in-memory storage for identity-addressed opaque ciphertext.

use std::collections::{HashMap, VecDeque};

use tokio::sync::mpsc;

use super::protocol::ServerMsg;

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
    pub queue: VecDeque<StoredEnvelope>,
    pub subscribers: Vec<Subscriber>,
}

impl Mailbox {
    fn bytes(&self) -> usize {
        self.queue
            .iter()
            .map(|envelope| envelope.ciphertext.len())
            .sum()
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

        let size = envelope.ciphertext.len();
        let entry = self.mailboxes.entry(mailbox.to_string()).or_default();
        entry.queue.push_back(envelope);
        self.total_bytes += size;

        let mut dropped = 0;
        while entry.queue.len() > config.max_queue {
            if let Some(old) = entry.queue.pop_front() {
                dropped += old.ciphertext.len();
            }
        }
        self.total_bytes -= dropped;

        while self.total_bytes > config.max_total_bytes && self.evict_from_largest() {}
        Deposit::Stored
    }

    fn evict_from_largest(&mut self) -> bool {
        let Some(address) = self
            .mailboxes
            .iter()
            .filter(|(_, mailbox)| !mailbox.queue.is_empty())
            .max_by_key(|(_, mailbox)| mailbox.bytes())
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
            let before = entry.bytes();
            entry.queue.retain(|envelope| envelope.id != id);
            self.total_bytes -= before - entry.bytes();
        }
    }

    pub fn expire(&mut self, cutoff: u64) {
        let mut freed = 0;
        self.mailboxes.retain(|_, mailbox| {
            let before = mailbox.bytes();
            mailbox.queue.retain(|envelope| envelope.ts >= cutoff);
            freed += before - mailbox.bytes();
            !(mailbox.queue.is_empty() && mailbox.subscribers.is_empty())
        });
        self.total_bytes -= freed;
    }
}

pub fn is_valid_address(value: &str) -> bool {
    matches!(hex::decode(value), Ok(bytes) if bytes.len() == PUBKEY_LEN)
}
