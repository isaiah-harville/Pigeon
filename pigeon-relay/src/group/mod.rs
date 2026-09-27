// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! Capability-authorized storage and delivery of opaque group ciphertext.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

pub(crate) mod connection;
pub(crate) mod protocol;
pub(crate) mod store;

use crate::durable::{DurableError, GroupJournal};
use protocol::GroupServerMsg;
use store::{Config, Store};

#[derive(Clone)]
pub struct Service {
    pub(crate) store: Arc<Mutex<Store>>,
    pub(crate) subscribers: Arc<Mutex<HashMap<[u8; 32], Vec<Subscriber>>>>,
}

impl Service {
    pub fn durable(config: Config, journal: GroupJournal, now: u64) -> Result<Self, DurableError> {
        Ok(Self {
            store: Arc::new(Mutex::new(Store::durable(config, journal, now)?)),
            subscribers: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn expire(&self, now: u64) {
        self.store.lock().unwrap().expire_at(now);
    }
}

pub struct Subscriber {
    pub connection_id: u64,
    pub tx: mpsc::Sender<GroupServerMsg>,
}

#[cfg(test)]
mod tests;
