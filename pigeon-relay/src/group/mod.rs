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
use store::{Config, GroupCapability, Store};

#[derive(Clone)]
pub struct Service {
    pub(crate) store: Arc<Mutex<Store>>,
    pub(crate) subscribers: Arc<Mutex<HashMap<[u8; 32], Vec<Subscriber>>>>,
    pub(crate) registration_admission: Arc<Mutex<RegistrationAdmission>>,
}

const REGISTRATION_WINDOW_SECS: u64 = 60;
const MAX_NEW_REGISTRATIONS_PER_WINDOW: usize = 60;
const MAX_REGISTRATION_ATTEMPTS_PER_CONNECTION: usize = 8;

#[derive(Default)]
pub(crate) struct RegistrationAttempts(usize);

impl RegistrationAttempts {
    pub fn admit(&mut self) -> bool {
        if self.0 >= MAX_REGISTRATION_ATTEMPTS_PER_CONNECTION {
            return false;
        }
        self.0 += 1;
        true
    }
}

#[derive(Default)]
pub(crate) struct RegistrationAdmission {
    window_started: u64,
    accepted: usize,
}

impl RegistrationAdmission {
    pub fn admit(&mut self, now: u64) -> bool {
        if now.saturating_sub(self.window_started) >= REGISTRATION_WINDOW_SECS {
            self.window_started = now;
            self.accepted = 0;
        }
        if self.accepted >= MAX_NEW_REGISTRATIONS_PER_WINDOW {
            return false;
        }
        self.accepted += 1;
        true
    }
}

impl Service {
    pub fn durable(config: Config, journal: GroupJournal, now: u64) -> Result<Self, DurableError> {
        Ok(Self {
            store: Arc::new(Mutex::new(Store::durable(config, journal, now)?)),
            subscribers: Arc::new(Mutex::new(HashMap::new())),
            registration_admission: Arc::new(Mutex::new(RegistrationAdmission::default())),
        })
    }

    pub fn expire(&self, now: u64) {
        self.store.lock().unwrap().expire_at(now);
    }
}

pub struct Subscriber {
    pub connection_id: u64,
    pub capability: GroupCapability,
    pub tx: mpsc::Sender<GroupServerMsg>,
}

#[cfg(test)]
mod tests;
