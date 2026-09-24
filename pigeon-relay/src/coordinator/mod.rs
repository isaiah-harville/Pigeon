// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! Ordering and signed receipts for opaque MLS handshake candidates.

use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;

pub(crate) mod protocol;
pub(crate) mod store;

use store::{Config, Store};

#[derive(Clone)]
pub struct Service {
    pub(crate) store: Arc<Mutex<Store>>,
}

impl Service {
    pub fn new(config: Config, signer: SigningKey) -> Self {
        Self {
            store: Arc::new(Mutex::new(Store::new(config, signer))),
        }
    }

    pub fn expire(&self, now: u64) {
        self.store.lock().unwrap().expire_at(now);
    }
}

#[cfg(test)]
mod tests;
