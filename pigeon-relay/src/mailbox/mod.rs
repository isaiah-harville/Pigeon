// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! Identity-addressed mailbox operations: deposit, queued/live delivery, acknowledgement, push-token
//! registration, ownership verification, and expiry. The sibling connection
//! loop supplies shared message IDs and the optional push registry explicitly.

pub(crate) mod connection;
pub(crate) mod protocol;
pub(crate) mod store;

#[cfg(test)]
mod tests;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use tokio::sync::mpsc;

use self::protocol::ServerMsg;
use self::store::{
    is_valid_address, Config, Deposit, Store, StoredEnvelope, Subscriber, MAX_CIPHERTEXT_LEN,
    PUBKEY_LEN,
};
use crate::clock::now;
use crate::push::{self, PushRegistry};

#[derive(Clone)]
pub struct Service {
    pub(crate) store: Arc<Mutex<Store>>,
    pub(crate) config: Config,
}

impl Service {
    pub fn new(config: Config) -> Self {
        Self {
            store: Arc::new(Mutex::new(Store::default())),
            config,
        }
    }

    pub fn expire(&self, cutoff: u64) {
        self.store.lock().unwrap().expire(cutoff);
    }
}

/// Raw length of an Ed25519 signature, in bytes.
const SIG_LEN: usize = 64;

pub fn publish(
    service: &Service,
    message_ids: &AtomicU64,
    push_registry: &Arc<PushRegistry>,
    tx: &mpsc::Sender<ServerMsg>,
    recipient: String,
    ciphertext: String,
) {
    if !is_valid_address(&recipient) {
        let _ = tx.try_send(ServerMsg::Error {
            message: "invalid recipient".into(),
        });
        return;
    }
    if ciphertext.is_empty() || ciphertext.len() > MAX_CIPHERTEXT_LEN {
        let _ = tx.try_send(ServerMsg::Error {
            message: "invalid ciphertext".into(),
        });
        return;
    }

    let id = format!("{:016x}", message_ids.fetch_add(1, Ordering::Relaxed));
    let envelope = StoredEnvelope {
        id: id.clone(),
        ciphertext,
        ts: now(),
    };

    let live = ServerMsg::Envelope {
        id: envelope.id.clone(),
        ciphertext: envelope.ciphertext.clone(),
        ts: envelope.ts,
    };

    let mut store = service.store.lock().unwrap();
    if store.deposit(&recipient, envelope, &service.config) == Deposit::AtCapacity {
        drop(store);
        let _ = tx.try_send(ServerMsg::Error {
            message: "relay at capacity".into(),
        });
        return;
    }
    // Fan out to any live, authenticated readers, distinguishing the two ways a
    // send can fail:
    //
    //   Full   — the reader is behind. Skip this live delivery (it stays queued,
    //            and an unacked envelope is never lost) but *keep* the
    //            subscription: dropping it would silently stop every future live
    //            delivery to a client whose socket is still perfectly healthy,
    //            with nothing to tell it to reconnect.
    //   Closed — the connection is gone. Drop it.
    //
    // Either way the relay never buffers past the channel bound.
    store.subscribers_mut(&recipient).retain(|s| {
        !matches!(
            s.tx.try_send(live.clone()),
            Err(mpsc::error::TrySendError::Closed(_))
        )
    });
    drop(store);

    // Wake any suspended/terminated device registered for this mailbox. No-op
    // unless push is configured and the coalescing window has elapsed; runs off
    // the connection task so it never blocks the deposit.
    push::notify_deposit(push_registry.clone(), recipient);

    let _ = tx.try_send(ServerMsg::Published { id });
}

/// Binds an APNs device token to the connection's authenticated mailbox. Rejects
/// unauthenticated connections (so only the mailbox's key holder can attach a
/// token) and relays that have no push gateway configured.
pub fn register_push(
    push_registry: &PushRegistry,
    tx: &mpsc::Sender<ServerMsg>,
    authed_mailbox: Option<&str>,
    token: String,
) {
    let Some(mailbox) = authed_mailbox else {
        let _ = tx.try_send(ServerMsg::Error {
            message: "not authenticated".into(),
        });
        return;
    };
    if !push_registry.enabled() {
        let _ = tx.try_send(ServerMsg::Error {
            message: "push not supported".into(),
        });
        return;
    }
    if !push::is_valid_token(&token) {
        let _ = tx.try_send(ServerMsg::Error {
            message: "invalid token".into(),
        });
        return;
    }
    if !push_registry.register(mailbox, token) {
        let _ = tx.try_send(ServerMsg::Error {
            message: "push registry full".into(),
        });
        return;
    }
    let _ = tx.try_send(ServerMsg::Ok {
        detail: "push registered".into(),
    });
}

/// Moves a connection's subscription from `previous` (if it had authenticated
/// to a different mailbox) to `mailbox`. Without dropping the old registration,
/// a connection that re-authenticates leaves a subscriber entry behind on the
/// mailbox it no longer serves: the disconnect path only unregisters the last
/// mailbox, so the stale entry lingers until some later deposit happens to
/// notice its channel is dead — and until then that mailbox keeps being treated
/// as having a live reader.
pub fn switch_subscription(
    service: &Service,
    previous: Option<&str>,
    mailbox: &str,
    conn_id: u64,
    tx: mpsc::Sender<ServerMsg>,
) {
    if let Some(previous) = previous {
        if previous != mailbox {
            remove_subscriber(service, previous, conn_id);
        }
    }
    register_subscriber(service, mailbox, conn_id, tx);
}

pub fn register_subscriber(
    service: &Service,
    mailbox: &str,
    conn_id: u64,
    tx: mpsc::Sender<ServerMsg>,
) {
    let mut store = service.store.lock().unwrap();
    let subscribers = store.subscribers_mut(mailbox);
    subscribers.retain(|s| s.conn_id != conn_id);
    subscribers.push(Subscriber { conn_id, tx });
}

pub fn flush_queue(service: &Service, mailbox: &str, tx: &mpsc::Sender<ServerMsg>) {
    let store = service.store.lock().unwrap();
    if let Some(entry) = store.get(mailbox) {
        for envelope in &entry.queue {
            let _ = tx.try_send(ServerMsg::Envelope {
                id: envelope.id.clone(),
                ciphertext: envelope.ciphertext.clone(),
                ts: envelope.ts,
            });
        }
    }
}

pub fn ack(service: &Service, mailbox: &str, id: &str) {
    service.store.lock().unwrap().ack(mailbox, id);
}

pub fn remove_subscriber(service: &Service, mailbox: &str, conn_id: u64) {
    service
        .store
        .lock()
        .unwrap()
        .remove_subscriber(mailbox, conn_id);
}

/// Verifies that whoever sent `signature` holds the private key for `mailbox`,
/// by checking an Ed25519 signature over the challenge `nonce`. The relay only
/// ever learns public keys (which are the addresses anyway).
pub fn verify_ownership(mailbox_hex: &str, nonce: &[u8], signature_b64: &str) -> bool {
    let Ok(pk_bytes) = hex::decode(mailbox_hex) else {
        return false;
    };
    let Ok(pk_arr) = <[u8; PUBKEY_LEN]>::try_from(pk_bytes.as_slice()) else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&pk_arr) else {
        return false;
    };

    let Ok(sig_bytes) = B64.decode(signature_b64) else {
        return false;
    };
    let Ok(sig_arr) = <[u8; SIG_LEN]>::try_from(sig_bytes.as_slice()) else {
        return false;
    };
    let signature = Signature::from_bytes(&sig_arr);

    verifying_key.verify_strict(nonce, &signature).is_ok()
}
