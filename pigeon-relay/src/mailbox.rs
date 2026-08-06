// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! Mailbox operations: deposit, queued/live delivery, acknowledgement, push-token
//! registration, ownership verification, and expiry. These are the pure mutations
//! over [`AppState`]; the connection loop in [`crate::connection`] drives them.

use std::sync::atomic::Ordering;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use tokio::sync::mpsc;

use crate::protocol::ServerMsg;
use crate::push;
use crate::state::{
    is_valid_address, now, AppState, Deposit, StoredEnvelope, Subscriber, MAX_CIPHERTEXT_LEN,
    PUBKEY_LEN,
};

/// Raw length of an Ed25519 signature, in bytes.
const SIG_LEN: usize = 64;

pub fn publish(
    state: &AppState,
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

    let id = format!("{:016x}", state.counter.fetch_add(1, Ordering::Relaxed));
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

    let mut store = state.mailboxes.lock().unwrap();
    if store.deposit(&recipient, envelope, &state.cfg) == Deposit::AtCapacity {
        drop(store);
        let _ = tx.try_send(ServerMsg::Error {
            message: "relay at capacity".into(),
        });
        return;
    }
    // Fan out to any live, authenticated readers. A channel that is closed or
    // backed up loses its subscription: the queue is the durable path, so its
    // client receives everything on its next subscribe rather than the relay
    // buffering without limit for a reader that has stopped draining.
    store
        .subscribers_mut(&recipient)
        .retain(|s| s.tx.try_send(live.clone()).is_ok());
    drop(store);

    // Wake any suspended/terminated device registered for this mailbox. No-op
    // unless push is configured and the coalescing window has elapsed; runs off
    // the connection task so it never blocks the deposit.
    push::notify_deposit(state.push.clone(), recipient);

    let _ = tx.try_send(ServerMsg::Published { id });
}

/// Binds an APNs device token to the connection's authenticated mailbox. Rejects
/// unauthenticated connections (so only the mailbox's key holder can attach a
/// token) and relays that have no push gateway configured.
pub fn register_push(
    state: &AppState,
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
    if !state.push.enabled() {
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
    state.push.register(mailbox, token);
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
    state: &AppState,
    previous: Option<&str>,
    mailbox: &str,
    conn_id: u64,
    tx: mpsc::Sender<ServerMsg>,
) {
    if let Some(previous) = previous {
        if previous != mailbox {
            remove_subscriber(state, previous, conn_id);
        }
    }
    register_subscriber(state, mailbox, conn_id, tx);
}

pub fn register_subscriber(
    state: &AppState,
    mailbox: &str,
    conn_id: u64,
    tx: mpsc::Sender<ServerMsg>,
) {
    let mut store = state.mailboxes.lock().unwrap();
    let subscribers = store.subscribers_mut(mailbox);
    subscribers.retain(|s| s.conn_id != conn_id);
    subscribers.push(Subscriber { conn_id, tx });
}

pub fn flush_queue(state: &AppState, mailbox: &str, tx: &mpsc::Sender<ServerMsg>) {
    let store = state.mailboxes.lock().unwrap();
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

pub fn ack(state: &AppState, mailbox: &str, id: &str) {
    state.mailboxes.lock().unwrap().ack(mailbox, id);
}

pub fn remove_subscriber(state: &AppState, mailbox: &str, conn_id: u64) {
    state
        .mailboxes
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

/// Drops envelopes older than `cutoff` and reclaims mailboxes with no queue and
/// no live subscribers. Bounds memory; envelopes are ephemeral by design.
pub fn expire_mailboxes(state: &AppState, cutoff: u64) {
    state.mailboxes.lock().unwrap().expire(cutoff);
}
