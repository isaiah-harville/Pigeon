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
    is_valid_address, now, AppState, StoredEnvelope, Subscriber, MAX_CIPHERTEXT_LEN, PUBKEY_LEN,
};

/// Raw length of an Ed25519 signature, in bytes.
const SIG_LEN: usize = 64;

pub fn publish(
    state: &AppState,
    tx: &mpsc::UnboundedSender<ServerMsg>,
    recipient: String,
    ciphertext: String,
) {
    if !is_valid_address(&recipient) {
        let _ = tx.send(ServerMsg::Error {
            message: "invalid recipient".into(),
        });
        return;
    }
    if ciphertext.is_empty() || ciphertext.len() > MAX_CIPHERTEXT_LEN {
        let _ = tx.send(ServerMsg::Error {
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

    let mut mailboxes = state.mailboxes.lock().unwrap();
    let mailbox = mailboxes.entry(recipient.clone()).or_default();
    mailbox.queue.push_back(envelope.clone());
    while mailbox.queue.len() > state.cfg.max_queue {
        mailbox.queue.pop_front();
    }
    // Fan out to any live, authenticated readers; drop dead channels.
    let live = ServerMsg::Envelope {
        id: envelope.id.clone(),
        ciphertext: envelope.ciphertext.clone(),
        ts: envelope.ts,
    };
    mailbox
        .subscribers
        .retain(|s| s.tx.send(live.clone()).is_ok());
    drop(mailboxes);

    // Wake any suspended/terminated device registered for this mailbox. No-op
    // unless push is configured and the coalescing window has elapsed; runs off
    // the connection task so it never blocks the deposit.
    push::notify_deposit(state.push.clone(), recipient);

    let _ = tx.send(ServerMsg::Published { id });
}

/// Binds an APNs device token to the connection's authenticated mailbox. Rejects
/// unauthenticated connections (so only the mailbox's key holder can attach a
/// token) and relays that have no push gateway configured.
pub fn register_push(
    state: &AppState,
    tx: &mpsc::UnboundedSender<ServerMsg>,
    authed_mailbox: Option<&str>,
    token: String,
) {
    let Some(mailbox) = authed_mailbox else {
        let _ = tx.send(ServerMsg::Error {
            message: "not authenticated".into(),
        });
        return;
    };
    if !state.push.enabled() {
        let _ = tx.send(ServerMsg::Error {
            message: "push not supported".into(),
        });
        return;
    }
    if !push::is_valid_token(&token) {
        let _ = tx.send(ServerMsg::Error {
            message: "invalid token".into(),
        });
        return;
    }
    state.push.register(mailbox, token);
    let _ = tx.send(ServerMsg::Ok {
        detail: "push registered".into(),
    });
}

pub fn register_subscriber(
    state: &AppState,
    mailbox: &str,
    conn_id: u64,
    tx: mpsc::UnboundedSender<ServerMsg>,
) {
    let mut mailboxes = state.mailboxes.lock().unwrap();
    let entry = mailboxes.entry(mailbox.to_string()).or_default();
    entry.subscribers.retain(|s| s.conn_id != conn_id);
    entry.subscribers.push(Subscriber { conn_id, tx });
}

pub fn flush_queue(state: &AppState, mailbox: &str, tx: &mpsc::UnboundedSender<ServerMsg>) {
    let mailboxes = state.mailboxes.lock().unwrap();
    if let Some(entry) = mailboxes.get(mailbox) {
        for envelope in &entry.queue {
            let _ = tx.send(ServerMsg::Envelope {
                id: envelope.id.clone(),
                ciphertext: envelope.ciphertext.clone(),
                ts: envelope.ts,
            });
        }
    }
}

pub fn ack(state: &AppState, mailbox: &str, id: &str) {
    let mut mailboxes = state.mailboxes.lock().unwrap();
    if let Some(entry) = mailboxes.get_mut(mailbox) {
        entry.queue.retain(|e| e.id != id);
    }
}

pub fn remove_subscriber(state: &AppState, mailbox: &str, conn_id: u64) {
    let mut mailboxes = state.mailboxes.lock().unwrap();
    if let Some(entry) = mailboxes.get_mut(mailbox) {
        entry.subscribers.retain(|s| s.conn_id != conn_id);
    }
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
    let mut mailboxes = state.mailboxes.lock().unwrap();
    mailboxes.retain(|_, mailbox| {
        mailbox.queue.retain(|e| e.ts >= cutoff);
        !(mailbox.queue.is_empty() && mailbox.subscribers.is_empty())
    });
}
