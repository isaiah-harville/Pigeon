// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! The wire protocol: JSON frames exchanged over the WebSocket at `/ws`.
//! Addresses are hex Ed25519 public keys; ciphertext blobs are base64 and the
//! relay never decodes them.

use serde::{Deserialize, Serialize};

/// Messages a client sends to the relay.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    /// Deposit ciphertext for `recipient` (hex Ed25519 public key). The sender
    /// is anonymous to the relay; no authentication is required to publish.
    Publish {
        recipient: String,
        ciphertext: String,
    },
    /// Begin reading the mailbox for `mailbox` (hex Ed25519 public key). The
    /// relay replies with a `challenge` the client must sign to prove ownership.
    Subscribe { mailbox: String },
    /// Prove ownership of the just-subscribed mailbox by signing the challenge
    /// nonce with the mailbox's Ed25519 private key (signature base64).
    Auth { signature: String },
    /// Acknowledge an `envelope`, deleting it from the mailbox.
    Ack { id: String },
    /// Register an APNs device token (hex) to receive content-free wake-up
    /// pushes for the just-authenticated mailbox. Only honored after `Auth`, so
    /// a token is bound to a mailbox solely by that mailbox's key holder. Only
    /// the official deployment (with a configured gateway) accepts these.
    RegisterPush { token: String },
    /// Remove a previously registered token (opt-out / token rotation).
    UnregisterPush { token: String },
}

/// Messages the relay sends to a client.
#[derive(Serialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    /// A random nonce the client must sign to authenticate (base64).
    Challenge { nonce: String },
    /// A stored ciphertext envelope delivered to an authenticated subscriber.
    Envelope {
        id: String,
        ciphertext: String,
        ts: u64,
    },
    /// Confirms a `publish` was stored.
    Published { id: String },
    /// Generic success.
    Ok { detail: String },
    /// Generic failure (never includes addresses or content).
    Error { message: String },
}
