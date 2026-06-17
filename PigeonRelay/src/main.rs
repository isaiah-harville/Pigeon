// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! Pigeon relay — a zero-knowledge, federated ciphertext mailbox.
//!
//! The relay exists for one reason: two devices that are out of Bluetooth/local
//! range and on different networks (e.g. both on cellular) cannot connect
//! directly, because behind NAT a phone can dial out but not be dialed in. They
//! need a mutually-reachable rendezvous. This is that rendezvous, and nothing
//! more.
//!
//! It is deliberately *blind*: it stores and forwards opaque ciphertext blobs
//! addressed by a recipient's Ed25519 public key. It never decodes a payload,
//! never holds a key, and never logs an address or content. Confidentiality,
//! authentication, integrity, and trust are all enforced end-to-end by the
//! Pigeon clients, below this layer — a compromised relay yields metadata and a
//! denial-of-service position, never plaintext or a forged session.
//!
//! Federation is inherent: relays are independent and never talk to each other.
//! A user advertises the relay(s) they can be reached at (in their contact
//! bundle); senders deliver to those relays. Run as many as you like.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

/// Raw length of an Ed25519 public key / mailbox address, in bytes.
const PUBKEY_LEN: usize = 32;
/// Raw length of an Ed25519 signature, in bytes.
const SIG_LEN: usize = 64;
/// Upper bound on a single stored ciphertext (base64 chars). Bounds memory and
/// blunts trivial flooding; well above a fragmented Pigeon envelope.
const MAX_CIPHERTEXT_LEN: usize = 256 * 1024;

// ---------------------------------------------------------------------------
// Wire protocol (JSON over a WebSocket at /ws)
// ---------------------------------------------------------------------------

/// Messages a client sends to the relay.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMsg {
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
}

/// Messages the relay sends to a client.
#[derive(Serialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMsg {
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

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Config {
    /// How long an undelivered envelope is retained before expiry.
    ttl_secs: u64,
    /// Maximum envelopes held per mailbox (oldest dropped past this).
    max_queue: usize,
}

#[derive(Clone)]
struct StoredEnvelope {
    id: String,
    /// Opaque base64 ciphertext. The relay never decodes or inspects it.
    ciphertext: String,
    ts: u64,
}

/// A live, authenticated reader of a mailbox.
struct Subscriber {
    conn_id: u64,
    tx: mpsc::UnboundedSender<ServerMsg>,
}

#[derive(Default)]
struct Mailbox {
    queue: VecDeque<StoredEnvelope>,
    subscribers: Vec<Subscriber>,
}

#[derive(Clone)]
struct AppState {
    mailboxes: Arc<Mutex<HashMap<String, Mailbox>>>,
    cfg: Config,
    /// Monotonic counter for connection ids and envelope ids.
    counter: Arc<AtomicU64>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Whether `hex_str` decodes to exactly a 32-byte public key.
fn is_valid_address(hex_str: &str) -> bool {
    matches!(hex::decode(hex_str), Ok(bytes) if bytes.len() == PUBKEY_LEN)
}

// ---------------------------------------------------------------------------
// Connection handling
// ---------------------------------------------------------------------------

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: AppState) {
    let conn_id = state.counter.fetch_add(1, Ordering::Relaxed);
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<ServerMsg>();

    // Single writer task: everything outbound (live envelopes + replies) flows
    // through `tx` so we never write to the socket from two places.
    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let Ok(text) = serde_json::to_string(&msg) else {
                continue;
            };
            if ws_tx.send(Message::Text(text)).await.is_err() {
                break;
            }
        }
    });

    // Per-connection auth state.
    let mut pending_challenge: Option<(String, Vec<u8>)> = None; // (mailbox, nonce)
    let mut authed_mailbox: Option<String> = None;

    while let Some(Ok(msg)) = ws_rx.next().await {
        let text = match msg {
            Message::Text(t) => t,
            Message::Close(_) => break,
            _ => continue, // ignore binary/ping/pong
        };

        let Ok(cmsg) = serde_json::from_str::<ClientMsg>(&text) else {
            let _ = tx.send(ServerMsg::Error {
                message: "malformed message".into(),
            });
            continue;
        };

        match cmsg {
            ClientMsg::Publish {
                recipient,
                ciphertext,
            } => {
                publish(&state, &tx, recipient, ciphertext);
            }
            ClientMsg::Subscribe { mailbox } => {
                if !is_valid_address(&mailbox) {
                    let _ = tx.send(ServerMsg::Error {
                        message: "invalid mailbox".into(),
                    });
                    continue;
                }
                let mut nonce = vec![0u8; 32];
                rand::thread_rng().fill_bytes(&mut nonce);
                let _ = tx.send(ServerMsg::Challenge {
                    nonce: B64.encode(&nonce),
                });
                pending_challenge = Some((mailbox, nonce));
            }
            ClientMsg::Auth { signature } => {
                let Some((mailbox, nonce)) = pending_challenge.take() else {
                    let _ = tx.send(ServerMsg::Error {
                        message: "subscribe first".into(),
                    });
                    continue;
                };
                if verify_ownership(&mailbox, &nonce, &signature) {
                    // Register before flushing so a publish racing this auth is
                    // delivered live rather than missed (at-least-once; clients
                    // dedup at the mesh layer).
                    register_subscriber(&state, &mailbox, conn_id, tx.clone());
                    authed_mailbox = Some(mailbox.clone());
                    let _ = tx.send(ServerMsg::Ok {
                        detail: "authenticated".into(),
                    });
                    flush_queue(&state, &mailbox, &tx);
                } else {
                    let _ = tx.send(ServerMsg::Error {
                        message: "authentication failed".into(),
                    });
                }
            }
            ClientMsg::Ack { id } => {
                if let Some(mailbox) = &authed_mailbox {
                    ack(&state, mailbox, &id);
                } else {
                    let _ = tx.send(ServerMsg::Error {
                        message: "not authenticated".into(),
                    });
                }
            }
        }
    }

    if let Some(mailbox) = authed_mailbox {
        remove_subscriber(&state, &mailbox, conn_id);
    }
    writer.abort();
}

// ---------------------------------------------------------------------------
// Mailbox operations
// ---------------------------------------------------------------------------

fn publish(
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
    let mailbox = mailboxes.entry(recipient).or_default();
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

    let _ = tx.send(ServerMsg::Published { id });
}

fn register_subscriber(
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

fn flush_queue(state: &AppState, mailbox: &str, tx: &mpsc::UnboundedSender<ServerMsg>) {
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

fn ack(state: &AppState, mailbox: &str, id: &str) {
    let mut mailboxes = state.mailboxes.lock().unwrap();
    if let Some(entry) = mailboxes.get_mut(mailbox) {
        entry.queue.retain(|e| e.id != id);
    }
}

fn remove_subscriber(state: &AppState, mailbox: &str, conn_id: u64) {
    let mut mailboxes = state.mailboxes.lock().unwrap();
    if let Some(entry) = mailboxes.get_mut(mailbox) {
        entry.subscribers.retain(|s| s.conn_id != conn_id);
    }
}

/// Verifies that whoever sent `signature` holds the private key for `mailbox`,
/// by checking an Ed25519 signature over the challenge `nonce`. The relay only
/// ever learns public keys (which are the addresses anyway).
fn verify_ownership(mailbox_hex: &str, nonce: &[u8], signature_b64: &str) -> bool {
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

// ---------------------------------------------------------------------------
// Maintenance + entrypoint
// ---------------------------------------------------------------------------

/// Periodically expires old envelopes and reclaims empty mailboxes, bounding
/// memory without any persistence (envelopes are ephemeral by design).
async fn expiry_loop(state: AppState) {
    let mut ticker = tokio::time::interval(Duration::from_secs(60));
    loop {
        ticker.tick().await;
        expire_mailboxes(&state, now().saturating_sub(state.cfg.ttl_secs));
    }
}

/// Drops envelopes older than `cutoff` and reclaims mailboxes with no queue and
/// no live subscribers. Bounds memory; envelopes are ephemeral by design.
fn expire_mailboxes(state: &AppState, cutoff: u64) {
    let mut mailboxes = state.mailboxes.lock().unwrap();
    mailboxes.retain(|_, mailbox| {
        mailbox.queue.retain(|e| e.ts >= cutoff);
        !(mailbox.queue.is_empty() && mailbox.subscribers.is_empty())
    });
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[tokio::main]
async fn main() {
    let addr = std::env::var("PIGEON_RELAY_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let cfg = Config {
        ttl_secs: env_u64("PIGEON_RELAY_TTL_SECS", 7 * 24 * 3600),
        max_queue: env_u64("PIGEON_RELAY_MAX_QUEUE", 1000) as usize,
    };
    let state = AppState {
        mailboxes: Arc::new(Mutex::new(HashMap::new())),
        cfg,
        counter: Arc::new(AtomicU64::new(1)),
    };

    tokio::spawn(expiry_loop(state.clone()));

    let app = Router::new()
        .route(
            "/",
            get(|| async { "pigeon-relay: blind ciphertext mailbox\n" }),
        )
        .route("/healthz", get(|| async { "ok" }))
        .route("/ws", get(ws_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));
    // Intentionally the only startup log; we never log addresses or content.
    eprintln!("pigeon-relay listening on {addr}");
    axum::serve(listener, app).await.expect("server error");
}

#[cfg(test)]
mod tests;
