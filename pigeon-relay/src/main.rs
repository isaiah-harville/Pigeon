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
//!
//! Layout: [`protocol`] (wire frames), [`state`] (mailbox map + config),
//! [`mailbox`] (deposit/ack/expiry operations), [`connection`] (the per-socket
//! loop), and [`push`] (the opt-in APNs wake-up gateway, official relay only).

use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::routing::get;
use axum::Router;

mod connection;
mod coordinator_store;
mod group_connection;
mod group_protocol;
mod group_store;
mod mailbox;
mod protocol;
mod push;
mod state;

use coordinator_store::{CoordinatorConfig, CoordinatorStore};
use group_store::{GroupStore, GroupStoreConfig};
use push::PushRegistry;
use state::{now, AppState, Config, Store};

/// Periodically expires old envelopes and reclaims empty mailboxes, bounding
/// memory without any persistence (envelopes are ephemeral by design).
async fn expiry_loop(state: AppState) {
    let mut ticker = tokio::time::interval(Duration::from_secs(60));
    loop {
        ticker.tick().await;
        mailbox::expire_mailboxes(&state, now().saturating_sub(state.cfg.ttl_secs));
        state.groups.lock().unwrap().expire_at(now());
        state.coordinator.lock().unwrap().expire_at(now());
    }
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn coordinator_signer() -> ed25519_dalek::SigningKey {
    if let Ok(encoded) = std::env::var("PIGEON_COORDINATOR_SIGNING_SEED_HEX") {
        let bytes = hex::decode(encoded).expect("invalid coordinator signing seed");
        let seed: [u8; 32] = bytes
            .try_into()
            .expect("invalid coordinator signing seed length");
        return ed25519_dalek::SigningKey::from_bytes(&seed);
    }
    #[cfg(not(debug_assertions))]
    panic!("PIGEON_COORDINATOR_SIGNING_SEED_HEX is required in release builds");

    #[cfg(debug_assertions)]
    {
        // Development-only ephemeral key. Release deployments must pin a stable
        // seed so clients do not observe an unexplained coordinator identity reset.
        let mut seed = [0_u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
        ed25519_dalek::SigningKey::from_bytes(&seed)
    }
}

#[tokio::main]
async fn main() {
    let addr = std::env::var("PIGEON_RELAY_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let cfg = Config {
        ttl_secs: env_u64("PIGEON_RELAY_TTL_SECS", 30 * 24 * 3600),
        max_queue: env_u64("PIGEON_RELAY_MAX_QUEUE", 1000) as usize,
        max_mailboxes: env_u64("PIGEON_RELAY_MAX_MAILBOXES", 10_000) as usize,
        max_total_bytes: env_u64("PIGEON_RELAY_MAX_TOTAL_BYTES", 512 * 1024 * 1024) as usize,
    };

    // Opt-in APNs wake-up gateway. Configured only on the official deployment;
    // everywhere else this is `None` and the relay simply doesn't push.
    let gateway = push::ApnsGateway::from_env();
    match &gateway {
        Some(_) => eprintln!("pigeon-relay: push gateway enabled"),
        None => eprintln!("pigeon-relay: push gateway disabled (no APNS config)"),
    }
    let push_min_interval = Duration::from_secs(env_u64("PIGEON_APNS_MIN_INTERVAL_SECS", 30));
    let push = Arc::new(PushRegistry::new(gateway, push_min_interval));
    let coordinator_signer = coordinator_signer();

    let state = AppState {
        mailboxes: Arc::new(Mutex::new(Store::default())),
        cfg,
        counter: Arc::new(AtomicU64::new(1)),
        push,
        groups: Arc::new(Mutex::new(GroupStore::bounded(GroupStoreConfig {
            ttl_secs: env_u64("PIGEON_GROUP_TTL_SECS", 30 * 24 * 3600),
            max_groups: env_u64("PIGEON_GROUP_MAX_GROUPS", 10_000) as usize,
            max_capabilities_per_group: env_u64("PIGEON_GROUP_MAX_CAPABILITIES", 128) as usize,
            max_entry_bytes: env_u64("PIGEON_GROUP_MAX_ENTRY_BYTES", 1024 * 1024) as usize,
            max_entries_per_group: env_u64("PIGEON_GROUP_MAX_ENTRIES", 10_000) as usize,
            max_total_bytes: env_u64("PIGEON_GROUP_MAX_TOTAL_BYTES", 512 * 1024 * 1024) as usize,
            max_fetch_batch_bytes: env_u64("PIGEON_GROUP_MAX_FETCH_BYTES", 4 * 1024 * 1024)
                as usize,
        }))),
        group_subscribers: Arc::new(Mutex::new(std::collections::HashMap::new())),
        coordinator: Arc::new(Mutex::new(CoordinatorStore::new(
            CoordinatorConfig {
                max_candidates_per_epoch: env_u64("PIGEON_COORDINATOR_MAX_PER_EPOCH", 256) as usize,
                max_candidate_bytes: env_u64("PIGEON_COORDINATOR_MAX_CANDIDATE_BYTES", 1024 * 1024)
                    as usize,
                max_total_bytes: env_u64("PIGEON_COORDINATOR_MAX_TOTAL_BYTES", 256 * 1024 * 1024)
                    as usize,
                max_fetch_batch_bytes: env_u64(
                    "PIGEON_COORDINATOR_MAX_FETCH_BYTES",
                    4 * 1024 * 1024,
                ) as usize,
                ttl_secs: env_u64("PIGEON_COORDINATOR_TTL_SECS", 30 * 24 * 3600),
            },
            coordinator_signer,
        ))),
    };

    tokio::spawn(expiry_loop(state.clone()));

    let app = Router::new()
        .route(
            "/",
            get(|| async { "pigeon-relay: blind ciphertext mailbox\n" }),
        )
        .route("/healthz", get(|| async { "ok" }))
        .route("/ws", get(connection::ws_handler))
        .route("/group/ws", get(group_connection::ws_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));
    // Intentionally the only startup log; we never log addresses or content.
    eprintln!("pigeon-relay listening");
    axum::serve(listener, app).await.expect("server error");
}

#[cfg(test)]
mod coordinator_tests;
#[cfg(test)]
mod group_tests;
#[cfg(test)]
mod tests;
