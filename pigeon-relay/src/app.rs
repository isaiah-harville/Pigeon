// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! Application composition for the relay's independent ciphertext services.

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::routing::get;
use axum::Router;

use crate::clock::now;
use crate::config::RelayConfig;
use crate::coordinator_store::CoordinatorStore;
use crate::group_store::GroupStore;
use crate::push::{ApnsGateway, PushRegistry};
use crate::state::{AppState, Store};
use crate::{connection, group_connection, mailbox};

pub fn build_state(config: RelayConfig) -> AppState {
    let gateway = ApnsGateway::from_env();
    match &gateway {
        Some(_) => eprintln!("pigeon-relay: push gateway enabled"),
        None => eprintln!("pigeon-relay: push gateway disabled (no APNS config)"),
    }

    AppState {
        mailboxes: Arc::new(Mutex::new(Store::default())),
        cfg: config.mailbox,
        counter: Arc::new(AtomicU64::new(1)),
        push: Arc::new(PushRegistry::new(gateway, config.apns_min_interval)),
        groups: Arc::new(Mutex::new(GroupStore::bounded(config.group))),
        group_subscribers: Arc::new(Mutex::new(HashMap::new())),
        coordinator: Arc::new(Mutex::new(CoordinatorStore::new(
            config.coordinator,
            coordinator_signer(config.coordinator_signing_seed),
        ))),
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/",
            get(|| async { "pigeon-relay: blind ciphertext mailbox\n" }),
        )
        .route("/healthz", get(|| async { "ok" }))
        .route("/ws", get(connection::ws_handler))
        .route("/group/ws", get(group_connection::ws_handler))
        .with_state(state)
}

/// Periodically reclaims expired ciphertext independently in each service.
pub async fn expiry_loop(state: AppState) {
    let mut ticker = tokio::time::interval(Duration::from_secs(60));
    loop {
        ticker.tick().await;
        let current_time = now();
        mailbox::expire_mailboxes(&state, current_time.saturating_sub(state.cfg.ttl_secs));
        state.groups.lock().unwrap().expire_at(current_time);
        state.coordinator.lock().unwrap().expire_at(current_time);
    }
}

fn coordinator_signer(seed: Option<[u8; 32]>) -> ed25519_dalek::SigningKey {
    if let Some(seed) = seed {
        return ed25519_dalek::SigningKey::from_bytes(&seed);
    }
    #[cfg(not(debug_assertions))]
    panic!("PIGEON_COORDINATOR_SIGNING_SEED_HEX is required in release builds");

    #[cfg(debug_assertions)]
    {
        // Development-only ephemeral key. Release deployments pin a stable
        // seed so clients never observe an unexplained coordinator reset.
        use rand::RngCore;

        let mut seed = [0_u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        ed25519_dalek::SigningKey::from_bytes(&seed)
    }
}
