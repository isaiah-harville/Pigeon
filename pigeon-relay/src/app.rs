// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! Application composition for the relay's independent ciphertext services.

use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use axum::routing::get;
use axum::Router;

use crate::clock::now;
use crate::config::RelayConfig;
use crate::push::{ApnsGateway, PushRegistry};
use crate::{coordinator, group, mailbox};

pub const SUBSCRIBER_CHANNEL_CAPACITY: usize = 256;

#[derive(Clone)]
pub struct AppState {
    pub(crate) mailbox: mailbox::Service,
    pub(crate) group: group::Service,
    pub(crate) coordinator: coordinator::Service,
    pub(crate) push: Arc<PushRegistry>,
    pub(crate) connection_ids: Arc<AtomicU64>,
}

pub fn build_state(config: RelayConfig) -> AppState {
    let gateway = ApnsGateway::from_env();
    match &gateway {
        Some(_) => eprintln!("pigeon-relay: push gateway enabled"),
        None => eprintln!("pigeon-relay: push gateway disabled (no APNS config)"),
    }

    AppState {
        mailbox: mailbox::Service::new(config.mailbox),
        group: group::Service::new(config.group),
        coordinator: coordinator::Service::new(
            config.coordinator,
            coordinator_signer(config.coordinator_signing_seed),
        ),
        push: Arc::new(PushRegistry::new(gateway, config.apns_min_interval)),
        connection_ids: Arc::new(AtomicU64::new(1)),
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/",
            get(|| async { "pigeon-relay: blind ciphertext mailbox\n" }),
        )
        .route("/healthz", get(|| async { "ok" }))
        .route("/ws", get(mailbox::connection::ws_handler))
        .route("/group/ws", get(group::connection::ws_handler))
        .with_state(state)
}

/// Periodically reclaims expired ciphertext independently in each service.
pub async fn expiry_loop(state: AppState) {
    let mut ticker = tokio::time::interval(Duration::from_secs(60));
    loop {
        ticker.tick().await;
        let current_time = now();
        state
            .mailbox
            .expire(current_time.saturating_sub(state.mailbox.config.ttl_secs));
        state.group.expire(current_time);
        state.coordinator.expire(current_time);
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use super::*;
    use crate::config::RelayConfig;

    fn test_config() -> RelayConfig {
        RelayConfig {
            bind_addr: "127.0.0.1:0".into(),
            mailbox: mailbox::store::Config {
                ttl_secs: 60,
                max_queue: 8,
                max_mailboxes: 8,
                max_total_bytes: 1024,
            },
            group: group::store::Config {
                ttl_secs: 60,
                max_groups: 8,
                max_capabilities_per_group: 128,
                max_entry_bytes: 256,
                max_entries_per_group: 8,
                max_total_bytes: 1024,
                max_fetch_batch_bytes: 512,
            },
            coordinator: coordinator::store::Config {
                max_candidates_per_epoch: 8,
                max_candidate_bytes: 256,
                max_total_bytes: 1024,
                max_fetch_batch_bytes: 512,
                ttl_secs: 60,
            },
            apns_min_interval: Duration::from_secs(30),
            coordinator_signing_seed: Some([7; 32]),
        }
    }

    #[tokio::test]
    async fn router_preserves_public_routes() {
        let app = router(build_state(test_config()));
        let health = app
            .clone()
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let mailbox = app
            .clone()
            .oneshot(Request::get("/ws").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let group = app
            .oneshot(Request::get("/group/ws").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(health.status(), StatusCode::OK);
        assert_ne!(mailbox.status(), StatusCode::NOT_FOUND);
        assert_ne!(group.status(), StatusCode::NOT_FOUND);
    }
}
