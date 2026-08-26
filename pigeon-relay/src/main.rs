// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! Pigeon relay — a zero-knowledge, federated ciphertext rendezvous.
//!
//! Independent relays store opaque pairwise mailbox traffic, opaque ordered
//! group traffic, and opaque MLS coordination candidates. Clients retain all
//! confidentiality, authentication, integrity, and trust decisions. Relays do
//! not federate with one another and never log addresses or content.

mod app;
mod clock;
mod config;
mod connection;
mod coordinator_store;
mod group_connection;
mod group_protocol;
mod group_store;
mod mailbox;
mod protocol;
mod push;
mod state;

#[tokio::main]
async fn main() {
    let config = config::RelayConfig::from_env()
        .unwrap_or_else(|error| panic!("failed to load relay configuration: {error}"));
    let addr = config.bind_addr.clone();
    let state = app::build_state(config);
    tokio::spawn(app::expiry_loop(state.clone()));

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|error| panic!("failed to bind {addr}: {error}"));
    // Intentionally the only operational log; never log addresses or content.
    eprintln!("pigeon-relay listening");
    axum::serve(listener, app::router(state))
        .await
        .expect("server error");
}

#[cfg(test)]
mod coordinator_tests;
#[cfg(test)]
mod group_tests;
#[cfg(test)]
mod tests;
