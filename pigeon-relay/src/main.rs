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
mod coordinator;
mod durable;
mod group;
mod invite;
mod mailbox;
mod push;

#[cfg(test)]
mod live_group_socket_tests;

#[tokio::main]
async fn main() {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments
        .get(1)
        .is_some_and(|argument| argument == "reclaim-empty-group")
    {
        if arguments.len() != 4 {
            panic!("usage: pigeon-relay reclaim-empty-group <state-dir> <coordination-id-hex>");
        }
        let id: [u8; 32] = hex::decode(&arguments[3])
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .expect("coordination ID must be 32 hex-encoded bytes");
        match durable::reclaim_empty_group(std::path::Path::new(&arguments[2]), &id) {
            Ok(true) => eprintln!("empty group registration reclaimed"),
            Ok(false) => {
                eprintln!("group missing or contains ciphertext/coordinator candidates");
                std::process::exit(2);
            }
            Err(error) => panic!("reclamation failed: {error}"),
        }
        return;
    }
    if arguments.len() != 1 {
        panic!("unknown relay command");
    }
    let config = config::RelayConfig::from_env()
        .unwrap_or_else(|error| panic!("failed to load relay configuration: {error}"));
    let addr = config.bind_addr.clone();
    let state = app::build_state(config)
        .unwrap_or_else(|error| panic!("failed to load durable relay state: {error}"));
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
