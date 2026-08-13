// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! The per-connection WebSocket loop: parses client frames, runs the
//! subscribe→challenge→auth ownership handshake, and dispatches to the mailbox
//! operations in [`crate::mailbox`]. A single writer task owns the outbound side
//! so the socket is never written from two places.

use std::sync::atomic::Ordering;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use tokio::sync::mpsc;

use crate::mailbox::{
    ack, flush_queue, publish, register_push, remove_subscriber, switch_subscription,
    verify_ownership,
};
use crate::protocol::{gate_protocol_message, ClientMsg, ProtocolGate, ServerMsg};
use crate::state::{is_valid_address, AppState, SUBSCRIBER_CHANNEL_CAPACITY};

pub async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: AppState) {
    let conn_id = state.counter.fetch_add(1, Ordering::Relaxed);
    let (mut ws_tx, mut ws_rx) = socket.split();
    // Bounded: a client that stops draining loses its subscription rather than
    // making the relay buffer for it (see SUBSCRIBER_CHANNEL_CAPACITY).
    let (tx, mut rx) = mpsc::channel::<ServerMsg>(SUBSCRIBER_CHANNEL_CAPACITY);

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
    let mut negotiated = false;

    while let Some(Ok(msg)) = ws_rx.next().await {
        let text = match msg {
            Message::Text(t) => t,
            Message::Close(_) => break,
            _ => continue, // ignore binary/ping/pong
        };

        let Ok(cmsg) = serde_json::from_str::<ClientMsg>(&text) else {
            let _ = tx.try_send(ServerMsg::Error {
                message: "malformed message".into(),
            });
            continue;
        };

        let cmsg = match gate_protocol_message(cmsg, &mut negotiated) {
            ProtocolGate::Reply(response) => {
                let _ = tx.try_send(response);
                continue;
            }
            ProtocolGate::Proceed(message) => message,
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
                    let _ = tx.try_send(ServerMsg::Error {
                        message: "invalid mailbox".into(),
                    });
                    continue;
                }
                let mut nonce = vec![0u8; 32];
                rand::thread_rng().fill_bytes(&mut nonce);
                let _ = tx.try_send(ServerMsg::Challenge {
                    nonce: B64.encode(&nonce),
                });
                pending_challenge = Some((mailbox, nonce));
            }
            ClientMsg::Auth { signature } => {
                let Some((mailbox, nonce)) = pending_challenge.take() else {
                    let _ = tx.try_send(ServerMsg::Error {
                        message: "subscribe first".into(),
                    });
                    continue;
                };
                if verify_ownership(&mailbox, &nonce, &signature) {
                    // Register before flushing so a publish racing this auth is
                    // delivered live rather than missed (at-least-once; clients
                    // dedup at the mesh layer). Re-authenticating to a different
                    // mailbox drops the previous registration, which the
                    // disconnect path (last mailbox only) would otherwise strand.
                    switch_subscription(
                        &state,
                        authed_mailbox.as_deref(),
                        &mailbox,
                        conn_id,
                        tx.clone(),
                    );
                    authed_mailbox = Some(mailbox.clone());
                    let _ = tx.try_send(ServerMsg::Ok {
                        detail: "authenticated".into(),
                    });
                    flush_queue(&state, &mailbox, &tx);
                } else {
                    let _ = tx.try_send(ServerMsg::Error {
                        message: "authentication failed".into(),
                    });
                }
            }
            ClientMsg::Ack { id } => {
                if let Some(mailbox) = &authed_mailbox {
                    ack(&state, mailbox, &id);
                } else {
                    let _ = tx.try_send(ServerMsg::Error {
                        message: "not authenticated".into(),
                    });
                }
            }
            ClientMsg::RegisterPush { token } => {
                register_push(&state, &tx, authed_mailbox.as_deref(), token);
            }
            ClientMsg::UnregisterPush { token } => {
                if let Some(mailbox) = &authed_mailbox {
                    state.push.unregister(mailbox, &token);
                    let _ = tx.try_send(ServerMsg::Ok {
                        detail: "push unregistered".into(),
                    });
                } else {
                    let _ = tx.try_send(ServerMsg::Error {
                        message: "not authenticated".into(),
                    });
                }
            }
            ClientMsg::Hello { .. } => unreachable!("hello handled by protocol gate"),
        }
    }

    if let Some(mailbox) = authed_mailbox {
        remove_subscriber(&state, &mailbox, conn_id);
    }
    writer.abort();
}
