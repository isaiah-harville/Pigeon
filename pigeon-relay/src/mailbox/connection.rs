// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! The mailbox WebSocket loop: parses client frames, runs the
//! subscribe→challenge→auth ownership handshake, and dispatches to the mailbox
//! operations in [`crate::mailbox`]. A single writer task owns the outbound side
//! so the socket is never written from two places.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, FromRef, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use tokio::sync::mpsc;
use tokio::sync::Semaphore;
use tokio::time::{timeout_at, Duration, Instant};

use super::protocol::{gate_protocol_message, ClientMsg, ProtocolGate, ServerMsg};
use super::store::is_valid_address;
use crate::app::{AppState, SUBSCRIBER_CHANNEL_CAPACITY};
use crate::invite;
use crate::mailbox::{
    ack, flush_queue, publish, register_push, remove_subscriber, switch_subscription,
    verify_ownership, Service,
};
use crate::push::PushRegistry;
use crate::socket_admission::{client_ip, SocketAdmission};

#[derive(Clone)]
pub struct ConnectionState {
    service: Service,
    push: Arc<PushRegistry>,
    message_ids: Arc<AtomicU64>,
    invite: invite::Service,
    socket_slots: Arc<Semaphore>,
    socket_admission: SocketAdmission,
    trusted_proxy_ip: Option<IpAddr>,
}

impl FromRef<AppState> for ConnectionState {
    fn from_ref(state: &AppState) -> Self {
        Self {
            service: state.mailbox.clone(),
            push: state.push.clone(),
            message_ids: state.connection_ids.clone(),
            invite: state.invite.clone(),
            socket_slots: state.socket_slots.clone(),
            socket_admission: state.socket_admission.clone(),
            trusted_proxy_ip: state.trusted_proxy_ip,
        }
    }
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<ConnectionState>,
    connection: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Ok(slot) = state.socket_slots.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let peer_ip = client_ip(
        connection.map_or(IpAddr::V4(Ipv4Addr::LOCALHOST), |value| value.0.ip()),
        &headers,
        state.trusted_proxy_ip,
    );
    let Some(ip_slot) = state.socket_admission.acquire(peer_ip) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    ws.max_message_size(512 * 1024)
        .on_upgrade(move |socket| async move {
            let _slot = slot;
            let _ip_slot = ip_slot;
            handle_socket(socket, state, peer_ip).await;
        })
        .into_response()
}

async fn handle_socket(socket: WebSocket, state: ConnectionState, peer_ip: IpAddr) {
    let conn_id = state.message_ids.fetch_add(1, Ordering::Relaxed);
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
    let mut pending_challenge: Option<(String, Vec<u8>, bool)> = None; // (mailbox, nonce, invite)
    let mut authed_mailbox: Option<String> = None;
    let mut authed_invite = false;
    let mut negotiated = false;
    let mut selected_version = 0;
    let handshake_deadline = Instant::now() + Duration::from_secs(60);

    loop {
        let next = if authed_mailbox.is_some() {
            ws_rx.next().await
        } else {
            match timeout_at(handshake_deadline, ws_rx.next()).await {
                Ok(message) => message,
                Err(_) => break,
            }
        };
        let Some(Ok(msg)) = next else {
            break;
        };
        let text = match msg {
            Message::Text(t) => t,
            Message::Close(_) => break,
            _ => continue, // ignore binary/ping/pong
        };

        let Ok(cmsg) = serde_json::from_str::<ClientMsg>(&text) else {
            let _ = tx.try_send(ServerMsg::Error {
                message: "malformed message".into(),
                request_id: None,
            });
            continue;
        };

        let cmsg = match gate_protocol_message(cmsg, &mut negotiated) {
            ProtocolGate::Reply(response) => {
                if let ServerMsg::Compatible {
                    protocol_version, ..
                } = &response
                {
                    selected_version = *protocol_version;
                }
                let _ = tx.try_send(response);
                continue;
            }
            ProtocolGate::Proceed(message) => message,
        };

        let is_invite_subscribe = matches!(&cmsg, ClientMsg::InviteSubscribe { .. });
        match cmsg {
            ClientMsg::Publish {
                recipient,
                ciphertext,
                request_id,
            } => {
                publish(
                    &state.service,
                    &state.message_ids,
                    &state.push,
                    &tx,
                    recipient,
                    ciphertext,
                    request_id,
                );
            }
            ClientMsg::InvitePublish {
                recipient,
                ciphertext,
                request_id,
            } => {
                if !state.socket_admission.admit_invite(peer_ip) {
                    let _ = tx.try_send(ServerMsg::Error {
                        message: "invite publish rate exceeded".into(),
                        request_id,
                    });
                    continue;
                }
                if selected_version < 3 {
                    let _ = tx.try_send(ServerMsg::Error {
                        message: "protocol version 3 required".into(),
                        request_id,
                    });
                    continue;
                }
                if request_id
                    .as_ref()
                    .is_some_and(|id| id.is_empty() || id.len() > 128 || !id.is_ascii())
                {
                    let _ = tx.try_send(ServerMsg::Error {
                        message: "invalid request id".into(),
                        request_id: None,
                    });
                    continue;
                }
                let Some(mailbox) = hex::decode(&recipient)
                    .ok()
                    .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                else {
                    let _ = tx.try_send(ServerMsg::Error {
                        message: "invalid recipient".into(),
                        request_id,
                    });
                    continue;
                };
                let result = state
                    .invite
                    .deposit(mailbox, ciphertext, crate::clock::now());
                match result {
                    Ok(id) => {
                        let _ = tx.try_send(ServerMsg::Published { id, request_id });
                    }
                    Err(invite::StoreError::AtCapacity) => {
                        let _ = tx.try_send(ServerMsg::Error {
                            message: "relay at capacity".into(),
                            request_id,
                        });
                    }
                    Err(invite::StoreError::InvalidCiphertext) => {
                        let _ = tx.try_send(ServerMsg::Error {
                            message: "invalid ciphertext".into(),
                            request_id,
                        });
                    }
                }
            }
            ClientMsg::Subscribe { mailbox } | ClientMsg::InviteSubscribe { mailbox } => {
                let is_invite = is_invite_subscribe;
                if is_invite && selected_version < 3 {
                    let _ = tx.try_send(ServerMsg::Error {
                        message: "protocol version 3 required".into(),
                        request_id: None,
                    });
                    continue;
                }
                if !is_valid_address(&mailbox) {
                    let _ = tx.try_send(ServerMsg::Error {
                        message: "invalid mailbox".into(),
                        request_id: None,
                    });
                    continue;
                }
                let mut nonce = vec![0u8; 32];
                rand::thread_rng().fill_bytes(&mut nonce);
                let _ = tx.try_send(ServerMsg::Challenge {
                    nonce: B64.encode(&nonce),
                });
                pending_challenge = Some((mailbox, nonce, is_invite));
            }
            ClientMsg::Auth { signature } => {
                let Some((mailbox, nonce, is_invite)) = pending_challenge.take() else {
                    let _ = tx.try_send(ServerMsg::Error {
                        message: "subscribe first".into(),
                        request_id: None,
                    });
                    continue;
                };
                if verify_ownership(&mailbox, &nonce, &signature) {
                    // Register before flushing so a publish racing this auth is
                    // delivered live rather than missed (at-least-once; clients
                    // dedup at the mesh layer). Re-authenticating to a different
                    // mailbox drops the previous registration, which the
                    // disconnect path (last mailbox only) would otherwise strand.
                    if is_invite {
                        let address: [u8; 32] = hex::decode(&mailbox).unwrap().try_into().unwrap();
                        if !state.invite.subscribe(address, conn_id, tx.clone()) {
                            let _ = tx.try_send(ServerMsg::Error {
                                message: "invite subscriber capacity".into(),
                                request_id: None,
                            });
                            continue;
                        }
                    }
                    if let Some(previous) = authed_mailbox.as_deref() {
                        if authed_invite && (!is_invite || previous != mailbox) {
                            let address: [u8; 32] =
                                hex::decode(previous).unwrap().try_into().unwrap();
                            state.invite.unsubscribe(address, conn_id);
                        } else if is_invite {
                            remove_subscriber(&state.service, previous, conn_id);
                        }
                    }
                    if !is_invite {
                        switch_subscription(
                            &state.service,
                            (!authed_invite)
                                .then_some(authed_mailbox.as_deref())
                                .flatten(),
                            &mailbox,
                            conn_id,
                            tx.clone(),
                        );
                    }
                    authed_mailbox = Some(mailbox.clone());
                    authed_invite = is_invite;
                    if !is_invite {
                        let _ = tx.try_send(ServerMsg::Ok {
                            detail: "authenticated".into(),
                        });
                        flush_queue(&state.service, &mailbox, &tx);
                    }
                } else {
                    let _ = tx.try_send(ServerMsg::Error {
                        message: "authentication failed".into(),
                        request_id: None,
                    });
                }
            }
            ClientMsg::Ack { id } => {
                if let Some(mailbox) = &authed_mailbox {
                    if authed_invite {
                        let address: [u8; 32] = hex::decode(mailbox).unwrap().try_into().unwrap();
                        state.invite.ack(address, &id).unwrap();
                    } else {
                        ack(&state.service, mailbox, &id);
                    }
                } else {
                    let _ = tx.try_send(ServerMsg::Error {
                        message: "not authenticated".into(),
                        request_id: None,
                    });
                }
            }
            ClientMsg::RegisterPush { token } => {
                register_push(
                    &state.push,
                    &tx,
                    authed_mailbox.as_deref(),
                    authed_invite,
                    token,
                );
            }
            ClientMsg::UnregisterPush { token } => {
                if let Some(mailbox) = &authed_mailbox {
                    if authed_invite {
                        let _ = tx.try_send(ServerMsg::Error {
                            message: "invite push not supported".into(),
                            request_id: None,
                        });
                        continue;
                    }
                    state.push.unregister(mailbox, &token);
                    let _ = tx.try_send(ServerMsg::Ok {
                        detail: "push unregistered".into(),
                    });
                } else {
                    let _ = tx.try_send(ServerMsg::Error {
                        message: "not authenticated".into(),
                        request_id: None,
                    });
                }
            }
            ClientMsg::Hello { .. } => unreachable!("hello handled by protocol gate"),
        }
    }

    if let Some(mailbox) = authed_mailbox {
        if authed_invite {
            let address: [u8; 32] = hex::decode(&mailbox).unwrap().try_into().unwrap();
            state.invite.unsubscribe(address, conn_id);
        } else {
            remove_subscriber(&state.service, &mailbox, conn_id);
        }
    }
    writer.abort();
}
