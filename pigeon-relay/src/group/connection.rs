// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! Per-socket handling for the isolated opaque group-message service.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRef, State};
use axum::response::IntoResponse;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use tokio::sync::mpsc;

use super::protocol::{
    decode_capability, decode_group_capability, decode_public_key, gate_group_message,
    verify_challenge, verify_registration, GroupClientMsg, GroupEntryWire, GroupProtocolGate,
    GroupServerMsg, MAX_GROUP_FRAME_BYTES,
};
use super::store::GroupCapability;
use super::{Service, Subscriber};
use crate::app::{AppState, SUBSCRIBER_CHANNEL_CAPACITY};
use crate::clock::now;
use crate::coordinator::{self, protocol::CandidateWire};
use crate::push::{self, PushRegistry};

#[derive(Clone)]
pub struct ConnectionState {
    service: Service,
    coordinator: coordinator::Service,
    push: Arc<PushRegistry>,
    connection_ids: Arc<AtomicU64>,
}

impl FromRef<AppState> for ConnectionState {
    fn from_ref(state: &AppState) -> Self {
        Self {
            service: state.group.clone(),
            coordinator: state.coordinator.clone(),
            push: state.push.clone(),
            connection_ids: state.connection_ids.clone(),
        }
    }
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<ConnectionState>,
) -> impl IntoResponse {
    ws.max_message_size(MAX_GROUP_FRAME_BYTES)
        .on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: ConnectionState) {
    let connection_id = state.connection_ids.fetch_add(1, Ordering::Relaxed);
    let (mut socket_tx, mut socket_rx) = socket.split();
    let (tx, mut rx) = mpsc::channel::<GroupServerMsg>(SUBSCRIBER_CHANNEL_CAPACITY);
    let writer = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            let Ok(text) = serde_json::to_string(&message) else {
                continue;
            };
            if socket_tx.send(Message::Text(text)).await.is_err() {
                break;
            }
        }
    });
    let mut negotiated = false;
    let mut pending: Option<(GroupCapability, [u8; 32])> = None;
    let mut authenticated: Option<GroupCapability> = None;

    while let Some(Ok(message)) = socket_rx.next().await {
        let Message::Text(text) = message else {
            if matches!(message, Message::Close(_)) {
                break;
            }
            continue;
        };
        let Ok(message) = serde_json::from_str::<GroupClientMsg>(&text) else {
            reply(&tx, malformed_error());
            continue;
        };
        let message = match gate_group_message(message, &mut negotiated) {
            GroupProtocolGate::Reply(response) => {
                reply(&tx, response);
                continue;
            }
            GroupProtocolGate::Proceed(message) => message,
        };
        match message {
            GroupClientMsg::Register {
                coordination_id,
                capabilities,
                signature,
            } => {
                let result = verify_registration(&coordination_id, &capabilities, &signature)
                    .and_then(|registration| {
                        state.service.store.lock().unwrap().register(registration)
                    });
                reply(
                    &tx,
                    if result.is_ok() {
                        GroupServerMsg::Registered
                    } else {
                        generic_error()
                    },
                );
            }
            GroupClientMsg::Authenticate {
                coordination_id,
                capability_key,
            } => {
                let capability = decode_group_capability(&coordination_id, &capability_key);
                let authorized = capability.as_ref().is_ok_and(|capability| {
                    state
                        .service
                        .store
                        .lock()
                        .unwrap()
                        .is_authorized(capability)
                });
                if !authorized {
                    reply(&tx, generic_error());
                    continue;
                }
                let mut nonce = [0_u8; 32];
                rand::thread_rng().fill_bytes(&mut nonce);
                pending = capability.ok().map(|capability| (capability, nonce));
                reply(
                    &tx,
                    GroupServerMsg::Challenge {
                        nonce: B64.encode(nonce),
                    },
                );
            }
            GroupClientMsg::Auth { signature } => {
                let Some((capability, nonce)) = pending.take() else {
                    reply(&tx, generic_error());
                    continue;
                };
                if !verify_challenge(&capability, &nonce, &signature) {
                    reply(&tx, generic_error());
                    continue;
                }
                remove_subscriber(&state, authenticated.as_ref(), connection_id);
                if state.service.store.lock().unwrap().can_read(&capability) {
                    state
                        .service
                        .subscribers
                        .lock()
                        .unwrap()
                        .entry(capability.coordination_id)
                        .or_default()
                        .push(Subscriber {
                            connection_id,
                            tx: tx.clone(),
                        });
                }
                authenticated = Some(capability);
                reply(&tx, GroupServerMsg::Ok);
            }
            GroupClientMsg::Append { ciphertext } => {
                let Some(capability) = authenticated.as_ref() else {
                    reply(&tx, generic_error());
                    continue;
                };
                let result = B64
                    .decode(ciphertext)
                    .map_err(|_| ())
                    .and_then(|ciphertext| {
                        state
                            .service
                            .store
                            .lock()
                            .unwrap()
                            .append(capability, ciphertext, now())
                            .map_err(|_| ())
                    });
                match result {
                    Ok(receipt) => {
                        wake_readers(&state, capability.coordination_id);
                        for reader_key in state
                            .service
                            .store
                            .lock()
                            .unwrap()
                            .reader_keys(&capability.coordination_id)
                        {
                            push::notify_deposit(
                                state.push.clone(),
                                push_scope(capability.coordination_id, reader_key),
                            );
                        }
                        reply(
                            &tx,
                            GroupServerMsg::Appended {
                                sequence: receipt.sequence,
                            },
                        );
                    }
                    Err(()) => reply(&tx, generic_error()),
                }
            }
            GroupClientMsg::Fetch { after_cursor } => {
                let Some(capability) = authenticated.as_ref() else {
                    reply(&tx, generic_error());
                    continue;
                };
                let response = match state
                    .service
                    .store
                    .lock()
                    .unwrap()
                    .fetch(capability, after_cursor)
                {
                    Ok(entries) => GroupServerMsg::Entries {
                        entries: entries
                            .into_iter()
                            .map(|entry| GroupEntryWire {
                                sequence: entry.sequence,
                                ciphertext: B64.encode(entry.ciphertext),
                                timestamp: entry.timestamp,
                            })
                            .collect(),
                    },
                    Err(_) => generic_error(),
                };
                reply(&tx, response);
            }
            GroupClientMsg::Advance { sequence } => {
                let result = authenticated.as_ref().map_or(Err(()), |capability| {
                    state
                        .service
                        .store
                        .lock()
                        .unwrap()
                        .advance(capability, sequence)
                        .map_err(|_| ())
                });
                reply(&tx, ok_or_error(result));
            }
            GroupClientMsg::Rotate {
                old_public_key,
                replacement,
            } => {
                let result = authenticated.as_ref().map_or(Err(()), |controller| {
                    let old = decode_public_key(&old_public_key).map_err(|_| ())?;
                    let replacement = decode_capability(&replacement).map_err(|_| ())?;
                    state
                        .service
                        .store
                        .lock()
                        .unwrap()
                        .rotate_capability(controller, old, replacement)
                        .map_err(|_| ())
                });
                reply(&tx, ok_or_error(result));
            }
            GroupClientMsg::Revoke { public_key } => {
                let result = authenticated.as_ref().map_or(Err(()), |controller| {
                    let key = decode_public_key(&public_key).map_err(|_| ())?;
                    state
                        .service
                        .store
                        .lock()
                        .unwrap()
                        .revoke_capability(controller, key)
                        .map_err(|_| ())
                });
                reply(&tx, ok_or_error(result));
            }
            GroupClientMsg::RegisterPush { token } => {
                let result = authenticated.as_ref().is_some_and(|capability| {
                    state.service.store.lock().unwrap().can_read(capability)
                        && state.push.enabled()
                        && push::is_valid_token(&token)
                        && state.push.register(
                            &push_scope(capability.coordination_id, capability.public_key),
                            token,
                        )
                });
                reply(
                    &tx,
                    if result {
                        GroupServerMsg::Ok
                    } else {
                        generic_error()
                    },
                );
            }
            GroupClientMsg::UnregisterPush { token } => {
                if let Some(capability) = authenticated.as_ref() {
                    state.push.unregister(
                        &push_scope(capability.coordination_id, capability.public_key),
                        &token,
                    );
                    reply(&tx, GroupServerMsg::Ok);
                } else {
                    reply(&tx, generic_error());
                }
            }
            GroupClientMsg::CoordinatorKey => {
                let public_key = state.coordinator.store.lock().unwrap().verifying_key();
                reply(
                    &tx,
                    GroupServerMsg::CoordinatorKey {
                        public_key: hex::encode(public_key.to_bytes()),
                    },
                );
            }
            GroupClientMsg::CoordinatorSubmit {
                claimed_base_epoch,
                candidate,
            } => {
                let Some(capability) = authenticated.as_ref() else {
                    reply(&tx, generic_error());
                    continue;
                };
                if !state.service.store.lock().unwrap().can_append(capability) {
                    reply(&tx, generic_error());
                    continue;
                }
                let result = B64.decode(candidate).map_err(|_| ()).and_then(|candidate| {
                    state
                        .coordinator
                        .store
                        .lock()
                        .unwrap()
                        .submit(
                            capability.coordination_id,
                            claimed_base_epoch,
                            candidate,
                            now(),
                        )
                        .map_err(|_| ())
                });
                match result {
                    Ok(receipt) => {
                        wake_readers(&state, capability.coordination_id);
                        reply(
                            &tx,
                            GroupServerMsg::CoordinatorReceipt {
                                receipt: receipt.into(),
                            },
                        );
                    }
                    Err(()) => reply(&tx, generic_error()),
                }
            }
            GroupClientMsg::CoordinatorFetch { after_sequence } => {
                let Some(capability) = authenticated.as_ref() else {
                    reply(&tx, generic_error());
                    continue;
                };
                if !state.service.store.lock().unwrap().can_read(capability) {
                    reply(&tx, generic_error());
                    continue;
                }
                let candidates = state
                    .coordinator
                    .store
                    .lock()
                    .unwrap()
                    .fetch(capability.coordination_id, after_sequence)
                    .into_iter()
                    .map(CandidateWire::from)
                    .collect();
                reply(&tx, GroupServerMsg::CoordinatorCandidates { candidates });
            }
            GroupClientMsg::Hello { .. } => unreachable!("hello handled by protocol gate"),
        }
    }
    remove_subscriber(&state, authenticated.as_ref(), connection_id);
    writer.abort();
}

fn reply(tx: &mpsc::Sender<GroupServerMsg>, message: GroupServerMsg) {
    let _ = tx.try_send(message);
}

fn wake_readers(state: &ConnectionState, coordination_id: [u8; 32]) {
    if let Some(subscribers) = state
        .service
        .subscribers
        .lock()
        .unwrap()
        .get_mut(&coordination_id)
    {
        subscribers.retain(|subscriber| {
            subscriber.tx.try_send(GroupServerMsg::Wake).is_ok() || !subscriber.tx.is_closed()
        });
    }
}

fn remove_subscriber(
    state: &ConnectionState,
    capability: Option<&GroupCapability>,
    connection_id: u64,
) {
    let Some(capability) = capability else {
        return;
    };
    let mut groups = state.service.subscribers.lock().unwrap();
    if let Some(subscribers) = groups.get_mut(&capability.coordination_id) {
        subscribers.retain(|subscriber| subscriber.connection_id != connection_id);
        if subscribers.is_empty() {
            groups.remove(&capability.coordination_id);
        }
    }
}

fn ok_or_error(result: Result<(), ()>) -> GroupServerMsg {
    if result.is_ok() {
        GroupServerMsg::Ok
    } else {
        generic_error()
    }
}

fn malformed_error() -> GroupServerMsg {
    GroupServerMsg::Error {
        message: "malformed message".into(),
    }
}

fn generic_error() -> GroupServerMsg {
    GroupServerMsg::Error {
        message: "group operation rejected".into(),
    }
}

fn push_scope(coordination_id: [u8; 32], capability_key: [u8; 32]) -> String {
    let mut scope = String::with_capacity(6 + 128);
    scope.push_str("group:");
    scope.push_str(&hex::encode(coordination_id));
    scope.push_str(&hex::encode(capability_key));
    scope
}
