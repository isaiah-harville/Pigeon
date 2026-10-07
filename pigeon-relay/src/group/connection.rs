// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! Per-socket handling for the isolated opaque group-message service.

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
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio::sync::Semaphore;
use tokio::time::{timeout_at, Duration, Instant};

use super::protocol::{
    decode_capability, decode_group_capability, decode_public_key, gate_group_message,
    registration_transcript, verify_admission_solution, verify_challenge, verify_registration,
    GroupClientMsg, GroupEntryWire, GroupProtocolGate, GroupServerMsg, MAX_GROUP_FRAME_BYTES,
};
use super::store::GroupCapability;
use super::{RegistrationAttempts, Service, Subscriber};
use crate::app::{AppState, SUBSCRIBER_CHANNEL_CAPACITY};
use crate::clock::now;
use crate::coordinator::{self, protocol::CandidateWire};
use crate::push::{self, PushRegistry};
use crate::socket_admission::{client_ip, SocketAdmission};

#[derive(Clone)]
pub struct ConnectionState {
    service: Service,
    coordinator: coordinator::Service,
    push: Arc<PushRegistry>,
    connection_ids: Arc<AtomicU64>,
    admission_difficulty: u8,
    socket_slots: Arc<Semaphore>,
    socket_admission: SocketAdmission,
    trusted_proxy_ip: Option<IpAddr>,
}

impl FromRef<AppState> for ConnectionState {
    fn from_ref(state: &AppState) -> Self {
        Self {
            service: state.group.clone(),
            coordinator: state.coordinator.clone(),
            push: state.push.clone(),
            connection_ids: state.connection_ids.clone(),
            admission_difficulty: state.group_admission_difficulty,
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
    ws.max_message_size(MAX_GROUP_FRAME_BYTES)
        .on_upgrade(move |socket| async move {
            let _slot = slot;
            let _ip_slot = ip_slot;
            handle_socket(socket, state).await;
        })
        .into_response()
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
    let mut registration_attempts = RegistrationAttempts::default();
    let mut registration_challenge: Option<([u8; 32], [u8; 32], u64)> = None;
    let handshake_deadline = Instant::now() + Duration::from_secs(60);

    loop {
        let next = if authenticated.is_some() {
            socket_rx.next().await
        } else {
            match timeout_at(handshake_deadline, socket_rx.next()).await {
                Ok(message) => message,
                Err(_) => break,
            }
        };
        let Some(Ok(message)) = next else {
            break;
        };
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
                authorization_generation,
                permanent_controller_public_key,
                capabilities,
                signature,
                admission_solution,
            } => {
                if !registration_attempts.admit() {
                    reply(&tx, generic_error());
                    continue;
                }
                let result = verify_registration(
                    &coordination_id,
                    authorization_generation,
                    &permanent_controller_public_key,
                    &capabilities,
                    &signature,
                )
                .and_then(|registration| {
                    let now = now();
                    let existing = state
                        .service
                        .store
                        .lock()
                        .unwrap()
                        .contains_group(&registration.coordination_id);
                    if !existing {
                        let transcript = registration_transcript(
                            registration.coordination_id,
                            registration.authorization_generation,
                            registration.permanent_controller_public_key,
                            &registration.capabilities,
                        );
                        let digest: [u8; 32] = Sha256::digest(&transcript).into();
                        let verified = admission_solution
                            .as_deref()
                            .and_then(|encoded| B64.decode(encoded).ok())
                            .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
                            .is_some_and(|solution| {
                                registration_challenge.take().is_some_and(
                                    |(nonce, expected_digest, issued_at)| {
                                        expected_digest == digest
                                            && now.saturating_sub(issued_at) < 60
                                            && verify_admission_solution(
                                                &nonce,
                                                &transcript,
                                                &solution,
                                                state.admission_difficulty,
                                            )
                                    },
                                )
                            });
                        if !verified {
                            if admission_solution.is_some() {
                                return Err(super::store::StoreError::Unauthorized);
                            }
                            let mut nonce = [0_u8; 32];
                            rand::thread_rng().fill_bytes(&mut nonce);
                            registration_challenge = Some((nonce, digest, now));
                            reply(
                                &tx,
                                GroupServerMsg::RegistrationChallenge {
                                    nonce: B64.encode(nonce),
                                    difficulty: state.admission_difficulty,
                                },
                            );
                            return Ok(None);
                        }
                    }
                    let mut store = state.service.store.lock().unwrap();
                    if !store.contains_group(&registration.coordination_id)
                        && !state
                            .service
                            .registration_admission
                            .lock()
                            .unwrap()
                            .admit(now)
                    {
                        return Err(super::store::StoreError::AtCapacity);
                    }
                    store.register_at(registration, now).map(Some)
                });
                match result {
                    Ok(Some(_)) => reply(&tx, GroupServerMsg::Registered),
                    Ok(None) => {}
                    Err(super::store::StoreError::AtCapacity) => reply(&tx, capacity_error()),
                    Err(_) => reply(&tx, generic_error()),
                }
            }
            GroupClientMsg::Authenticate {
                coordination_id,
                capability_id,
            } => {
                let capability = decode_group_capability(&coordination_id, &capability_id)
                    .ok()
                    .and_then(|(coordination_id, capability_id)| {
                        state
                            .service
                            .store
                            .lock()
                            .unwrap()
                            .resolve_capability(coordination_id, capability_id)
                    });
                if capability.is_none() {
                    reply(&tx, generic_error());
                    continue;
                }
                let mut nonce = [0_u8; 32];
                rand::thread_rng().fill_bytes(&mut nonce);
                pending = capability.map(|capability| (capability, nonce));
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
                {
                    let mut store = state.service.store.lock().unwrap();
                    if let Err(error) = store.activate(&capability, now()) {
                        reply(
                            &tx,
                            if error == super::store::StoreError::AtCapacity {
                                capacity_error()
                            } else {
                                generic_error()
                            },
                        );
                        continue;
                    }
                    store.touch(capability.coordination_id, now());
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
                            capability: capability.clone(),
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
                    Ok(entries) => batch_entries(
                        entries
                            .into_iter()
                            .map(|entry| GroupEntryWire {
                                sequence: entry.sequence,
                                ciphertext: B64.encode(entry.ciphertext),
                                timestamp: entry.timestamp,
                            })
                            .collect(),
                    )
                    .unwrap_or_else(|_| generic_error()),
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
            GroupClientMsg::ReplaceCapabilities {
                expected_generation,
                new_generation,
                permanent_controller_public_key,
                capabilities,
            } => {
                let result = authenticated.as_ref().map_or(Err(()), |controller| {
                    let permanent_controller_public_key =
                        decode_public_key(&permanent_controller_public_key).map_err(|_| ())?;
                    let capabilities = capabilities
                        .iter()
                        .map(decode_capability)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|_| ())?;
                    state
                        .service
                        .store
                        .lock()
                        .unwrap()
                        .replace_capabilities(
                            controller,
                            expected_generation,
                            new_generation,
                            permanent_controller_public_key,
                            capabilities,
                        )
                        .map_err(|_| ())
                });
                if result.is_ok() {
                    if let Some(capability) = authenticated.as_ref() {
                        prune_subscribers(&state, capability.coordination_id);
                    }
                }
                reply(&tx, ok_or_error(result));
            }
            GroupClientMsg::RevokeGroup {
                expected_generation,
            } => {
                let result = authenticated.as_ref().map_or(Err(()), |controller| {
                    state
                        .service
                        .store
                        .lock()
                        .unwrap()
                        .revoke_group(controller, expected_generation, now())
                        .map_err(|_| ())
                });
                if result.is_ok() {
                    if let Some(capability) = authenticated.as_ref() {
                        wake_and_push_readers(&state, capability.coordination_id);
                    }
                }
                reply(&tx, ok_or_error(result));
            }
            GroupClientMsg::RegisterPush { token } => {
                let result = authenticated.as_ref().is_some_and(|capability| {
                    state.service.store.lock().unwrap().can_read(capability)
                        && state.push.enabled()
                        && push::is_valid_token(&token)
                        && state.push.register(
                            &push_scope(capability.coordination_id, capability.capability_id),
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
                        &push_scope(capability.coordination_id, capability.capability_id),
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
                    if candidate.is_empty() {
                        return Err(());
                    }
                    state
                        .service
                        .store
                        .lock()
                        .unwrap()
                        .mark_coordinator_activity(&capability.coordination_id);
                    state
                        .coordinator
                        .store
                        .lock()
                        .unwrap()
                        .submit(
                            capability.coordination_id,
                            capability.capability_id,
                            claimed_base_epoch,
                            candidate,
                            now(),
                        )
                        .map_err(|_| ())
                });
                match result {
                    Ok(receipt) => {
                        wake_and_push_readers(&state, capability.coordination_id);
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
                reply(
                    &tx,
                    batch_candidates(candidates).unwrap_or_else(|_| generic_error()),
                );
            }
            GroupClientMsg::Hello { .. } => unreachable!("hello handled by protocol gate"),
        }
        if let Some(capability) = authenticated.as_ref() {
            let mut store = state.service.store.lock().unwrap();
            if store.can_read(capability) || store.can_append(capability) {
                store.touch(capability.coordination_id, now());
            }
        }
    }
    remove_subscriber(&state, authenticated.as_ref(), connection_id);
    writer.abort();
}

fn reply(tx: &mpsc::Sender<GroupServerMsg>, message: GroupServerMsg) {
    let _ = tx.try_send(message);
}

fn wake_readers(state: &ConnectionState, coordination_id: [u8; 32]) {
    let store = state.service.store.lock().unwrap();
    if let Some(subscribers) = state
        .service
        .subscribers
        .lock()
        .unwrap()
        .get_mut(&coordination_id)
    {
        wake_authorized_subscribers(&store, subscribers);
    }
}

fn prune_subscribers(state: &ConnectionState, coordination_id: [u8; 32]) {
    let store = state.service.store.lock().unwrap();
    if let Some(subscribers) = state
        .service
        .subscribers
        .lock()
        .unwrap()
        .get_mut(&coordination_id)
    {
        subscribers.retain(|subscriber| {
            store.can_read(&subscriber.capability) && !subscriber.tx.is_closed()
        });
    }
}

fn wake_authorized_subscribers(store: &super::store::Store, subscribers: &mut Vec<Subscriber>) {
    subscribers.retain(|subscriber| {
        store.can_read(&subscriber.capability)
            && (subscriber.tx.try_send(GroupServerMsg::Wake).is_ok() || !subscriber.tx.is_closed())
    });
}

const MAX_FETCH_ENTRIES: usize = 512;

fn batch_entries(entries: Vec<GroupEntryWire>) -> Result<GroupServerMsg, ()> {
    let overhead = serde_json::to_vec(&GroupServerMsg::Entries { entries: vec![] })
        .map_err(|_| ())?
        .len();
    let entries = bounded_items(entries, overhead)?;
    Ok(GroupServerMsg::Entries { entries })
}

fn batch_candidates(candidates: Vec<CandidateWire>) -> Result<GroupServerMsg, ()> {
    let overhead =
        serde_json::to_vec(&GroupServerMsg::CoordinatorCandidates { candidates: vec![] })
            .map_err(|_| ())?
            .len();
    let candidates = bounded_items(candidates, overhead)?;
    Ok(GroupServerMsg::CoordinatorCandidates { candidates })
}

fn bounded_items<T: Serialize>(items: Vec<T>, overhead: usize) -> Result<Vec<T>, ()> {
    let mut bytes = overhead;
    let mut page = Vec::new();
    for item in items {
        if page.len() == MAX_FETCH_ENTRIES {
            break;
        }
        let item_bytes = serde_json::to_vec(&item).map_err(|_| ())?.len();
        let next = bytes
            .saturating_add(item_bytes)
            .saturating_add(usize::from(!page.is_empty()));
        if next > MAX_GROUP_FRAME_BYTES {
            if page.is_empty() {
                return Err(());
            }
            break;
        }
        bytes = next;
        page.push(item);
    }
    Ok(page)
}

fn wake_and_push_readers(state: &ConnectionState, coordination_id: [u8; 32]) {
    wake_readers(state, coordination_id);
    for reader_key in state
        .service
        .store
        .lock()
        .unwrap()
        .reader_keys(&coordination_id)
    {
        push::notify_deposit(state.push.clone(), push_scope(coordination_id, reader_key));
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

fn capacity_error() -> GroupServerMsg {
    GroupServerMsg::Error {
        message: "capacity".into(),
    }
}

fn push_scope(coordination_id: [u8; 32], capability_key: [u8; 32]) -> String {
    let mut scope = String::with_capacity(6 + 128);
    scope.push_str("group:");
    scope.push_str(&hex::encode(coordination_id));
    scope.push_str(&hex::encode(capability_key));
    scope
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::store::{CapabilityRegistration, Config, GroupRegistration, Store};

    #[test]
    fn group_pages_at_512_entries_and_within_encoded_frame_limit() {
        let entries = (1..=513)
            .map(|sequence| GroupEntryWire {
                sequence,
                ciphertext: B64.encode([0_u8; 1]),
                timestamp: 1,
            })
            .collect();
        let page = batch_entries(entries).unwrap();
        let GroupServerMsg::Entries { entries } = &page else {
            panic!("wrong response")
        };
        assert_eq!(entries.len(), 512);
        assert!(serde_json::to_vec(&page).unwrap().len() <= MAX_GROUP_FRAME_BYTES);

        let entries = (1..=3)
            .map(|sequence| GroupEntryWire {
                sequence,
                ciphertext: B64.encode(vec![0_u8; 600_000]),
                timestamp: 1,
            })
            .collect();
        let page = batch_entries(entries).unwrap();
        let GroupServerMsg::Entries { entries } = &page else {
            panic!("wrong response")
        };
        assert_eq!(entries.len(), 2);
        assert!(serde_json::to_vec(&page).unwrap().len() <= MAX_GROUP_FRAME_BYTES);
    }

    #[test]
    fn group_page_includes_one_maximum_sized_entry() {
        let page = batch_entries(vec![GroupEntryWire {
            sequence: u64::MAX,
            ciphertext: B64.encode(vec![0_u8; 1024 * 1024]),
            timestamp: u64::MAX,
        }])
        .unwrap();
        let GroupServerMsg::Entries { entries } = &page else {
            panic!("wrong response")
        };
        assert_eq!(entries.len(), 1);
        assert!(serde_json::to_vec(&page).unwrap().len() <= MAX_GROUP_FRAME_BYTES);
    }

    #[test]
    fn coordinator_pages_by_count_and_encoded_bytes() {
        use crate::coordinator::protocol::ReceiptWire;
        let receipt = ReceiptWire {
            coordination_id: "a".repeat(64),
            sequence: 1,
            prior_receipt_hash: "b".repeat(64),
            claimed_base_epoch: 1,
            entry_hash: "c".repeat(64),
            signature: "d".repeat(88),
        };
        let candidates = (0..513)
            .map(|_| CandidateWire {
                receipt: receipt.clone(),
                candidate: B64.encode([1_u8]),
                timestamp: 1,
            })
            .collect();
        let page = batch_candidates(candidates).unwrap();
        let GroupServerMsg::CoordinatorCandidates { candidates } = &page else {
            panic!("wrong response")
        };
        assert_eq!(candidates.len(), 512);
        assert!(serde_json::to_vec(&page).unwrap().len() <= MAX_GROUP_FRAME_BYTES);

        let candidates = (0..3)
            .map(|_| CandidateWire {
                receipt: receipt.clone(),
                candidate: B64.encode(vec![1_u8; 600_000]),
                timestamp: 1,
            })
            .collect();
        let page = batch_candidates(candidates).unwrap();
        let GroupServerMsg::CoordinatorCandidates { candidates } = &page else {
            panic!("wrong response")
        };
        assert_eq!(candidates.len(), 2);
        assert!(serde_json::to_vec(&page).unwrap().len() <= MAX_GROUP_FRAME_BYTES);

        let page = batch_candidates(vec![CandidateWire {
            receipt,
            candidate: B64.encode(vec![1_u8; 1024 * 1024]),
            timestamp: u64::MAX,
        }])
        .unwrap();
        let GroupServerMsg::CoordinatorCandidates { candidates } = &page else {
            panic!("wrong response")
        };
        assert_eq!(candidates.len(), 1);
        assert!(serde_json::to_vec(&page).unwrap().len() <= MAX_GROUP_FRAME_BYTES);
    }

    #[test]
    fn revoked_socket_receives_no_wake_and_retained_reader_does() {
        let mut store = Store::bounded(Config {
            ttl_secs: 60,
            lease_secs: 60,
            max_groups: 4,
            max_capabilities_per_group: 4,
            max_entry_bytes: 1024,
            max_entries_per_group: 4,
            max_total_bytes: 4096,
            max_fetch_batch_bytes: 2048,
        });
        let registration = GroupRegistration {
            coordination_id: [9; 32],
            authorization_generation: 0,
            permanent_controller_public_key: [1; 32],
            capabilities: (1..=3)
                .map(|id| CapabilityRegistration {
                    capability_id: [id; 32],
                    public_key: [id; 32],
                    can_append: true,
                    can_read: true,
                    can_control: id == 1,
                })
                .collect(),
        };
        let group = store.register(registration).unwrap();
        let removed = group.reader(2);
        let retained = group.reader(1);
        let (removed_tx, mut removed_rx) = mpsc::channel(2);
        let (retained_tx, mut retained_rx) = mpsc::channel(2);
        let mut subscribers = vec![
            Subscriber {
                connection_id: 1,
                capability: removed,
                tx: removed_tx,
            },
            Subscriber {
                connection_id: 2,
                capability: retained.clone(),
                tx: retained_tx,
            },
        ];
        let replacements = vec![
            CapabilityRegistration {
                capability_id: [11; 32],
                public_key: [1; 32],
                can_append: true,
                can_read: true,
                can_control: true,
            },
            CapabilityRegistration {
                capability_id: retained.capability_id,
                public_key: retained.public_key,
                can_append: true,
                can_read: true,
                can_control: false,
            },
            CapabilityRegistration {
                capability_id: [14; 32],
                public_key: [4; 32],
                can_append: true,
                can_read: true,
                can_control: false,
            },
        ];
        store
            .replace_capabilities(&group.writer(0), 0, 1, [1; 32], replacements)
            .unwrap();
        wake_authorized_subscribers(&store, &mut subscribers);
        assert!(removed_rx.try_recv().is_err());
        assert!(matches!(retained_rx.try_recv(), Ok(GroupServerMsg::Wake)));
        assert_eq!(subscribers.len(), 1);
        // Message appends and coordinator submissions both use this wake path.
        wake_authorized_subscribers(&store, &mut subscribers);
        assert!(removed_rx.try_recv().is_err());
        assert!(matches!(retained_rx.try_recv(), Ok(GroupServerMsg::Wake)));
    }

    #[test]
    fn group_fetch_returns_first_entry_when_raw_budget_is_smaller() {
        let mut store = Store::bounded(Config {
            ttl_secs: 60,
            lease_secs: 60,
            max_groups: 4,
            max_capabilities_per_group: 4,
            max_entry_bytes: 1024,
            max_entries_per_group: 4,
            max_total_bytes: 4096,
            max_fetch_batch_bytes: 1,
        });
        let group = store
            .register(GroupRegistration {
                coordination_id: [7; 32],
                authorization_generation: 0,
                permanent_controller_public_key: [1; 32],
                capabilities: (1..=3)
                    .map(|id| CapabilityRegistration {
                        capability_id: [id; 32],
                        public_key: [id; 32],
                        can_append: true,
                        can_read: true,
                        can_control: id == 1,
                    })
                    .collect(),
            })
            .unwrap();
        store.append(&group.writer(0), vec![1; 10], 1).unwrap();
        assert_eq!(store.fetch(&group.reader(1), 0).unwrap().len(), 1);
    }

    #[test]
    fn durable_backlog_pages_after_restart() {
        use crate::durable::GroupJournal;
        let directory = tempfile::tempdir().unwrap();
        let config = Config {
            ttl_secs: 60,
            lease_secs: 60,
            max_groups: 4,
            max_capabilities_per_group: 4,
            max_entry_bytes: 1024,
            max_entries_per_group: 600,
            max_total_bytes: 4096,
            max_fetch_batch_bytes: 4096,
        };
        let mut store = Store::durable(
            config.clone(),
            GroupJournal::open(directory.path()).unwrap(),
            1,
        )
        .unwrap();
        let group = store
            .register_at(
                GroupRegistration {
                    coordination_id: [7; 32],
                    authorization_generation: 0,
                    permanent_controller_public_key: [1; 32],
                    capabilities: (1..=3)
                        .map(|id| CapabilityRegistration {
                            capability_id: [id; 32],
                            public_key: [id; 32],
                            can_append: true,
                            can_read: true,
                            can_control: id == 1,
                        })
                        .collect(),
                },
                1,
            )
            .unwrap();
        for value in 0..513_u16 {
            store
                .append(&group.writer(0), value.to_be_bytes().to_vec(), 1)
                .unwrap();
        }
        drop(store);

        let restored =
            Store::durable(config, GroupJournal::open(directory.path()).unwrap(), 2).unwrap();
        let reader = restored
            .resolve_capability(*group.id(), group.reader(1).capability_id)
            .unwrap();
        let first = batch_entries(
            restored
                .fetch(&reader, 0)
                .unwrap()
                .into_iter()
                .map(|entry| GroupEntryWire {
                    sequence: entry.sequence,
                    ciphertext: B64.encode(entry.ciphertext),
                    timestamp: entry.timestamp,
                })
                .collect(),
        )
        .unwrap();
        let GroupServerMsg::Entries { entries } = first else {
            panic!("wrong response")
        };
        assert_eq!(entries.len(), 512);
        let second = batch_entries(
            restored
                .fetch(&reader, entries.last().unwrap().sequence)
                .unwrap()
                .into_iter()
                .map(|entry| GroupEntryWire {
                    sequence: entry.sequence,
                    ciphertext: B64.encode(entry.ciphertext),
                    timestamp: entry.timestamp,
                })
                .collect(),
        )
        .unwrap();
        let GroupServerMsg::Entries { entries } = second else {
            panic!("wrong response")
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].sequence, 513);
    }
}
