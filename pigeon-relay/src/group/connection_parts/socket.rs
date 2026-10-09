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
