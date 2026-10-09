#[test]
fn public_request_waits_for_pending_mutation_then_auto_approves_on_receipt() {
    let mut admin = owner_with_group();
    let group = snapshot(&admin).groups.remove(0);
    execute(
        &mut admin,
        "invite",
        wire_proto::client_command::Body::CreateGroupInvite(wire_proto::CreateGroupInvite {
            group_id: group.group_id.clone(),
            mode: wire_proto::GroupInviteMode::Public as i32,
            expires_at_ms: EXPIRY,
            now_ms: NOW,
        }),
    );
    let ticket = snapshot(&admin).group_invites[0].ticket.clone();
    let changed = execute(
        &mut admin,
        "rename",
        wire_proto::client_command::Body::ChangeGroupPolicy(wire_proto::ChangeGroupPolicy {
            group_id: group.group_id,
            kind: wire_proto::GroupPolicyChangeKind::NameChanged as i32,
            subject_identity: Vec::new(),
            string_value: "Changed".to_owned(),
            bool_value: false,
        }),
    );
    let submission =
        wire_proto::GroupCoordinatorSubmission::decode(changed.outbound[0].payload.as_slice())
            .unwrap();
    let mut joiner = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(2)).unwrap();
    let request = execute(
        &mut joiner,
        "start",
        wire_proto::client_command::Body::StartGroupInviteJoin(wire_proto::StartGroupInviteJoin {
            ticket,
            now_ms: NOW,
        }),
    )
    .outbound
    .remove(0);
    let pending = execute(
        &mut admin,
        "receive",
        wire_proto::client_command::Body::ApplyGroupInviteInboxEnvelope(
            wire_proto::ApplyGroupInviteInboxEnvelope {
                inbox_address: request.destination,
                ciphertext: request.payload,
                now_ms: NOW,
            },
        ),
    );
    assert!(pending.outbound.is_empty());
    assert_eq!(
        snapshot(&admin).group_invites[0].requests[0].progress,
        wire_proto::GroupInviteProgress::Pending as i32
    );

    let entry_hash: [u8; 32] = Sha256::digest(&submission.candidate).into();
    let coordination_id: [u8; 32] = group.coordination_id.try_into().unwrap();
    let transcript = pigeon_core::coordinator_receipt_transcript(
        coordination_id,
        1,
        [0; 32],
        submission.claimed_base_epoch,
        entry_hash,
    );
    let receipt = wire_proto::CoordinatorCandidate {
        receipt: Some(wire_proto::CoordinatorReceipt {
            version: 1,
            coordination_id: coordination_id.to_vec(),
            sequence: 1,
            prior_receipt_hash: vec![0; 32],
            claimed_base_epoch: submission.claimed_base_epoch,
            entry_hash: entry_hash.to_vec(),
            signature: SigningKey::from_bytes(&[60; 32])
                .sign(&transcript)
                .to_bytes()
                .to_vec(),
        }),
        candidate: submission.candidate,
    }
    .encode_to_vec();
    let released = execute(
        &mut admin,
        "coordinator",
        wire_proto::client_command::Body::ApplyInbound(wire_proto::ApplyInbound {
            kind: wire_proto::OutboundKind::GroupCoordinator as i32,
            payload: receipt,
            request_id: "coordinator".to_owned(),
            now_ms: NOW + 1,
        }),
    );
    assert_eq!(
        released
            .outbound
            .iter()
            .filter(|item| { item.kind == wire_proto::OutboundKind::GroupInviteReply as i32 })
            .count(),
        1
    );
    assert_eq!(
        snapshot(&admin).group_invites[0].requests[0].progress,
        wire_proto::GroupInviteProgress::Approved as i32
    );
}

#[test]
fn expired_invites_are_pruned_before_active_invite_limit() {
    let mut admin = owner_with_group();
    let group_id = snapshot(&admin).groups[0].group_id.clone();
    for index in 0..16 {
        execute(
            &mut admin,
            &format!("invite-{index}"),
            wire_proto::client_command::Body::CreateGroupInvite(wire_proto::CreateGroupInvite {
                group_id: group_id.clone(),
                mode: wire_proto::GroupInviteMode::Private as i32,
                expires_at_ms: NOW + 1,
                now_ms: NOW,
            }),
        );
    }
    assert_eq!(snapshot(&admin).group_invites.len(), 16);
    execute(
        &mut admin,
        "fresh-invite",
        wire_proto::client_command::Body::CreateGroupInvite(wire_proto::CreateGroupInvite {
            group_id,
            mode: wire_proto::GroupInviteMode::Private as i32,
            expires_at_ms: EXPIRY,
            now_ms: NOW + 2,
        }),
    );
    assert_eq!(snapshot(&admin).group_invites.len(), 1);
}

#[test]
fn terminal_request_is_pruned_without_losing_replay_defense() {
    let mut admin = owner_with_group();
    let group_id = snapshot(&admin).groups[0].group_id.clone();
    execute(
        &mut admin,
        "invite",
        wire_proto::client_command::Body::CreateGroupInvite(wire_proto::CreateGroupInvite {
            group_id,
            mode: wire_proto::GroupInviteMode::Private as i32,
            expires_at_ms: EXPIRY,
            now_ms: NOW,
        }),
    );
    let ticket = snapshot(&admin).group_invites[0].ticket.clone();
    let mut first_joiner =
        PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(2)).unwrap();
    let first_request = execute(
        &mut first_joiner,
        "start-first",
        wire_proto::client_command::Body::StartGroupInviteJoin(wire_proto::StartGroupInviteJoin {
            ticket: ticket.clone(),
            now_ms: NOW,
        }),
    )
    .outbound
    .remove(0);
    execute(
        &mut admin,
        "first-request",
        wire_proto::client_command::Body::ApplyGroupInviteInboxEnvelope(
            wire_proto::ApplyGroupInviteInboxEnvelope {
                inbox_address: first_request.destination.clone(),
                ciphertext: first_request.payload.clone(),
                now_ms: NOW,
            },
        ),
    );
    let request_id = snapshot(&admin).group_invites[0].requests[0]
        .request_id
        .clone();
    execute(
        &mut admin,
        "reject",
        wire_proto::client_command::Body::DecideGroupInviteRequest(
            wire_proto::DecideGroupInviteRequest {
                inbox_address: first_request.destination.clone(),
                request_id,
                approve: false,
                now_ms: NOW,
            },
        ),
    );
    let mut second_joiner =
        PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(3)).unwrap();
    let second_request = execute(
        &mut second_joiner,
        "start-second",
        wire_proto::client_command::Body::StartGroupInviteJoin(wire_proto::StartGroupInviteJoin {
            ticket,
            now_ms: NOW,
        }),
    )
    .outbound
    .remove(0);
    execute(
        &mut admin,
        "second-request",
        wire_proto::client_command::Body::ApplyGroupInviteInboxEnvelope(
            wire_proto::ApplyGroupInviteInboxEnvelope {
                inbox_address: second_request.destination,
                ciphertext: second_request.payload,
                now_ms: NOW,
            },
        ),
    );
    assert_eq!(snapshot(&admin).group_invites[0].requests.len(), 1);
    let replay = execute(
        &mut admin,
        "first-replay",
        wire_proto::client_command::Body::ApplyGroupInviteInboxEnvelope(
            wire_proto::ApplyGroupInviteInboxEnvelope {
                inbox_address: first_request.destination,
                ciphertext: first_request.payload,
                now_ms: NOW,
            },
        ),
    );
    assert_eq!(
        replay.invite_envelope_outcome,
        wire_proto::GroupInviteEnvelopeOutcome::Rejected as i32
    );
}

#[test]
fn authenticated_reply_after_ticket_expiry_terminates_pending_join() {
    let mut admin = owner_with_group();
    let group_id = snapshot(&admin).groups[0].group_id.clone();
    execute(
        &mut admin,
        "invite",
        wire_proto::client_command::Body::CreateGroupInvite(wire_proto::CreateGroupInvite {
            group_id,
            mode: wire_proto::GroupInviteMode::Private as i32,
            expires_at_ms: EXPIRY,
            now_ms: NOW,
        }),
    );
    let ticket = snapshot(&admin).group_invites[0].ticket.clone();
    let mut joiner = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(2)).unwrap();
    let request = execute(
        &mut joiner,
        "start",
        wire_proto::client_command::Body::StartGroupInviteJoin(wire_proto::StartGroupInviteJoin {
            ticket,
            now_ms: NOW,
        }),
    )
    .outbound
    .remove(0);
    execute(
        &mut admin,
        "receive",
        wire_proto::client_command::Body::ApplyGroupInviteInboxEnvelope(
            wire_proto::ApplyGroupInviteInboxEnvelope {
                inbox_address: request.destination.clone(),
                ciphertext: request.payload,
                now_ms: NOW,
            },
        ),
    );
    let request_id = snapshot(&admin).group_invites[0].requests[0]
        .request_id
        .clone();
    let response = execute(
        &mut admin,
        "reject",
        wire_proto::client_command::Body::DecideGroupInviteRequest(
            wire_proto::DecideGroupInviteRequest {
                inbox_address: request.destination,
                request_id,
                approve: false,
                now_ms: NOW,
            },
        ),
    )
    .outbound
    .remove(0);
    let result = execute(
        &mut joiner,
        "late-reply",
        wire_proto::client_command::Body::ApplyGroupInviteReply(
            wire_proto::ApplyGroupInviteReply {
                reply_address: response.destination,
                ciphertext: response.payload,
                now_ms: EXPIRY + 1,
            },
        ),
    );
    assert_eq!(
        result.invite_envelope_outcome,
        wire_proto::GroupInviteEnvelopeOutcome::Accepted as i32
    );
    assert_eq!(
        snapshot(&joiner).group_invite_joins[0].progress,
        wire_proto::GroupInviteProgress::Expired as i32
    );
}

#[test]
fn refresh_expires_unanswered_join_and_removes_unsent_request() {
    let mut admin = owner_with_group();
    let group_id = snapshot(&admin).groups[0].group_id.clone();
    execute(
        &mut admin,
        "invite",
        wire_proto::client_command::Body::CreateGroupInvite(wire_proto::CreateGroupInvite {
            group_id,
            mode: wire_proto::GroupInviteMode::Private as i32,
            expires_at_ms: EXPIRY,
            now_ms: NOW,
        }),
    );
    let ticket = snapshot(&admin).group_invites[0].ticket.clone();
    let mut joiner = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(2)).unwrap();
    execute(
        &mut joiner,
        "start",
        wire_proto::client_command::Body::StartGroupInviteJoin(wire_proto::StartGroupInviteJoin {
            ticket,
            now_ms: NOW,
        }),
    );
    assert_eq!(snapshot(&joiner).pending_outbound.len(), 1);
    execute(
        &mut joiner,
        "refresh",
        wire_proto::client_command::Body::RefreshGroupInvites(wire_proto::RefreshGroupInvites {
            now_ms: EXPIRY + 1,
        }),
    );
    let refreshed = snapshot(&joiner);
    assert_eq!(
        refreshed.group_invite_joins[0].progress,
        wire_proto::GroupInviteProgress::Expired as i32
    );
    assert!(refreshed.pending_outbound.is_empty());
    let checkpoint = joiner.store().load().unwrap().unwrap();
    let state = wire_proto::ClientCheckpoint::decode(checkpoint.bytes.as_slice()).unwrap();
    assert!(state.group_invite_joins[0].reply_inbox_state.is_empty());
    assert_eq!(state.group_invite_joins[0].reply_address.len(), 32);
    execute(
        &mut joiner,
        "refresh-again",
        wire_proto::client_command::Body::RefreshGroupInvites(wire_proto::RefreshGroupInvites {
            now_ms: EXPIRY + 2,
        }),
    );
    assert!(snapshot(&joiner).group_invite_joins.is_empty());
    execute(
        &mut admin,
        "refresh",
        wire_proto::client_command::Body::RefreshGroupInvites(wire_proto::RefreshGroupInvites {
            now_ms: EXPIRY + 1,
        }),
    );
    assert!(snapshot(&admin).group_invites.is_empty());
}
