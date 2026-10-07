use ed25519_dalek::{Signer, SigningKey};
use pigeon_core::{
    ClientCommand, IdentityError, IdentityPurpose, MemoryStateStore, PigeonClient, SecureIdentity,
    StateStore, wire_proto,
};
use prost::Message;
use sha2::{Digest, Sha256};

struct TestIdentity {
    root: SigningKey,
    mls: SigningKey,
    capability: SigningKey,
    recovery: SigningKey,
}

impl TestIdentity {
    fn new(byte: u8) -> Self {
        Self {
            root: SigningKey::from_bytes(&[byte; 32]),
            mls: SigningKey::from_bytes(&[byte + 64; 32]),
            capability: SigningKey::from_bytes(&[byte + 96; 32]),
            recovery: SigningKey::from_bytes(&[byte + 128; 32]),
        }
    }
}

impl SecureIdentity for TestIdentity {
    fn ensure_public_key(&self, purpose: IdentityPurpose) -> Result<[u8; 32], IdentityError> {
        Ok(match purpose {
            IdentityPurpose::Root => self.root.verifying_key().to_bytes(),
            IdentityPurpose::Mls => self.mls.verifying_key().to_bytes(),
            IdentityPurpose::GroupCapability(_) => self.capability.verifying_key().to_bytes(),
            IdentityPurpose::GroupRecovery(_) => self.recovery.verifying_key().to_bytes(),
            _ => return Err(IdentityError::Unavailable),
        })
    }

    fn sign(&self, purpose: IdentityPurpose, message: &[u8]) -> Result<[u8; 64], IdentityError> {
        let key = match purpose {
            IdentityPurpose::Root => &self.root,
            IdentityPurpose::Mls => &self.mls,
            IdentityPurpose::GroupCapability(_) => &self.capability,
            IdentityPurpose::GroupRecovery(_) => &self.recovery,
            _ => return Err(IdentityError::Unavailable),
        };
        Ok(key.sign(message).to_bytes())
    }
}

const NOW: i64 = 1_700_000_000_000;
const EXPIRY: i64 = NOW + 7 * 24 * 60 * 60 * 1000;

fn execute(
    client: &mut PigeonClient<MemoryStateStore, TestIdentity>,
    id: &str,
    body: wire_proto::client_command::Body,
) -> wire_proto::ClientOutput {
    let wire = wire_proto::ClientCommand {
        version: 1,
        command_id: id.to_owned(),
        body: Some(body),
    }
    .encode_to_vec();
    wire_proto::ClientOutput::decode(
        client
            .execute(ClientCommand::decode(&wire).unwrap())
            .unwrap()
            .encode()
            .as_slice(),
    )
    .unwrap()
}

fn snapshot(client: &PigeonClient<MemoryStateStore, TestIdentity>) -> wire_proto::ClientSnapshot {
    wire_proto::ClientSnapshot::decode(client.snapshot().unwrap().encode().as_slice()).unwrap()
}

fn owner_with_group() -> PigeonClient<MemoryStateStore, TestIdentity> {
    let mut owner = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(1)).unwrap();
    execute(
        &mut owner,
        "create",
        wire_proto::client_command::Body::CreateGroup(wire_proto::CreateGroup {
            name: "Open Event".to_owned(),
            member_identities: vec![],
            relay_url: "https://relay.example/group".to_owned(),
            mesh_enabled: false,
            coordinator_public_key: SigningKey::from_bytes(&[60; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
        }),
    );
    owner
}

#[test]
fn public_invite_auto_approves_and_material_stages_only_after_checkpoint() {
    let mut admin = owner_with_group();
    let group_id = snapshot(&admin).groups[0].group_id.clone();
    execute(
        &mut admin,
        "invite",
        wire_proto::client_command::Body::CreateGroupInvite(wire_proto::CreateGroupInvite {
            group_id,
            mode: wire_proto::GroupInviteMode::Public as i32,
            expires_at_ms: EXPIRY,
            now_ms: NOW,
        }),
    );
    let ticket = snapshot(&admin).group_invites[0].ticket.clone();
    let mut joiner = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(2)).unwrap();
    let started = execute(
        &mut joiner,
        "start",
        wire_proto::client_command::Body::StartGroupInviteJoin(wire_proto::StartGroupInviteJoin {
            ticket: ticket.clone(),
            now_ms: NOW,
        }),
    );
    assert_eq!(started.outbound.len(), 1);
    assert_eq!(
        started.outbound[0].kind,
        wire_proto::OutboundKind::GroupInviteRequest as i32
    );
    let request = &started.outbound[0];
    let approved = execute(
        &mut admin,
        "receive",
        wire_proto::client_command::Body::ApplyGroupInviteInboxEnvelope(
            wire_proto::ApplyGroupInviteInboxEnvelope {
                inbox_address: request.destination.clone(),
                ciphertext: request.payload.clone(),
                now_ms: NOW,
            },
        ),
    );
    assert_eq!(approved.outbound.len(), 1);
    assert_eq!(
        approved.outbound[0].kind,
        wire_proto::OutboundKind::GroupInviteReply as i32
    );
    let response = &approved.outbound[0];
    let material = execute(
        &mut joiner,
        "reply",
        wire_proto::client_command::Body::ApplyGroupInviteReply(
            wire_proto::ApplyGroupInviteReply {
                reply_address: response.destination.clone(),
                ciphertext: response.payload.clone(),
                now_ms: NOW,
            },
        ),
    );
    assert_eq!(material.outbound.len(), 1);
    assert_eq!(
        material.outbound[0].kind,
        wire_proto::OutboundKind::GroupInviteMaterial as i32
    );
    let submission = &material.outbound[0];
    let staged = execute(
        &mut admin,
        "material",
        wire_proto::client_command::Body::ApplyGroupInviteInboxEnvelope(
            wire_proto::ApplyGroupInviteInboxEnvelope {
                inbox_address: submission.destination.clone(),
                ciphertext: submission.payload.clone(),
                now_ms: NOW,
            },
        ),
    );
    assert_eq!(staged.outbound.len(), 1);
    assert_eq!(
        staged.outbound[0].kind,
        wire_proto::OutboundKind::GroupCoordinator as i32
    );
    assert_eq!(
        snapshot(&joiner).group_invite_joins[0].progress,
        wire_proto::GroupInviteProgress::Approved as i32
    );
}

#[test]
fn private_invite_waits_for_approval_and_can_be_rejected() {
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
    let started = execute(
        &mut joiner,
        "start",
        wire_proto::client_command::Body::StartGroupInviteJoin(wire_proto::StartGroupInviteJoin {
            ticket: ticket.clone(),
            now_ms: NOW,
        }),
    );
    let request = &started.outbound[0];
    let pending = execute(
        &mut admin,
        "receive",
        wire_proto::client_command::Body::ApplyGroupInviteInboxEnvelope(
            wire_proto::ApplyGroupInviteInboxEnvelope {
                inbox_address: request.destination.clone(),
                ciphertext: request.payload.clone(),
                now_ms: NOW,
            },
        ),
    );
    assert!(pending.outbound.is_empty());
    let request_id = snapshot(&admin).group_invites[0].requests[0]
        .request_id
        .clone();
    let rejected = execute(
        &mut admin,
        "reject",
        wire_proto::client_command::Body::DecideGroupInviteRequest(
            wire_proto::DecideGroupInviteRequest {
                inbox_address: request.destination.clone(),
                request_id,
                approve: false,
                now_ms: NOW,
            },
        ),
    );
    assert_eq!(rejected.outbound.len(), 1);
    let response = &rejected.outbound[0];
    let result = execute(
        &mut joiner,
        "reply",
        wire_proto::client_command::Body::ApplyGroupInviteReply(
            wire_proto::ApplyGroupInviteReply {
                reply_address: response.destination.clone(),
                ciphertext: response.payload.clone(),
                now_ms: NOW,
            },
        ),
    );
    assert!(result.outbound.is_empty());
    assert_eq!(
        result.invite_envelope_outcome,
        wire_proto::GroupInviteEnvelopeOutcome::Accepted as i32
    );
    let replay = execute(
        &mut joiner,
        "reply-replay",
        wire_proto::client_command::Body::ApplyGroupInviteReply(
            wire_proto::ApplyGroupInviteReply {
                reply_address: response.destination.clone(),
                ciphertext: response.payload.clone(),
                now_ms: NOW,
            },
        ),
    );
    assert_eq!(
        replay.invite_envelope_outcome,
        wire_proto::GroupInviteEnvelopeOutcome::Rejected as i32
    );
    assert_eq!(
        snapshot(&joiner).group_invite_joins[0].progress,
        wire_proto::GroupInviteProgress::Rejected as i32
    );
    execute(
        &mut joiner,
        "retry-after-rejection",
        wire_proto::client_command::Body::StartGroupInviteJoin(wire_proto::StartGroupInviteJoin {
            ticket,
            now_ms: NOW,
        }),
    );
    assert_eq!(snapshot(&joiner).group_invite_joins.len(), 1);
}

#[test]
fn replayed_invite_request_is_durably_rejected_without_a_second_approval() {
    let mut admin = owner_with_group();
    let group_id = snapshot(&admin).groups[0].group_id.clone();
    execute(
        &mut admin,
        "invite",
        wire_proto::client_command::Body::CreateGroupInvite(wire_proto::CreateGroupInvite {
            group_id,
            mode: wire_proto::GroupInviteMode::Public as i32,
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
    let body = || {
        wire_proto::client_command::Body::ApplyGroupInviteInboxEnvelope(
            wire_proto::ApplyGroupInviteInboxEnvelope {
                inbox_address: request.destination.clone(),
                ciphertext: request.payload.clone(),
                now_ms: NOW,
            },
        )
    };
    let first = execute(&mut admin, "first", body());
    assert_eq!(
        first.invite_envelope_outcome,
        wire_proto::GroupInviteEnvelopeOutcome::Accepted as i32
    );
    let before = snapshot(&admin);
    let replay = execute(&mut admin, "replay", body());
    assert_eq!(
        replay.invite_envelope_outcome,
        wire_proto::GroupInviteEnvelopeOutcome::Rejected as i32
    );
    assert!(replay.outbound.is_empty());
    let after = snapshot(&admin);
    assert_eq!(after.group_invites[0].requests.len(), 1);
    assert_eq!(after.pending_outbound.len(), before.pending_outbound.len());
}

#[test]
fn invite_mailbox_challenge_signer_uses_only_active_stored_keys() {
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
    let ticket =
        pigeon_core::GroupInviteTicket::decode(&snapshot(&admin).group_invites[0].ticket).unwrap();
    let nonce = [7u8; 32];
    let signature = admin
        .sign_group_invite_mailbox_challenge(&ticket.inbox_address(), &nonce)
        .unwrap();
    ed25519_dalek::VerifyingKey::from_bytes(&ticket.inbox_address())
        .unwrap()
        .verify_strict(&nonce, &ed25519_dalek::Signature::from_bytes(&signature))
        .unwrap();
    execute(
        &mut admin,
        "revoke",
        wire_proto::client_command::Body::RevokeGroupInvite(wire_proto::RevokeGroupInvite {
            inbox_address: ticket.inbox_address().to_vec(),
        }),
    );
    assert!(
        admin
            .sign_group_invite_mailbox_challenge(&ticket.inbox_address(), &nonce)
            .is_err()
    );
}

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
