use ed25519_dalek::{Signer, SigningKey};
use pigeon_core::{
    ClientCommand, CoordinatorBinding, CoordinatorReceipt, Error, GroupId, GroupJoinMaterial,
    GroupJoinRequest, GroupMutationCandidate, GroupRelayControl, GroupRelayControlKind,
    GroupRelayRegistration, IdentityError, IdentityPurpose, MemoryStateStore, PigeonClient,
    PigeonGroupPolicy, RecoveryCertificate, RecoveryEndorsement, RecoveryProposal, SecureIdentity,
    StateStore, TransactionalOpenMlsStorage, coordinator_receipt_transcript, wire_proto,
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
            mls: SigningKey::from_bytes(&[byte.wrapping_add(64); 32]),
            capability: SigningKey::from_bytes(&[byte.wrapping_add(96); 32]),
            recovery: SigningKey::from_bytes(&[byte.wrapping_add(128); 32]),
        }
    }

    fn root_public(&self) -> [u8; 32] {
        self.root.verifying_key().to_bytes()
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

fn create_group() -> ClientCommand {
    ClientCommand::create_group(
        "command-1",
        "Friends",
        vec![
            TestIdentity::new(2).root_public(),
            TestIdentity::new(3).root_public(),
        ],
        "https://relay.example",
        TestIdentity::new(60).root_public(),
        false,
    )
    .unwrap()
}

fn pairwise_prekey(client: &PigeonClient<MemoryStateStore, TestIdentity>) -> Vec<u8> {
    wire_proto::ClientSnapshot::decode(client.snapshot().unwrap().encode().as_slice())
        .unwrap()
        .pairwise_prekey_bundle
}

fn register_pairwise_peers(
    left: &mut PigeonClient<MemoryStateStore, TestIdentity>,
    right: &mut PigeonClient<MemoryStateStore, TestIdentity>,
    label: &str,
) {
    left.execute(ClientCommand::ensure_pairwise_account(format!("{label}-left-account")).unwrap())
        .unwrap();
    right
        .execute(ClientCommand::ensure_pairwise_account(format!("{label}-right-account")).unwrap())
        .unwrap();
    let left_prekey = pairwise_prekey(left);
    let right_prekey = pairwise_prekey(right);
    left.execute(
        ClientCommand::register_pairwise_contact(
            format!("{label}-register-right"),
            right_prekey,
            "https://relay.example",
        )
        .unwrap(),
    )
    .unwrap();
    right
        .execute(
            ClientCommand::register_pairwise_contact(
                format!("{label}-register-left"),
                left_prekey,
                "https://relay.example",
            )
            .unwrap(),
        )
        .unwrap();
}

fn group_clients() -> (
    PigeonClient<MemoryStateStore, TestIdentity>,
    PigeonClient<MemoryStateStore, TestIdentity>,
    PigeonClient<MemoryStateStore, TestIdentity>,
) {
    let mut owner = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(1)).unwrap();
    let mut bob = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(2)).unwrap();
    let mut carol = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(3)).unwrap();
    register_pairwise_peers(&mut owner, &mut bob, "group-bob");
    register_pairwise_peers(&mut owner, &mut carol, "group-carol");
    (owner, bob, carol)
}

fn receive_group_control(
    recipient: &mut PigeonClient<MemoryStateStore, TestIdentity>,
    command_id: &str,
    item: &pigeon_core::OutboundItem,
) -> pigeon_core::ClientOutput {
    let payload = wire_proto::OutboundItem::decode(item.encode().as_slice())
        .unwrap()
        .payload;
    recipient
        .execute(ClientCommand::apply_pairwise_control(command_id, payload).unwrap())
        .unwrap()
}

fn coordinator_candidate(
    submission: &wire_proto::GroupCoordinatorSubmission,
    sequence: u64,
    prior_receipt_hash: [u8; 32],
    coordination_id: [u8; 32],
) -> Vec<u8> {
    coordinator_candidate_signed(
        submission,
        sequence,
        prior_receipt_hash,
        coordination_id,
        &TestIdentity::new(60).root,
    )
}

fn coordinator_candidate_signed(
    submission: &wire_proto::GroupCoordinatorSubmission,
    sequence: u64,
    prior_receipt_hash: [u8; 32],
    coordination_id: [u8; 32],
    signer: &SigningKey,
) -> Vec<u8> {
    let entry_hash: [u8; 32] = Sha256::digest(&submission.candidate).into();
    let transcript = coordinator_receipt_transcript(
        coordination_id,
        sequence,
        prior_receipt_hash,
        submission.claimed_base_epoch,
        entry_hash,
    );
    wire_proto::CoordinatorCandidate {
        receipt: Some(wire_proto::CoordinatorReceipt {
            version: 1,
            coordination_id: coordination_id.to_vec(),
            sequence,
            prior_receipt_hash: prior_receipt_hash.to_vec(),
            claimed_base_epoch: submission.claimed_base_epoch,
            entry_hash: entry_hash.to_vec(),
            signature: signer.sign(&transcript).to_bytes().to_vec(),
        }),
        candidate: submission.candidate.clone(),
    }
    .encode_to_vec()
}

#[test]
fn recovery_certificate_moves_coordination_without_the_owner_relay() {
    let anchored = create_anchored_group();
    let mut owner = anchored.owner;
    let checkpoint = owner.store().load().unwrap().unwrap();
    let state = wire_proto::ClientCheckpoint::decode(checkpoint.bytes.as_slice()).unwrap();
    let policy = PigeonGroupPolicy::decode(&state.groups[0].policy).unwrap();
    let replacement_coordination_id = [77; 32];
    let replacement_coordinator = TestIdentity::new(61);
    let proposal = RecoveryProposal::new(
        &policy,
        state.groups[0].epoch,
        anchored.receipt_head,
        "https://replacement-relay.example",
        CoordinatorBinding::new(
            replacement_coordination_id,
            replacement_coordinator.root_public(),
        ),
    )
    .unwrap();
    let certificate = RecoveryCertificate::new(
        proposal.clone(),
        vec![RecoveryEndorsement::sign(&proposal, &TestIdentity::new(1)).unwrap()],
    )
    .unwrap();
    let encoded_certificate = certificate.encode();

    let staged = owner
        .execute(ClientCommand::recover_group("recover", encoded_certificate.clone()).unwrap())
        .unwrap();
    assert!(staged.events.is_empty());
    assert_eq!(staged.outbound.len(), 2);
    let outbound: Vec<_> = staged
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .collect();
    let registration = outbound
        .iter()
        .find(|item| item.kind == wire_proto::OutboundKind::GroupRelayRegistration as i32)
        .unwrap();
    assert_eq!(registration.destination, replacement_coordination_id);
    GroupRelayRegistration::decode(&registration.payload).unwrap();
    let submission_item = outbound
        .iter()
        .find(|item| item.kind == wire_proto::OutboundKind::GroupCoordinator as i32)
        .unwrap();
    let submission =
        wire_proto::GroupCoordinatorSubmission::decode(submission_item.payload.as_slice()).unwrap();
    let mutation = GroupMutationCandidate::decode(&submission.candidate).unwrap();
    assert_eq!(
        mutation.recovery_certificate(),
        Some(encoded_certificate.as_slice())
    );
    let forged = coordinator_candidate_signed(
        &submission,
        1,
        [0; 32],
        replacement_coordination_id,
        &TestIdentity::new(60).root,
    );
    let before_forgery = owner.snapshot().unwrap().encode();
    assert!(
        owner
            .execute(
                ClientCommand::apply_group_coordinator_candidate("reject-forged-recovery", forged)
                    .unwrap(),
            )
            .is_err()
    );
    assert_eq!(owner.snapshot().unwrap().encode(), before_forgery);
    let canonical = coordinator_candidate_signed(
        &submission,
        1,
        [0; 32],
        replacement_coordination_id,
        &replacement_coordinator.root,
    );
    let merged = owner
        .execute(
            ClientCommand::apply_group_coordinator_candidate("merge-recovery", canonical.clone())
                .unwrap(),
        )
        .unwrap();
    assert!(merged.events.is_empty());

    let replayed = owner
        .execute(
            ClientCommand::apply_group_coordinator_candidate("replay-recovery", canonical).unwrap(),
        )
        .unwrap();
    assert!(replayed.events.is_empty());
    assert!(replayed.outbound.is_empty());

    let snapshot =
        wire_proto::ClientSnapshot::decode(owner.snapshot().unwrap().encode().as_slice()).unwrap();
    let group = &snapshot.groups[0];
    assert_eq!(group.relay_url, "https://replacement-relay.example");
    assert_eq!(group.coordination_id, replacement_coordination_id);
    let capability_id: [u8; 32] = group.capability_id.as_slice().try_into().unwrap();
    let confirmed = owner
        .execute(
            ClientCommand::confirm_group_relay_authorization(
                "confirm-recovered-relay",
                anchored.group_id,
                capability_id,
            )
            .unwrap(),
        )
        .unwrap();
    let event = wire_proto::AppEvent::decode(confirmed.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupPolicyChanged(change) = event.body.unwrap() else {
        panic!("expected relay-changed recovery event");
    };
    assert_eq!(
        change.kind,
        wire_proto::GroupPolicyChangeKind::RelayChanged as i32
    );
}

#[test]
fn canonical_recovery_is_broadcast_once_over_the_existing_mls_group() {
    let anchored = create_anchored_group();
    let mut owner = anchored.owner;
    let replacement_coordination_id = [77; 32];
    let replacement_coordinator = TestIdentity::new(61);

    let staged = owner
        .execute(
            ClientCommand::begin_group_recovery(
                "begin-recovery",
                anchored.group_id,
                "https://replacement-relay.example",
                replacement_coordination_id,
                replacement_coordinator.root_public(),
            )
            .unwrap(),
        )
        .unwrap();
    let submission_item = staged
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupCoordinator as i32)
        .unwrap();
    let submission =
        wire_proto::GroupCoordinatorSubmission::decode(submission_item.payload.as_slice()).unwrap();
    let canonical = coordinator_candidate_signed(
        &submission,
        1,
        [0; 32],
        replacement_coordination_id,
        &replacement_coordinator.root,
    );

    let merged = owner
        .execute(
            ClientCommand::apply_group_coordinator_candidate(
                "merge-recovery-and-fan-out",
                canonical.clone(),
            )
            .unwrap(),
        )
        .unwrap();
    let recovery_notices: Vec<_> = merged
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .filter(|item| item.kind == wire_proto::OutboundKind::GroupMessage as i32)
        .collect();

    assert_eq!(recovery_notices.len(), 1);
    assert_eq!(recovery_notices[0].destination, anchored.coordination_id);
    assert_ne!(recovery_notices[0].payload, canonical);
}

#[test]
fn promoted_admin_recovers_and_broadcasts_while_owner_is_offline() {
    let group = create_group_with_dave();
    let mut owner = group.owner;
    let mut dave = group.dave;
    let dave_identity = TestIdentity::new(4).root_public();

    let promotion = owner
        .execute(
            ClientCommand::promote_group_admin("promote-dave", group.group_id, dave_identity)
                .unwrap(),
        )
        .unwrap();
    let promotion_submission = promotion
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupCoordinator as i32)
        .unwrap();
    let promotion_submission =
        wire_proto::GroupCoordinatorSubmission::decode(promotion_submission.payload.as_slice())
            .unwrap();
    let promoted = coordinator_candidate(
        &promotion_submission,
        3,
        group.receipt_head,
        group.coordination_id,
    );
    owner
        .execute(
            ClientCommand::apply_group_coordinator_candidate(
                "owner-merges-promotion",
                promoted.clone(),
            )
            .unwrap(),
        )
        .unwrap();
    dave.execute(
        ClientCommand::apply_group_coordinator_candidate("dave-merges-promotion", promoted)
            .unwrap(),
    )
    .unwrap();
    let replacement_coordination_id = [78; 32];
    let replacement_coordinator = TestIdentity::new(62);
    let recovery = dave
        .execute(
            ClientCommand::begin_group_recovery(
                "dave-recovers",
                group.group_id,
                "https://replacement-relay.example",
                replacement_coordination_id,
                replacement_coordinator.root_public(),
            )
            .unwrap(),
        )
        .unwrap();
    let recovery_submission = recovery
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupCoordinator as i32)
        .unwrap();
    let recovery_submission =
        wire_proto::GroupCoordinatorSubmission::decode(recovery_submission.payload.as_slice())
            .unwrap();
    let recovered = coordinator_candidate_signed(
        &recovery_submission,
        1,
        [0; 32],
        replacement_coordination_id,
        &replacement_coordinator.root,
    );
    let merged = dave
        .execute(
            ClientCommand::apply_group_coordinator_candidate("dave-merges-recovery", recovered)
                .unwrap(),
        )
        .unwrap();
    let recovery_notices: Vec<_> = merged
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .filter(|item| item.kind == wire_proto::OutboundKind::GroupMessage as i32)
        .collect();

    assert_eq!(recovery_notices.len(), 1);
    assert_eq!(recovery_notices[0].destination, group.coordination_id);
    owner
        .execute(
            ClientCommand::apply_group_message(
                "owner-receives-recovery-after-offline-window",
                recovery_notices[0].payload.clone(),
            )
            .unwrap(),
        )
        .unwrap();
    let snapshot =
        wire_proto::ClientSnapshot::decode(dave.snapshot().unwrap().encode().as_slice()).unwrap();
    assert_eq!(
        snapshot.groups[0].relay_url,
        "https://replacement-relay.example"
    );
    assert_eq!(
        snapshot.groups[0].coordination_id,
        replacement_coordination_id
    );
    let owner_snapshot =
        wire_proto::ClientSnapshot::decode(owner.snapshot().unwrap().encode().as_slice()).unwrap();
    assert_eq!(
        owner_snapshot.groups[0].coordination_id,
        replacement_coordination_id
    );
}
