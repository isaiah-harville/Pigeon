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

#[test]
fn canonical_policy_change_cancels_a_stale_pending_recovery() {
    let group = create_group_with_dave();
    let mut owner = group.owner;
    let dave_identity = TestIdentity::new(4).root_public();

    let promotion = owner
        .execute(
            ClientCommand::promote_group_admin(
                "promote-before-recovery",
                group.group_id,
                dave_identity,
            )
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
    let promoted_head = CoordinatorReceipt::decode_candidate(&promoted)
        .unwrap()
        .0
        .receipt_hash();
    owner
        .execute(
            ClientCommand::apply_group_coordinator_candidate("merge-promotion", promoted).unwrap(),
        )
        .unwrap();

    let pending = owner
        .execute(
            ClientCommand::begin_group_recovery(
                "begin-stale-recovery",
                group.group_id,
                "https://replacement-one.example",
                [81; 32],
                TestIdentity::new(63).root_public(),
            )
            .unwrap(),
        )
        .unwrap();
    assert!(pending.outbound.iter().any(|item| {
        wire_proto::OutboundItem::decode(item.encode().as_slice())
            .unwrap()
            .kind
            == wire_proto::OutboundKind::GroupMessage as i32
    }));

    let rename = owner
        .execute(
            ClientCommand::rename_group("rename-during-recovery", group.group_id, "Birds Two")
                .unwrap(),
        )
        .unwrap();
    let rename_submission = rename
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupCoordinator as i32)
        .unwrap();
    let rename_submission =
        wire_proto::GroupCoordinatorSubmission::decode(rename_submission.payload.as_slice())
            .unwrap();
    let renamed =
        coordinator_candidate(&rename_submission, 4, promoted_head, group.coordination_id);
    owner
        .execute(ClientCommand::apply_group_coordinator_candidate("merge-rename", renamed).unwrap())
        .unwrap();

    let retry = owner.execute(
        ClientCommand::begin_group_recovery(
            "begin-fresh-recovery",
            group.group_id,
            "https://replacement-two.example",
            [82; 32],
            TestIdentity::new(64).root_public(),
        )
        .unwrap(),
    );
    assert!(retry.is_ok());
}

#[test]
fn recovery_quorum_round_trips_inside_mls_group_ciphertext() {
    let group = create_group_with_dave();
    let mut owner = group.owner;
    let mut dave = group.dave;
    let dave_identity = TestIdentity::new(4).root_public();

    let promotion = owner
        .execute(
            ClientCommand::promote_group_admin(
                "promote-quorum-admin",
                group.group_id,
                dave_identity,
            )
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
                "owner-merges-quorum-promotion",
                promoted.clone(),
            )
            .unwrap(),
        )
        .unwrap();
    dave.execute(
        ClientCommand::apply_group_coordinator_candidate("dave-merges-quorum-promotion", promoted)
            .unwrap(),
    )
    .unwrap();

    let proposal = owner
        .execute(
            ClientCommand::begin_group_recovery(
                "owner-begins-quorum-recovery",
                group.group_id,
                "https://replacement-quorum.example",
                [83; 32],
                TestIdentity::new(65).root_public(),
            )
            .unwrap(),
        )
        .unwrap();
    let proposal = proposal
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupMessage as i32)
        .unwrap();
    let endorsement = dave
        .execute(
            ClientCommand::apply_group_message("dave-endorses-recovery", proposal.payload).unwrap(),
        )
        .unwrap();
    assert!(endorsement.events.is_empty());
    let endorsement = endorsement
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupMessage as i32)
        .unwrap();

    let finalized = owner
        .execute(
            ClientCommand::apply_group_message("owner-accepts-endorsement", endorsement.payload)
                .unwrap(),
        )
        .unwrap();
    let kinds = finalized
        .outbound
        .iter()
        .map(|item| {
            wire_proto::OutboundItem::decode(item.encode().as_slice())
                .unwrap()
                .kind
        })
        .collect::<Vec<_>>();
    assert!(kinds.contains(&(wire_proto::OutboundKind::GroupRelayRegistration as i32)));
    assert!(kinds.contains(&(wire_proto::OutboundKind::GroupCoordinator as i32)));
}

#[test]
fn endorsement_arriving_after_recovery_was_cancelled_is_consumed() {
    let group = create_group_with_dave();
    let mut owner = group.owner;
    let mut dave = group.dave;
    let dave_identity = TestIdentity::new(4).root_public();

    let promotion = owner
        .execute(
            ClientCommand::promote_group_admin("promote-late-admin", group.group_id, dave_identity)
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
    let promoted_head = CoordinatorReceipt::decode_candidate(&promoted)
        .unwrap()
        .0
        .receipt_hash();
    owner
        .execute(
            ClientCommand::apply_group_coordinator_candidate(
                "owner-merges-late-promotion",
                promoted.clone(),
            )
            .unwrap(),
        )
        .unwrap();
    dave.execute(
        ClientCommand::apply_group_coordinator_candidate("dave-merges-late-promotion", promoted)
            .unwrap(),
    )
    .unwrap();

    let proposal = owner
        .execute(
            ClientCommand::begin_group_recovery(
                "owner-begins-late-recovery",
                group.group_id,
                "https://replacement-late.example",
                [84; 32],
                TestIdentity::new(66).root_public(),
            )
            .unwrap(),
        )
        .unwrap();
    let proposal = proposal
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupMessage as i32)
        .unwrap();
    let endorsement = dave
        .execute(
            ClientCommand::apply_group_message("dave-endorses-late", proposal.payload).unwrap(),
        )
        .unwrap();
    let endorsement = endorsement
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupMessage as i32)
        .unwrap();

    // A canonical rename lands first and cancels the pending recovery.
    let rename = owner
        .execute(
            ClientCommand::rename_group("rename-before-endorsement", group.group_id, "Birds Two")
                .unwrap(),
        )
        .unwrap();
    let rename_submission = rename
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupCoordinator as i32)
        .unwrap();
    let rename_submission =
        wire_proto::GroupCoordinatorSubmission::decode(rename_submission.payload.as_slice())
            .unwrap();
    let renamed =
        coordinator_candidate(&rename_submission, 4, promoted_head, group.coordination_id);
    owner
        .execute(
            ClientCommand::apply_group_coordinator_candidate("merge-rename-first", renamed)
                .unwrap(),
        )
        .unwrap();

    let late = owner
        .execute(
            ClientCommand::apply_group_message("owner-gets-late-endorsement", endorsement.payload)
                .unwrap(),
        )
        .unwrap();
    assert!(late.outbound.iter().all(|item| {
        wire_proto::OutboundItem::decode(item.encode().as_slice())
            .unwrap()
            .kind
            != wire_proto::OutboundKind::GroupRelayRegistration as i32
    }));

    // The group is not wedged: a fresh recovery can still begin.
    owner
        .execute(
            ClientCommand::begin_group_recovery(
                "owner-begins-after-late",
                group.group_id,
                "https://replacement-after.example",
                [85; 32],
                TestIdentity::new(67).root_public(),
            )
            .unwrap(),
        )
        .unwrap();
}

struct AnchoredGroup {
    owner: PigeonClient<MemoryStateStore, TestIdentity>,
    group_id: GroupId,
    coordination_id: [u8; 32],
    receipt_head: [u8; 32],
    initial_candidate: Vec<u8>,
}

fn create_anchored_group() -> AnchoredGroup {
    let mut client = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(1)).unwrap();
    let mut bob = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(2)).unwrap();
    let mut carol = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(3)).unwrap();
    for peer in [&mut client, &mut bob, &mut carol] {
        peer.execute(ClientCommand::ensure_pairwise_account("group-account").unwrap())
            .unwrap();
    }
    let owner_prekey = pairwise_prekey(&client);
    for (name, peer) in [("bob", &mut bob), ("carol", &mut carol)] {
        client
            .execute(
                ClientCommand::register_pairwise_contact(
                    format!("register-{name}"),
                    pairwise_prekey(peer),
                    "https://relay.example",
                )
                .unwrap(),
            )
            .unwrap();
        peer.execute(
            ClientCommand::register_pairwise_contact(
                "register-owner",
                owner_prekey.clone(),
                "https://relay.example",
            )
            .unwrap(),
        )
        .unwrap();
    }
    let pending = client.execute(create_group()).unwrap();
    let requests: Vec<_> = pending
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .collect();
    let bob_material = bob
        .execute(
            ClientCommand::apply_pairwise_control("bob-joins", requests[0].payload.clone())
                .unwrap(),
        )
        .unwrap();
    let carol_material = carol
        .execute(
            ClientCommand::apply_pairwise_control("carol-joins", requests[1].payload.clone())
                .unwrap(),
        )
        .unwrap();
    client
        .execute(
            ClientCommand::apply_pairwise_control(
                "anchor-material-1",
                wire_proto::OutboundItem::decode(bob_material.outbound[0].encode().as_slice())
                    .unwrap()
                    .payload,
            )
            .unwrap(),
        )
        .unwrap();
    let created = client
        .execute(
            ClientCommand::apply_pairwise_control(
                "anchor-material-2",
                wire_proto::OutboundItem::decode(carol_material.outbound[0].encode().as_slice())
                    .unwrap()
                    .payload,
            )
            .unwrap(),
        )
        .unwrap();
    let event = wire_proto::AppEvent::decode(created.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupCreated(group) = event.body.unwrap() else {
        panic!("expected group creation");
    };
    let group_id = GroupId::from_bytes(group.group_id.try_into().unwrap());
    let coordinator = created
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupCoordinator as i32)
        .unwrap();
    let coordination_id = coordinator.destination.as_slice().try_into().unwrap();
    let submission =
        wire_proto::GroupCoordinatorSubmission::decode(coordinator.payload.as_slice()).unwrap();
    let candidate = coordinator_candidate(&submission, 1, [0; 32], coordination_id);
    let receipt_hash = CoordinatorReceipt::decode_candidate(&candidate)
        .unwrap()
        .0
        .receipt_hash();
    client
        .execute(
            ClientCommand::apply_group_coordinator_candidate("anchor-receipt", candidate.clone())
                .unwrap(),
        )
        .unwrap();
    AnchoredGroup {
        owner: client,
        group_id,
        coordination_id,
        receipt_head: receipt_hash,
        initial_candidate: candidate,
    }
}

#[test]
fn snapshot_exposes_durable_coordinator_cursor() {
    let anchored = create_anchored_group();
    let snapshot =
        wire_proto::ClientSnapshot::decode(anchored.owner.snapshot().unwrap().encode().as_slice())
            .unwrap();

    assert_eq!(snapshot.groups.len(), 1);
    assert_eq!(snapshot.groups[0].coordinator_sequence, 1);
}

#[test]
fn invalid_coordinator_entry_is_consumed_before_a_later_valid_commit() {
    let anchored = create_anchored_group();
    let mut owner = anchored.owner;
    let staged = owner
        .execute(
            ClientCommand::rename_group("stage-valid-rename", anchored.group_id, "Swifts").unwrap(),
        )
        .unwrap();
    let outbound =
        wire_proto::OutboundItem::decode(staged.outbound[0].encode().as_slice()).unwrap();
    let valid_submission =
        wire_proto::GroupCoordinatorSubmission::decode(outbound.payload.as_slice()).unwrap();
    let mut invalid_submission = valid_submission.clone();
    invalid_submission.candidate = vec![0xff, 0x00, 0x01];
    let invalid = coordinator_candidate(
        &invalid_submission,
        2,
        anchored.receipt_head,
        anchored.coordination_id,
    );
    let invalid_receipt_head = CoordinatorReceipt::decode_candidate(&invalid)
        .unwrap()
        .0
        .receipt_hash();

    let rejected = owner
        .execute(
            ClientCommand::apply_group_coordinator_candidate("consume-invalid", invalid).unwrap(),
        )
        .unwrap();
    assert_eq!(rejected.events.len(), 1);
    let warning = wire_proto::AppEvent::decode(rejected.events[0].encode().as_slice()).unwrap();
    assert!(matches!(
        warning.body,
        Some(wire_proto::app_event::Body::GroupSecurityWarning(_))
    ));
    let after_invalid =
        wire_proto::ClientSnapshot::decode(owner.snapshot().unwrap().encode().as_slice()).unwrap();
    assert_eq!(after_invalid.groups[0].coordinator_sequence, 2);
    assert_eq!(after_invalid.groups[0].name, "Friends");

    let valid = coordinator_candidate(
        &valid_submission,
        3,
        invalid_receipt_head,
        anchored.coordination_id,
    );
    owner
        .execute(
            ClientCommand::apply_group_coordinator_candidate("merge-valid-after-invalid", valid)
                .unwrap(),
        )
        .unwrap();
    let merged =
        wire_proto::ClientSnapshot::decode(owner.snapshot().unwrap().encode().as_slice()).unwrap();
    assert_eq!(merged.groups[0].coordinator_sequence, 3);
    assert_eq!(merged.groups[0].name, "Swifts");
}

#[test]
fn invalid_sequenced_group_message_is_durably_classified() {
    let anchored = create_anchored_group();
    let mut owner = anchored.owner;
    let generation = owner.checkpoint_generation();
    let command =
        ClientCommand::apply_group_message("relay-group-sequence-2", vec![0xff, 0x00, 0x01])
            .unwrap();

    let rejected = owner.execute(command).unwrap();

    assert!(rejected.events.is_empty());
    assert!(rejected.outbound.is_empty());
    assert_eq!(owner.checkpoint_generation(), generation + 1);
    let replay = owner
        .execute(
            ClientCommand::apply_group_message("relay-group-sequence-2", vec![0xff, 0x00, 0x01])
                .unwrap(),
        )
        .unwrap();
    assert!(replay.events.is_empty());
    assert!(replay.outbound.is_empty());
    assert_eq!(owner.checkpoint_generation(), generation + 1);
}

struct GroupWithDave {
    owner: PigeonClient<MemoryStateStore, TestIdentity>,
    dave: PigeonClient<MemoryStateStore, TestIdentity>,
    group_id: GroupId,
    coordination_id: [u8; 32],
    receipt_head: [u8; 32],
}

fn create_group_with_dave() -> GroupWithDave {
    let anchored = create_anchored_group();
    let mut owner = anchored.owner;
    let group_id = anchored.group_id;
    let coordination_id = anchored.coordination_id;
    let receipt_head = anchored.receipt_head;
    let mut dave = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(4)).unwrap();
    register_pairwise_peers(&mut owner, &mut dave, "helper-dave");
    let invited = owner
        .execute(
            ClientCommand::add_group_member(
                "helper-invite-dave",
                group_id,
                TestIdentity::new(4).root_public(),
            )
            .unwrap(),
        )
        .unwrap();
    let request =
        wire_proto::OutboundItem::decode(invited.outbound[0].encode().as_slice()).unwrap();
    let material_output = dave
        .execute(
            ClientCommand::apply_pairwise_control("helper-dave-material", request.payload).unwrap(),
        )
        .unwrap();
    let material =
        wire_proto::OutboundItem::decode(material_output.outbound[0].encode().as_slice()).unwrap();
    let staged = owner
        .execute(
            ClientCommand::apply_pairwise_control("helper-apply-dave", material.payload).unwrap(),
        )
        .unwrap();
    let submission_item =
        wire_proto::OutboundItem::decode(staged.outbound[0].encode().as_slice()).unwrap();
    let submission =
        wire_proto::GroupCoordinatorSubmission::decode(submission_item.payload.as_slice()).unwrap();
    let canonical = coordinator_candidate(&submission, 2, receipt_head, coordination_id);
    let receipt_head = CoordinatorReceipt::decode_candidate(&canonical)
        .unwrap()
        .0
        .receipt_hash();
    let merged = owner
        .execute(
            ClientCommand::apply_group_coordinator_candidate(
                "helper-merge-dave",
                canonical.clone(),
            )
            .unwrap(),
        )
        .unwrap();
    let welcome = merged
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| {
            item.kind == wire_proto::OutboundKind::Pairwise as i32
                && item.destination == TestIdentity::new(4).root_public()
        })
        .unwrap();
    let relay_control = merged
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupRelayControl as i32)
        .unwrap();
    owner
        .execute(
            ClientCommand::acknowledge_effects(
                "helper-ack-add-relay-control",
                vec![relay_control.item_id],
                Vec::new(),
            )
            .unwrap(),
        )
        .unwrap();
    dave.execute(
        ClientCommand::apply_pairwise_control("helper-join-dave", welcome.payload).unwrap(),
    )
    .unwrap();
    dave.execute(
        ClientCommand::apply_group_coordinator_candidate(
            "helper-anchor-initial",
            anchored.initial_candidate,
        )
        .unwrap(),
    )
    .unwrap();
    dave.execute(
        ClientCommand::apply_group_coordinator_candidate("helper-anchor-add", canonical).unwrap(),
    )
    .unwrap();
    GroupWithDave {
        owner,
        dave,
        group_id,
        coordination_id,
        receipt_head,
    }
}

#[test]
fn non_admin_policy_event_waits_for_replacement_relay_authentication() {
    let group = create_group_with_dave();
    let mut owner = group.owner;
    let mut dave = group.dave;

    let staged = owner
        .execute(ClientCommand::rename_group("rename", group.group_id, "Renamed").unwrap())
        .unwrap();
    let submission_item =
        wire_proto::OutboundItem::decode(staged.outbound[0].encode().as_slice()).unwrap();
    let submission =
        wire_proto::GroupCoordinatorSubmission::decode(submission_item.payload.as_slice()).unwrap();
    let canonical =
        coordinator_candidate(&submission, 3, group.receipt_head, group.coordination_id);

    owner
        .execute(
            ClientCommand::apply_group_coordinator_candidate(
                "owner-merges-rename",
                canonical.clone(),
            )
            .unwrap(),
        )
        .unwrap();
    let observed = dave
        .execute(
            ClientCommand::apply_group_coordinator_candidate("dave-observes-rename", canonical)
                .unwrap(),
        )
        .unwrap();
    assert!(observed.events.is_empty());
    assert!(observed.outbound.is_empty());

    let snapshot =
        wire_proto::ClientSnapshot::decode(dave.snapshot().unwrap().encode().as_slice()).unwrap();
    let capability_id: [u8; 32] = snapshot.groups[0]
        .capability_id
        .as_slice()
        .try_into()
        .unwrap();
    assert!(
        dave.execute(
            ClientCommand::confirm_group_relay_authorization(
                "reject-wrong-relay-generation",
                group.group_id,
                [9; 32],
            )
            .unwrap(),
        )
        .is_err()
    );
    let confirmed = dave
        .execute(
            ClientCommand::confirm_group_relay_authorization(
                "confirm-renamed-relay-generation",
                group.group_id,
                capability_id,
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(confirmed.events.len(), 1);
    let event = wire_proto::AppEvent::decode(confirmed.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupPolicyChanged(change) = event.body.unwrap() else {
        panic!("expected policy event after relay authentication");
    };
    assert_eq!(
        change.kind,
        wire_proto::GroupPolicyChangeKind::NameChanged as i32
    );
    assert_eq!(change.name, "Renamed");
}

#[test]
fn failed_checkpoint_releases_no_event_or_outbound() {
    let store = MemoryStateStore::failing_on_replace();
    let mut client = PigeonClient::new(store, TestIdentity::new(1)).unwrap();

    let error = client.execute(create_group()).unwrap_err();

    assert!(matches!(error, Error::Persistence(_)));
    assert_eq!(client.checkpoint_generation(), 0);
    assert!(client.store().load().unwrap().is_none());
}

#[test]
fn pairwise_account_is_persisted_before_its_public_prekey_is_exposed() {
    let identity = TestIdentity::new(1);
    let expected_identity = identity.root_public();
    let mut client = PigeonClient::new(MemoryStateStore::default(), identity).unwrap();

    let output = client
        .execute(ClientCommand::ensure_pairwise_account("pairwise-setup").unwrap())
        .unwrap();
    assert_eq!(output.checkpoint_generation, 1);
    let snapshot =
        wire_proto::ClientSnapshot::decode(client.snapshot().unwrap().encode().as_slice()).unwrap();
    let published = pigeon_core::PrekeyBundle::decode(&snapshot.pairwise_prekey_bundle).unwrap();
    published.verify().unwrap();
    assert_eq!(published.identity.identity_key, expected_identity);

    let stored = client.store().load().unwrap().unwrap();
    let mut reloaded = PigeonClient::new(
        CheckpointFixtureStore::from_checkpoint(stored),
        TestIdentity::new(1),
    )
    .unwrap();
    let reloaded_snapshot =
        wire_proto::ClientSnapshot::decode(reloaded.snapshot().unwrap().encode().as_slice())
            .unwrap();
    assert_eq!(
        reloaded_snapshot.pairwise_prekey_bundle,
        snapshot.pairwise_prekey_bundle
    );

    let duplicate = reloaded
        .execute(ClientCommand::ensure_pairwise_account("pairwise-setup-again").unwrap())
        .unwrap();
    assert_eq!(duplicate.checkpoint_generation, 2);
    let duplicate_snapshot =
        wire_proto::ClientSnapshot::decode(reloaded.snapshot().unwrap().encode().as_slice())
            .unwrap();
    assert_eq!(
        duplicate_snapshot.pairwise_prekey_bundle,
        snapshot.pairwise_prekey_bundle
    );
}

#[test]
fn pairwise_control_ratchet_is_persisted_before_envelopes_are_released() {
    let mut bob = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(2)).unwrap();
    bob.execute(ClientCommand::ensure_pairwise_account("bob-pairwise").unwrap())
        .unwrap();
    let bob_snapshot =
        wire_proto::ClientSnapshot::decode(bob.snapshot().unwrap().encode().as_slice()).unwrap();

    let mut alice = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(1)).unwrap();
    alice
        .execute(ClientCommand::ensure_pairwise_account("alice-pairwise").unwrap())
        .unwrap();
    alice
        .execute(
            ClientCommand::register_pairwise_contact(
                "register-bob",
                bob_snapshot.pairwise_prekey_bundle,
                "https://bob-relay.example",
            )
            .unwrap(),
        )
        .unwrap();

    let first = alice
        .execute(
            ClientCommand::send_pairwise_control(
                "send-first",
                TestIdentity::new(2).root_public(),
                wire_proto::OutboundKind::GroupJoinRequest,
                b"first control".to_vec(),
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(first.outbound.len(), 1);
    let first_item =
        wire_proto::OutboundItem::decode(first.outbound[0].encode().as_slice()).unwrap();
    assert_eq!(first_item.kind, wire_proto::OutboundKind::Pairwise as i32);
    assert_eq!(first_item.destination, TestIdentity::new(2).root_public());
    assert_eq!(first_item.relay_url, "https://bob-relay.example");
    let first_envelope =
        wire_proto::PairwiseEnvelope::decode(first_item.payload.as_slice()).unwrap();
    assert!(matches!(
        first_envelope.body,
        Some(wire_proto::pairwise_envelope::Body::Initiation(_))
    ));

    let second = alice
        .execute(
            ClientCommand::send_pairwise_control(
                "send-second",
                TestIdentity::new(2).root_public(),
                wire_proto::OutboundKind::GroupWelcome,
                b"second control".to_vec(),
            )
            .unwrap(),
        )
        .unwrap();
    let second_item =
        wire_proto::OutboundItem::decode(second.outbound[0].encode().as_slice()).unwrap();
    let second_envelope =
        wire_proto::PairwiseEnvelope::decode(second_item.payload.as_slice()).unwrap();
    assert!(matches!(
        second_envelope.body,
        Some(wire_proto::pairwise_envelope::Body::Message(_))
    ));
}

#[test]
fn inbound_pairwise_control_is_decrypted_and_dispatched_inside_one_transaction() {
    let mut alice = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(1)).unwrap();
    let mut bob = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(2)).unwrap();
    alice
        .execute(ClientCommand::ensure_pairwise_account("alice-account").unwrap())
        .unwrap();
    bob.execute(ClientCommand::ensure_pairwise_account("bob-account").unwrap())
        .unwrap();
    let alice_prekey =
        wire_proto::ClientSnapshot::decode(alice.snapshot().unwrap().encode().as_slice())
            .unwrap()
            .pairwise_prekey_bundle;
    let bob_prekey =
        wire_proto::ClientSnapshot::decode(bob.snapshot().unwrap().encode().as_slice())
            .unwrap()
            .pairwise_prekey_bundle;
    alice
        .execute(
            ClientCommand::register_pairwise_contact(
                "alice-registers-bob",
                bob_prekey,
                "https://bob-relay.example",
            )
            .unwrap(),
        )
        .unwrap();
    bob.execute(
        ClientCommand::register_pairwise_contact(
            "bob-registers-alice",
            alice_prekey,
            "https://alice-relay.example",
        )
        .unwrap(),
    )
    .unwrap();

    let draft = alice.execute(create_group()).unwrap();
    let request = draft
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.destination == TestIdentity::new(2).root_public())
        .unwrap();
    assert_eq!(request.kind, wire_proto::OutboundKind::Pairwise as i32);

    let decrypted = bob
        .execute(
            ClientCommand::apply_pairwise_control("bob-decrypts-request", request.payload.clone())
                .unwrap(),
        )
        .unwrap();

    assert_eq!(decrypted.outbound.len(), 1);
    let material =
        wire_proto::OutboundItem::decode(decrypted.outbound[0].encode().as_slice()).unwrap();
    assert_eq!(material.kind, wire_proto::OutboundKind::Pairwise as i32);
    assert_eq!(material.destination, TestIdentity::new(1).root_public());

    let sent = bob
        .execute(
            ClientCommand::send_direct_text(
                "direct-message",
                TestIdentity::new(1).root_public(),
                "hello",
                "",
                1234,
            )
            .unwrap(),
        )
        .unwrap();
    let direct = wire_proto::OutboundItem::decode(sent.outbound[0].encode().as_slice()).unwrap();
    let envelope = wire_proto::PairwiseEnvelope::decode(direct.payload.as_slice()).unwrap();
    assert!(matches!(
        envelope.body,
        Some(wire_proto::pairwise_envelope::Body::Message(_))
    ));
    // Direct messages can arrive before earlier group controls on the same ratchet.
    let received = alice
        .execute(
            ClientCommand::apply_pairwise_control("direct-in", direct.payload.clone()).unwrap(),
        )
        .unwrap();
    let event = wire_proto::AppEvent::decode(received.events[0].encode().as_slice()).unwrap();
    let Some(wire_proto::app_event::Body::DirectApplicationReceived(application)) = event.body
    else {
        panic!("expected direct message")
    };
    assert_eq!(
        application.sender_identity,
        TestIdentity::new(2).root_public()
    );
    let Some(wire_proto::direct_application::Body::Message(message)) =
        application.application.unwrap().body
    else {
        panic!("expected direct message body")
    };
    assert_eq!(message.text, "hello");
    let duplicate = alice
        .execute(ClientCommand::apply_pairwise_control("direct-duplicate", direct.payload).unwrap())
        .unwrap();
    assert!(duplicate.events.is_empty());
    let snapshot =
        wire_proto::ClientSnapshot::decode(alice.snapshot().unwrap().encode().as_slice()).unwrap();
    assert!(
        snapshot
            .pending_events
            .iter()
            .any(|pending| pending.event_id == event.event_id)
    );

    let acknowledged = alice
        .execute(
            ClientCommand::send_direct_acknowledgement(
                "ack-direct-message",
                TestIdentity::new(2).root_public(),
                "direct-message",
            )
            .unwrap(),
        )
        .unwrap();
    let acknowledgement =
        wire_proto::OutboundItem::decode(acknowledged.outbound[0].encode().as_slice()).unwrap();
    let received_ack = bob
        .execute(
            ClientCommand::apply_pairwise_control(
                "bob-receives-direct-ack",
                acknowledgement.payload,
            )
            .unwrap(),
        )
        .unwrap();
    let ack_event =
        wire_proto::AppEvent::decode(received_ack.events[0].encode().as_slice()).unwrap();
    let Some(wire_proto::app_event::Body::DirectApplicationReceived(application)) = ack_event.body
    else {
        panic!("expected direct acknowledgement")
    };
    let Some(wire_proto::direct_application::Body::Acknowledgement(ack)) =
        application.application.unwrap().body
    else {
        panic!("expected direct acknowledgement body")
    };
    assert_eq!(ack.message_id, "direct-message");
    let bob_snapshot =
        wire_proto::ClientSnapshot::decode(bob.snapshot().unwrap().encode().as_slice()).unwrap();
    assert!(
        bob_snapshot
            .pending_outbound
            .iter()
            .all(|item| item.item_id != "direct-message")
    );

    alice
        .execute(
            ClientCommand::apply_pairwise_control(
                "independent-transport-delivery-id",
                material.payload,
            )
            .unwrap(),
        )
        .unwrap();

    let replay = bob
        .execute(
            ClientCommand::apply_pairwise_control(
                "bob-receives-republished-request",
                request.payload,
            )
            .unwrap(),
        )
        .unwrap();
    assert!(replay.events.is_empty());
    assert!(replay.outbound.is_empty());
}

#[test]
fn registering_a_contact_wraps_already_pending_group_controls() {
    let mut bob = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(2)).unwrap();
    bob.execute(ClientCommand::ensure_pairwise_account("bob-account").unwrap())
        .unwrap();
    let bob_prekey =
        wire_proto::ClientSnapshot::decode(bob.snapshot().unwrap().encode().as_slice())
            .unwrap()
            .pairwise_prekey_bundle;
    let mut alice = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(1)).unwrap();
    alice
        .execute(ClientCommand::ensure_pairwise_account("alice-account").unwrap())
        .unwrap();

    let draft = alice.execute(create_group()).unwrap();
    assert!(draft.outbound.is_empty());
    let before_registration =
        wire_proto::ClientSnapshot::decode(alice.snapshot().unwrap().encode().as_slice()).unwrap();
    assert!(before_registration.pending_outbound.is_empty());

    alice
        .execute(
            ClientCommand::register_pairwise_contact(
                "register-bob-late",
                bob_prekey,
                "https://bob-relay.example",
            )
            .unwrap(),
        )
        .unwrap();
    let snapshot =
        wire_proto::ClientSnapshot::decode(alice.snapshot().unwrap().encode().as_slice()).unwrap();
    let wrapped = snapshot
        .pending_outbound
        .iter()
        .find(|item| item.item_id == "command-1:join:0")
        .unwrap();
    assert_eq!(wrapped.kind, wire_proto::OutboundKind::Pairwise as i32);
    assert_eq!(wrapped.relay_url, "https://bob-relay.example");
}

#[test]
fn signed_group_join_request_requires_pairwise_envelope() {
    let mut bob = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(2)).unwrap();
    let request = GroupJoinRequest::create(
        &TestIdentity::new(1),
        GroupId::from_bytes([7; 32]),
        [8; 32],
        "https://relay.example",
    )
    .unwrap();
    let generation = bob.checkpoint_generation();
    assert!(matches!(
        bob.execute(
            ClientCommand::apply_group_join_request(
                "unwrapped-request",
                "join-request",
                request.encode(),
            )
            .unwrap(),
        ),
        Err(Error::InvalidSignature)
    ));
    assert_eq!(bob.checkpoint_generation(), generation);
}

#[test]
fn inbound_pairwise_rejects_an_unregistered_olm_key_for_a_known_root() {
    let mut original =
        PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(1)).unwrap();
    let mut replacement =
        PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(1)).unwrap();
    let mut bob = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(2)).unwrap();
    for client in [&mut original, &mut replacement, &mut bob] {
        client
            .execute(ClientCommand::ensure_pairwise_account("account").unwrap())
            .unwrap();
    }
    let original_bundle =
        wire_proto::ClientSnapshot::decode(original.snapshot().unwrap().encode().as_slice())
            .unwrap()
            .pairwise_prekey_bundle;
    let bob_bundle =
        wire_proto::ClientSnapshot::decode(bob.snapshot().unwrap().encode().as_slice())
            .unwrap()
            .pairwise_prekey_bundle;
    bob.execute(
        ClientCommand::register_pairwise_contact(
            "register",
            original_bundle,
            "https://alice-relay.example",
        )
        .unwrap(),
    )
    .unwrap();
    replacement
        .execute(
            ClientCommand::register_pairwise_contact(
                "register",
                bob_bundle,
                "https://bob-relay.example",
            )
            .unwrap(),
        )
        .unwrap();
    let draft = replacement.execute(create_group()).unwrap();
    let request = draft
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.destination == TestIdentity::new(2).root_public())
        .unwrap();
    let before = bob.snapshot().unwrap().encode();
    let result = bob.execute(
        ClientCommand::apply_pairwise_control("unexpected-account", request.payload).unwrap(),
    );
    assert!(matches!(result, Err(Error::InvalidSignature)));
    assert_eq!(bob.snapshot().unwrap().encode(), before);
}

struct CheckpointFixtureStore {
    checkpoint: Option<pigeon_core::SealedCheckpoint>,
}

impl CheckpointFixtureStore {
    fn from_checkpoint(checkpoint: pigeon_core::SealedCheckpoint) -> Self {
        Self {
            checkpoint: Some(checkpoint),
        }
    }
}

impl StateStore for CheckpointFixtureStore {
    fn load(&self) -> Result<Option<pigeon_core::SealedCheckpoint>, pigeon_core::StorageError> {
        Ok(self.checkpoint.clone())
    }

    fn replace(
        &mut self,
        expected_generation: u64,
        next: pigeon_core::SealedCheckpoint,
    ) -> Result<(), pigeon_core::StorageError> {
        let current = self
            .checkpoint
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.generation);
        if current != expected_generation || next.generation != expected_generation + 1 {
            return Err(pigeon_core::StorageError::Conflict);
        }
        self.checkpoint = Some(next);
        Ok(())
    }
}

#[test]
fn checkpoint_rejects_unbounded_idempotency_history() {
    let mut client = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(1)).unwrap();
    client
        .execute(ClientCommand::ensure_pairwise_account("seed-checkpoint").unwrap())
        .unwrap();
    let checkpoint = client.store().load().unwrap().unwrap();
    let mut state = wire_proto::ClientCheckpoint::decode(checkpoint.bytes.as_slice()).unwrap();
    state.applied_command_ids = (0..=pigeon_core::MAX_PENDING_OUTBOUND_ENTRIES)
        .map(|index| format!("command-{index}"))
        .collect();
    let bytes = state.encode_to_vec();
    let oversized = pigeon_core::SealedCheckpoint {
        generation: state.generation,
        sha256: Sha256::digest(&bytes).into(),
        bytes,
    };

    let result = PigeonClient::new(
        CheckpointFixtureStore::from_checkpoint(oversized),
        TestIdentity::new(1),
    );

    assert!(matches!(
        result,
        Err(Error::Persistence(pigeon_core::StorageError::Corrupt))
    ));
}

#[test]
fn output_is_released_only_after_the_checkpoint_advances() {
    let (mut client, _, _) = group_clients();
    let previous_generation = client.checkpoint_generation();

    let output = client.execute(create_group()).unwrap();

    assert_eq!(output.checkpoint_generation, previous_generation + 1);
    assert!(output.events.is_empty());
    assert_eq!(output.outbound.len(), 2);
    assert_eq!(client.checkpoint_generation(), previous_generation + 1);
    assert_eq!(
        client.store().load().unwrap().unwrap().generation,
        previous_generation + 1
    );
}

#[test]
fn owner_only_group_is_created_and_durable_in_one_transaction() {
    let mut client = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(1)).unwrap();
    let command = ClientCommand::create_group(
        "owner-only",
        "Open Event",
        vec![],
        "https://relay.example",
        TestIdentity::new(60).root_public(),
        false,
    )
    .unwrap();
    let output = client.execute(command).unwrap();
    assert_eq!(output.checkpoint_generation, 1);
    assert_eq!(output.outbound.len(), 1);
    assert_eq!(
        wire_proto::OutboundItem::decode(output.outbound[0].encode().as_slice())
            .unwrap()
            .kind,
        wire_proto::OutboundKind::GroupRelayRegistration as i32
    );
    assert_eq!(output.events.len(), 1);
    let checkpoint = client.store().load().unwrap().unwrap();
    let state = wire_proto::ClientCheckpoint::decode(checkpoint.bytes.as_slice()).unwrap();
    assert_eq!(state.groups.len(), 1);
    assert!(state.pending_group_creations.is_empty());
}

#[test]
fn final_join_material_atomically_creates_the_real_mls_group() {
    let (mut client, mut bob, mut carol) = group_clients();

    let pending = client.execute(create_group()).unwrap();
    assert!(pending.events.is_empty());
    assert_eq!(pending.outbound.len(), 2);
    let bob_material = receive_group_control(&mut bob, "bob-material", &pending.outbound[0]);
    let carol_material = receive_group_control(&mut carol, "carol-material", &pending.outbound[1]);

    let one = client
        .execute(
            ClientCommand::apply_pairwise_control(
                "command-2",
                wire_proto::OutboundItem::decode(bob_material.outbound[0].encode().as_slice())
                    .unwrap()
                    .payload,
            )
            .unwrap(),
        )
        .unwrap();
    assert!(one.events.is_empty());
    assert!(one.outbound.is_empty());

    let created = client
        .execute(
            ClientCommand::apply_pairwise_control(
                "command-3",
                wire_proto::OutboundItem::decode(carol_material.outbound[0].encode().as_slice())
                    .unwrap()
                    .payload,
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        created.checkpoint_generation,
        pending.checkpoint_generation + 2
    );
    assert_eq!(created.events.len(), 1);
    assert_eq!(created.outbound.len(), 4);
    let event = wire_proto::AppEvent::decode(created.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupCreated(group) = event.body.unwrap() else {
        panic!("final join material must emit GroupCreated");
    };
    assert_eq!(group.owner_identity, TestIdentity::new(1).root_public());
    assert_eq!(group.name, "Friends");
    assert_eq!(group.epoch, 1);
    assert_eq!(group.policy_revision, 0);
    let outbound: Vec<_> = created
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .collect();
    let registration_item = outbound
        .iter()
        .find(|item| item.item_id.ends_with(":register"))
        .unwrap();
    assert_eq!(
        registration_item.kind,
        wire_proto::OutboundKind::GroupRelayRegistration as i32
    );
    let registration = GroupRelayRegistration::decode(&registration_item.payload).unwrap();
    registration.verify().unwrap();
    assert_eq!(registration.capabilities().len(), 3);
    assert_eq!(
        registration
            .capabilities()
            .iter()
            .filter(|capability| capability.can_control())
            .count(),
        1
    );
    let coordinator = outbound
        .iter()
        .find(|item| item.item_id.ends_with(":coordinate"))
        .unwrap();
    assert_eq!(
        coordinator.kind,
        wire_proto::OutboundKind::GroupCoordinator as i32
    );
    assert_ne!(coordinator.payload, registration_item.payload);
    assert_eq!(
        client.checkpoint_generation(),
        created.checkpoint_generation
    );
}

#[test]
fn snapshot_rebuilds_group_projection_without_advancing_checkpoint() {
    let anchored = create_anchored_group();
    let generation = anchored.owner.checkpoint_generation();

    let snapshot =
        wire_proto::ClientSnapshot::decode(anchored.owner.snapshot().unwrap().encode().as_slice())
            .unwrap();

    assert_eq!(snapshot.checkpoint_generation, generation);
    assert_eq!(anchored.owner.checkpoint_generation(), generation);
    assert_eq!(snapshot.groups.len(), 1);
    let group = &snapshot.groups[0];
    assert_eq!(group.group_id, anchored.group_id.as_bytes());
    assert_eq!(group.owner_identity, TestIdentity::new(1).root_public());
    assert_eq!(
        group.admin_identities,
        vec![TestIdentity::new(1).root_public()]
    );
    assert_eq!(group.member_identities.len(), 3);
    assert_eq!(group.name, "Friends");
    assert_eq!(group.relay_url, "https://relay.example");
    assert_eq!(group.coordination_id, anchored.coordination_id);
    assert_eq!(group.capability_public_key.len(), 32);
    assert_eq!(group.capability_id.len(), 32);
    assert_eq!(
        group.coordinator_public_key,
        TestIdentity::new(60).root_public()
    );
    assert_eq!(group.epoch, 1);
    assert_eq!(group.policy_revision, 0);
    assert!(!group.mesh_enabled);
    assert!(!group.dissolved);
}

#[test]
fn relay_challenge_signature_is_bound_to_the_authenticated_group_capability() {
    let anchored = create_anchored_group();
    let nonce = [42_u8; 32];

    let signature = anchored
        .owner
        .sign_group_relay_challenge(anchored.group_id, nonce)
        .unwrap();

    let snapshot =
        wire_proto::ClientSnapshot::decode(anchored.owner.snapshot().unwrap().encode().as_slice())
            .unwrap();
    let group = &snapshot.groups[0];
    let capability_key: [u8; 32] = group.capability_public_key.as_slice().try_into().unwrap();
    let capability_id: [u8; 32] = group.capability_id.as_slice().try_into().unwrap();
    let mut transcript = b"pigeon.relay.group.challenge.v2".to_vec();
    transcript.extend_from_slice(&anchored.coordination_id);
    transcript.extend_from_slice(&capability_id);
    transcript.extend_from_slice(&nonce);

    ed25519_dalek::VerifyingKey::from_bytes(&capability_key)
        .unwrap()
        .verify_strict(
            &transcript,
            &ed25519_dalek::Signature::from_bytes(&signature),
        )
        .unwrap();
}

#[test]
fn outbound_effects_remain_in_the_snapshot_until_explicitly_acknowledged() {
    let (mut client, _, _) = group_clients();
    let output = client.execute(create_group()).unwrap();
    let first = wire_proto::OutboundItem::decode(output.outbound[0].encode().as_slice()).unwrap();

    let snapshot =
        wire_proto::ClientSnapshot::decode(client.snapshot().unwrap().encode().as_slice()).unwrap();
    assert_eq!(snapshot.pending_outbound.len(), 2);

    client
        .execute(
            ClientCommand::acknowledge_effects("ack-first", vec![first.item_id], Vec::new())
                .unwrap(),
        )
        .unwrap();
    let snapshot =
        wire_proto::ClientSnapshot::decode(client.snapshot().unwrap().encode().as_slice()).unwrap();
    assert_eq!(snapshot.pending_outbound.len(), 1);
}

#[test]
fn one_join_material_cannot_fill_two_group_drafts() {
    let (mut client, mut bob, _) = group_clients();
    let mut bob_storage = TransactionalOpenMlsStorage::new();
    client.execute(create_group()).unwrap();
    let checkpoint = client.store().load().unwrap().unwrap();
    let state = wire_proto::ClientCheckpoint::decode(checkpoint.bytes.as_slice()).unwrap();
    let draft = &state.pending_group_creations[0];
    let bob_material = GroupJoinMaterial::issue(
        &TestIdentity::new(2),
        TestIdentity::new(1).root_public(),
        GroupId::from_bytes(draft.group_id.as_slice().try_into().unwrap()),
        draft.coordination_id.as_slice().try_into().unwrap(),
        &mut bob_storage,
    )
    .unwrap();
    client
        .execute(
            ClientCommand::create_group(
                "other-group",
                "Other Friends",
                vec![
                    TestIdentity::new(2).root_public(),
                    TestIdentity::new(3).root_public(),
                ],
                "https://relay.example",
                TestIdentity::new(60).root_public(),
                false,
            )
            .unwrap(),
        )
        .unwrap();
    let first_wrapped = bob
        .execute(
            ClientCommand::send_pairwise_control(
                "first-wrapper",
                TestIdentity::new(1).root_public(),
                wire_proto::OutboundKind::GroupJoinMaterial,
                bob_material.encode(),
            )
            .unwrap(),
        )
        .unwrap();
    receive_group_control(&mut client, "first-response", &first_wrapped.outbound[0]);
    let generation = client.checkpoint_generation();

    let replay_wrapped = bob
        .execute(
            ClientCommand::send_pairwise_control(
                "second-wrapper",
                TestIdentity::new(1).root_public(),
                wire_proto::OutboundKind::GroupJoinMaterial,
                bob_material.encode(),
            )
            .unwrap(),
        )
        .unwrap();
    let replay = client.execute(
        ClientCommand::apply_pairwise_control(
            "replayed-response",
            wire_proto::OutboundItem::decode(replay_wrapped.outbound[0].encode().as_slice())
                .unwrap()
                .payload,
        )
        .unwrap(),
    );

    assert!(matches!(replay, Err(Error::InvalidSignature)));
    assert_eq!(client.checkpoint_generation(), generation);
}

#[test]
fn member_issues_join_material_only_after_its_checkpoint_advances() {
    let (mut creator_client, mut member_client, _) = group_clients();
    let pending = creator_client.execute(create_group()).unwrap();
    let prior_generation = member_client.checkpoint_generation();

    let response =
        receive_group_control(&mut member_client, "member-response", &pending.outbound[0]);

    assert_eq!(response.checkpoint_generation, prior_generation + 1);
    assert_eq!(member_client.checkpoint_generation(), prior_generation + 1);
    assert!(response.events.is_empty());
    assert_eq!(response.outbound.len(), 1);
    let material =
        wire_proto::OutboundItem::decode(response.outbound[0].encode().as_slice()).unwrap();
    assert_eq!(material.kind, wire_proto::OutboundKind::Pairwise as i32);
    assert_eq!(material.destination, TestIdentity::new(1).root_public());
    let accepted = receive_group_control(
        &mut creator_client,
        "owner-receives-material",
        &response.outbound[0],
    );
    assert!(accepted.events.is_empty());
}

#[test]
fn policy_change_persists_before_releasing_a_coordinator_submission() {
    let anchored = create_anchored_group();
    let mut client = anchored.owner;
    let group_id = anchored.group_id;
    let coordination_id = anchored.coordination_id;
    let prior_generation = client.checkpoint_generation();

    let staged = client
        .execute(ClientCommand::rename_group("rename-1", group_id, "Best Friends").unwrap())
        .unwrap();

    assert_eq!(staged.checkpoint_generation, prior_generation + 1);
    assert!(staged.events.is_empty());
    assert_eq!(staged.outbound.len(), 1);
    let outbound =
        wire_proto::OutboundItem::decode(staged.outbound[0].encode().as_slice()).unwrap();
    assert_eq!(
        outbound.kind,
        wire_proto::OutboundKind::GroupCoordinator as i32
    );
    let submission =
        wire_proto::GroupCoordinatorSubmission::decode(outbound.payload.as_slice()).unwrap();
    assert_eq!(submission.claimed_base_epoch, 1);
    assert!(!submission.candidate.is_empty());
    assert!(
        client
            .execute(
                ClientCommand::rename_group("rename-while-pending", group_id, "Other").unwrap()
            )
            .is_err()
    );
    assert_eq!(client.checkpoint_generation(), prior_generation + 1);

    let canonical = coordinator_candidate(&submission, 2, anchored.receipt_head, coordination_id);
    let merged = client
        .execute(
            ClientCommand::apply_group_coordinator_candidate("rename-receipt", canonical).unwrap(),
        )
        .unwrap();
    assert_eq!(merged.checkpoint_generation, prior_generation + 2);
    assert!(merged.events.is_empty());
    assert_eq!(merged.outbound.len(), 1);
    let control = wire_proto::OutboundItem::decode(merged.outbound[0].encode().as_slice()).unwrap();
    assert_eq!(
        control.kind,
        wire_proto::OutboundKind::GroupRelayControl as i32
    );
    let acknowledged = client
        .execute(
            ClientCommand::acknowledge_effects(
                "ack-rename-relay-control",
                vec![control.item_id],
                Vec::new(),
            )
            .unwrap(),
        )
        .unwrap();
    let event = wire_proto::AppEvent::decode(acknowledged.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupPolicyChanged(change) = event.body.unwrap() else {
        panic!("expected canonical policy event");
    };
    assert_eq!(
        change.kind,
        wire_proto::GroupPolicyChangeKind::NameChanged as i32
    );
    assert_eq!(change.name, "Best Friends");
    assert_eq!(change.epoch, 2);
    assert_eq!(change.policy_revision, 1);
}

#[test]
fn coordinator_equivocation_is_durably_frozen_and_reported() {
    let anchored = create_anchored_group();
    let mut client = anchored.owner;
    let coordination_id = anchored.coordination_id;
    let accepted = anchored.initial_candidate;
    let fork_submission = wire_proto::GroupCoordinatorSubmission {
        version: 1,
        claimed_base_epoch: 0,
        candidate: GroupMutationCandidate::new(Vec::new(), b"conflicting commit".to_vec())
            .unwrap()
            .encode(),
    };
    let fork = coordinator_candidate(&fork_submission, 1, [0; 32], coordination_id);
    let generation = client.checkpoint_generation();

    let frozen = client
        .execute(ClientCommand::apply_group_coordinator_candidate("observe-fork", fork).unwrap())
        .unwrap();

    assert_eq!(frozen.checkpoint_generation, generation + 1);
    assert_eq!(frozen.events.len(), 1);
    assert!(frozen.outbound.is_empty());
    let event = wire_proto::AppEvent::decode(frozen.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupSecurityWarning(warning) = event.body.unwrap() else {
        panic!("expected coordinator security warning");
    };
    assert_eq!(warning.code, 1);
    assert_eq!(warning.epoch, 1);

    assert!(
        client
            .execute(
                ClientCommand::apply_group_coordinator_candidate("candidate-after-fork", accepted,)
                    .unwrap(),
            )
            .is_err()
    );
    assert_eq!(client.checkpoint_generation(), generation + 1);
}

#[test]
fn membership_changes_release_relay_controls_and_welcome_only_after_canonical_merge() {
    let anchored = create_anchored_group();
    let mut owner_client = anchored.owner;
    let group_id = anchored.group_id;
    let coordination_id = anchored.coordination_id;
    let receipt_head = anchored.receipt_head;
    let mut dave_client =
        PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(4)).unwrap();
    register_pairwise_peers(&mut owner_client, &mut dave_client, "membership-dave");
    let invited = owner_client
        .execute(
            ClientCommand::add_group_member(
                "invite-dave",
                group_id,
                TestIdentity::new(4).root_public(),
            )
            .unwrap(),
        )
        .unwrap();
    assert!(invited.events.is_empty());
    assert_eq!(invited.outbound.len(), 1);
    let request =
        wire_proto::OutboundItem::decode(invited.outbound[0].encode().as_slice()).unwrap();
    assert_eq!(request.kind, wire_proto::OutboundKind::Pairwise as i32);
    assert_eq!(request.destination, TestIdentity::new(4).root_public());

    let response = dave_client
        .execute(ClientCommand::apply_pairwise_control("dave-material", request.payload).unwrap())
        .unwrap();
    let material =
        wire_proto::OutboundItem::decode(response.outbound[0].encode().as_slice()).unwrap();
    let staged = owner_client
        .execute(
            ClientCommand::apply_pairwise_control("apply-dave-material", material.payload).unwrap(),
        )
        .unwrap();
    assert!(staged.events.is_empty());
    assert_eq!(staged.outbound.len(), 1);
    let submission_item =
        wire_proto::OutboundItem::decode(staged.outbound[0].encode().as_slice()).unwrap();
    let submission =
        wire_proto::GroupCoordinatorSubmission::decode(submission_item.payload.as_slice()).unwrap();
    let canonical = coordinator_candidate(&submission, 2, receipt_head, coordination_id);
    let second_receipt_head = CoordinatorReceipt::decode_candidate(&canonical)
        .unwrap()
        .0
        .receipt_hash();

    let before_merge =
        wire_proto::ClientSnapshot::decode(owner_client.snapshot().unwrap().encode().as_slice())
            .unwrap();
    let prior_capability_id = before_merge.groups[0].capability_id.clone();

    let merged = owner_client
        .execute(ClientCommand::apply_group_coordinator_candidate("merge-dave", canonical).unwrap())
        .unwrap();
    assert!(merged.events.is_empty());
    assert_eq!(merged.outbound.len(), 2);
    let outbound: Vec<_> = merged
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .collect();
    let control_item = outbound
        .iter()
        .find(|item| item.kind == wire_proto::OutboundKind::GroupRelayControl as i32)
        .unwrap();
    let control = GroupRelayControl::decode(&control_item.payload).unwrap();
    assert_eq!(control.kind(), GroupRelayControlKind::ReplaceAll);
    assert!(control.capabilities().iter().any(|capability| {
        capability.public_key() == TestIdentity::new(4).capability.verifying_key().to_bytes()
    }));
    let before_control_ack =
        wire_proto::ClientSnapshot::decode(owner_client.snapshot().unwrap().encode().as_slice())
            .unwrap();
    assert_eq!(
        before_control_ack.groups[0].capability_id,
        prior_capability_id
    );

    let acknowledged = owner_client
        .execute(
            ClientCommand::acknowledge_effects(
                "ack-add-relay-control",
                vec![control_item.item_id.clone()],
                Vec::new(),
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(acknowledged.events.len(), 1);
    let event = wire_proto::AppEvent::decode(acknowledged.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupPolicyChanged(change) = event.body.unwrap() else {
        panic!("expected member-added policy event");
    };
    assert_eq!(
        change.kind,
        wire_proto::GroupPolicyChangeKind::MemberAdded as i32
    );
    assert_eq!(change.subject_identity, TestIdentity::new(4).root_public());
    let after_control_ack =
        wire_proto::ClientSnapshot::decode(owner_client.snapshot().unwrap().encode().as_slice())
            .unwrap();
    assert_ne!(
        after_control_ack.groups[0].capability_id,
        prior_capability_id
    );

    let welcome = outbound
        .iter()
        .find(|item| {
            item.kind == wire_proto::OutboundKind::Pairwise as i32
                && item.destination == TestIdentity::new(4).root_public()
        })
        .unwrap();
    assert_eq!(welcome.destination, TestIdentity::new(4).root_public());
    let joined = dave_client
        .execute(
            ClientCommand::apply_pairwise_control("join-dave", welcome.payload.clone()).unwrap(),
        )
        .unwrap();
    assert_eq!(joined.events.len(), 1);

    let staged_remove = owner_client
        .execute(
            ClientCommand::remove_group_member(
                "remove-dave",
                group_id,
                TestIdentity::new(4).root_public(),
            )
            .unwrap(),
        )
        .unwrap();
    assert!(staged_remove.events.is_empty());
    let remove_item =
        wire_proto::OutboundItem::decode(staged_remove.outbound[0].encode().as_slice()).unwrap();
    let remove_submission =
        wire_proto::GroupCoordinatorSubmission::decode(remove_item.payload.as_slice()).unwrap();
    let canonical_remove =
        coordinator_candidate(&remove_submission, 3, second_receipt_head, coordination_id);
    let removed = owner_client
        .execute(
            ClientCommand::apply_group_coordinator_candidate("merge-remove", canonical_remove)
                .unwrap(),
        )
        .unwrap();
    assert!(removed.events.is_empty());
    let revoke_item = removed
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupRelayControl as i32)
        .unwrap();
    let revoke = GroupRelayControl::decode(&revoke_item.payload).unwrap();
    assert_eq!(revoke.kind(), GroupRelayControlKind::ReplaceAll);
    assert!(!revoke.capabilities().iter().any(|capability| {
        capability.public_key() == TestIdentity::new(4).capability.verifying_key().to_bytes()
    }));
    let acknowledged = owner_client
        .execute(
            ClientCommand::acknowledge_effects(
                "ack-remove-relay-control",
                vec![revoke_item.item_id],
                Vec::new(),
            )
            .unwrap(),
        )
        .unwrap();
    let event = wire_proto::AppEvent::decode(acknowledged.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupPolicyChanged(change) = event.body.unwrap() else {
        panic!("expected member-removed policy event");
    };
    assert_eq!(
        change.kind,
        wire_proto::GroupPolicyChangeKind::MemberRemoved as i32
    );
}

#[test]
fn ordinary_member_leave_is_committed_by_an_online_admin() {
    let group = create_group_with_dave();
    let mut owner = group.owner;
    let mut dave = group.dave;
    let group_id = group.group_id;
    let coordination_id = group.coordination_id;
    let receipt_head = group.receipt_head;
    let owner_pending =
        wire_proto::ClientSnapshot::decode(owner.snapshot().unwrap().encode().as_slice())
            .unwrap()
            .pending_outbound
            .into_iter()
            .map(|item| item.item_id)
            .collect();
    owner
        .execute(
            ClientCommand::acknowledge_effects(
                "clear-owner-fixture-effects",
                owner_pending,
                Vec::new(),
            )
            .unwrap(),
        )
        .unwrap();
    let dave_pending =
        wire_proto::ClientSnapshot::decode(dave.snapshot().unwrap().encode().as_slice())
            .unwrap()
            .pending_outbound
            .into_iter()
            .map(|item| item.item_id)
            .collect();
    dave.execute(
        ClientCommand::acknowledge_effects("clear-dave-fixture-effects", dave_pending, Vec::new())
            .unwrap(),
    )
    .unwrap();
    owner
        .execute(ClientCommand::ensure_pairwise_account("owner-pairwise-account").unwrap())
        .unwrap();
    dave.execute(ClientCommand::ensure_pairwise_account("dave-pairwise-account").unwrap())
        .unwrap();
    let owner_prekey =
        wire_proto::ClientSnapshot::decode(owner.snapshot().unwrap().encode().as_slice())
            .unwrap()
            .pairwise_prekey_bundle;
    let dave_prekey =
        wire_proto::ClientSnapshot::decode(dave.snapshot().unwrap().encode().as_slice())
            .unwrap()
            .pairwise_prekey_bundle;
    owner
        .execute(
            ClientCommand::register_pairwise_contact(
                "owner-registers-dave",
                dave_prekey,
                "https://dave-relay.example",
            )
            .unwrap(),
        )
        .unwrap();
    dave.execute(
        ClientCommand::register_pairwise_contact(
            "dave-registers-owner",
            owner_prekey,
            "https://owner-relay.example",
        )
        .unwrap(),
    )
    .unwrap();

    let proposed = dave
        .execute(ClientCommand::leave_group("dave-leaves", group_id).unwrap())
        .unwrap();
    assert!(proposed.events.is_empty());
    assert_eq!(proposed.outbound.len(), 1);
    let proposal =
        wire_proto::OutboundItem::decode(proposed.outbound[0].encode().as_slice()).unwrap();
    assert_eq!(proposal.kind, wire_proto::OutboundKind::Pairwise as i32);
    assert_eq!(proposal.destination, TestIdentity::new(1).root_public());
    let pending_leave =
        wire_proto::ClientSnapshot::decode(dave.snapshot().unwrap().encode().as_slice()).unwrap();
    assert!(pending_leave.groups[0].local_leave_pending);

    let staged = owner
        .execute(
            ClientCommand::apply_pairwise_control("owner-commits-leave", proposal.payload).unwrap(),
        )
        .unwrap();
    assert!(staged.events.is_empty());
    assert_eq!(staged.outbound.len(), 1);
    let submission_item =
        wire_proto::OutboundItem::decode(staged.outbound[0].encode().as_slice()).unwrap();
    let submission =
        wire_proto::GroupCoordinatorSubmission::decode(submission_item.payload.as_slice()).unwrap();
    let mutation = GroupMutationCandidate::decode(&submission.candidate).unwrap();
    assert_eq!(mutation.proposals().len(), 1);

    let canonical = coordinator_candidate(&submission, 3, receipt_head, coordination_id);
    let merged = owner
        .execute(
            ClientCommand::apply_group_coordinator_candidate("merge-dave-leave", canonical.clone())
                .unwrap(),
        )
        .unwrap();
    assert!(merged.events.is_empty());
    let revoke_item = merged
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupRelayControl as i32)
        .unwrap();
    let revoke = GroupRelayControl::decode(&revoke_item.payload).unwrap();
    assert_eq!(revoke.kind(), GroupRelayControlKind::ReplaceAll);
    assert!(!revoke.capabilities().iter().any(|capability| {
        capability.public_key() == TestIdentity::new(4).capability.verifying_key().to_bytes()
    }));
    let acknowledged = owner
        .execute(
            ClientCommand::acknowledge_effects(
                "ack-leave-relay-control",
                vec![revoke_item.item_id],
                Vec::new(),
            )
            .unwrap(),
        )
        .unwrap();
    let event = wire_proto::AppEvent::decode(acknowledged.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupPolicyChanged(change) = event.body.unwrap() else {
        panic!("expected member-left policy event");
    };
    assert_eq!(
        change.kind,
        wire_proto::GroupPolicyChangeKind::MemberLeft as i32
    );
    assert_eq!(change.subject_identity, TestIdentity::new(4).root_public());
    let departed = dave
        .execute(
            ClientCommand::apply_group_coordinator_candidate("observe-own-leave", canonical)
                .unwrap(),
        )
        .unwrap();
    assert_eq!(departed.events.len(), 1);
    assert!(departed.outbound.is_empty());
    let departed_snapshot =
        wire_proto::ClientSnapshot::decode(dave.snapshot().unwrap().encode().as_slice()).unwrap();
    assert!(!departed_snapshot.groups[0].local_leave_pending);
}
