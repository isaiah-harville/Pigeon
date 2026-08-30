use ed25519_dalek::{Signer, SigningKey};
use pigeon_core::{
    ClientCommand, CoordinatorReceipt, Error, GroupId, GroupJoinMaterial, GroupJoinRequest,
    GroupRelayControl, GroupRelayControlKind, GroupRelayRegistration, IdentityError,
    IdentityPurpose, MemoryStateStore, PigeonClient, SecureIdentity, StateStore,
    TransactionalOpenMlsStorage, coordinator_receipt_transcript, wire_proto,
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

fn issue_join_material(
    request: &wire_proto::OutboundItem,
    member: &TestIdentity,
    storage: &mut TransactionalOpenMlsStorage,
) -> GroupJoinMaterial {
    assert_eq!(
        request.kind,
        wire_proto::OutboundKind::GroupJoinRequest as i32
    );
    assert_eq!(request.destination, member.root_public());
    let request = GroupJoinRequest::decode(&request.payload).unwrap();
    GroupJoinMaterial::issue(
        member,
        request.requester_identity(),
        request.group_id(),
        request.coordination_id(),
        storage,
    )
    .unwrap()
}

fn coordinator_candidate(
    submission: &wire_proto::GroupCoordinatorSubmission,
    sequence: u64,
    prior_receipt_hash: [u8; 32],
    coordination_id: [u8; 32],
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
            signature: TestIdentity::new(60)
                .root
                .sign(&transcript)
                .to_bytes()
                .to_vec(),
        }),
        candidate: submission.candidate.clone(),
    }
    .encode_to_vec()
}

fn create_anchored_group() -> (
    PigeonClient<MemoryStateStore, TestIdentity>,
    GroupId,
    [u8; 32],
    [u8; 32],
) {
    let mut client = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(1)).unwrap();
    let pending = client.execute(create_group()).unwrap();
    let requests: Vec<_> = pending
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .collect();
    let mut bob_storage = TransactionalOpenMlsStorage::new();
    let mut carol_storage = TransactionalOpenMlsStorage::new();
    let bob_material = issue_join_material(&requests[0], &TestIdentity::new(2), &mut bob_storage);
    let carol_material =
        issue_join_material(&requests[1], &TestIdentity::new(3), &mut carol_storage);
    client
        .execute(
            ClientCommand::apply_group_join_material(
                "anchor-material-1",
                "command-1:join:0",
                bob_material.encode(),
            )
            .unwrap(),
        )
        .unwrap();
    let created = client
        .execute(
            ClientCommand::apply_group_join_material(
                "anchor-material-2",
                "command-1:join:1",
                carol_material.encode(),
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
            ClientCommand::apply_group_coordinator_candidate("anchor-receipt", candidate).unwrap(),
        )
        .unwrap();
    (client, group_id, coordination_id, receipt_hash)
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
fn output_is_released_only_after_the_checkpoint_advances() {
    let store = MemoryStateStore::default();
    let mut client = PigeonClient::new(store, TestIdentity::new(1)).unwrap();

    let output = client.execute(create_group()).unwrap();

    assert_eq!(output.checkpoint_generation, 1);
    assert!(output.events.is_empty());
    assert_eq!(output.outbound.len(), 2);
    assert_eq!(client.checkpoint_generation(), 1);
    assert_eq!(client.store().load().unwrap().unwrap().generation, 1);
}

#[test]
fn final_join_material_atomically_creates_the_real_mls_group() {
    let owner = TestIdentity::new(1);
    let bob = TestIdentity::new(2);
    let carol = TestIdentity::new(3);
    let mut bob_storage = TransactionalOpenMlsStorage::new();
    let mut carol_storage = TransactionalOpenMlsStorage::new();
    let mut client = PigeonClient::new(MemoryStateStore::default(), owner).unwrap();

    let pending = client.execute(create_group()).unwrap();
    assert!(pending.events.is_empty());
    assert_eq!(pending.outbound.len(), 2);
    let requests: Vec<_> = pending
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .collect();
    let bob_material = issue_join_material(&requests[0], &bob, &mut bob_storage);
    let carol_material = issue_join_material(&requests[1], &carol, &mut carol_storage);

    let one = client
        .execute(
            ClientCommand::apply_group_join_material(
                "command-2",
                "command-1:join:0",
                bob_material.encode(),
            )
            .unwrap(),
        )
        .unwrap();
    assert!(one.events.is_empty());
    assert!(one.outbound.is_empty());

    let created = client
        .execute(
            ClientCommand::apply_group_join_material(
                "command-3",
                "command-1:join:1",
                carol_material.encode(),
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(created.checkpoint_generation, 3);
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
    assert_eq!(client.checkpoint_generation(), 3);
}

#[test]
fn one_join_material_cannot_fill_two_group_drafts() {
    let owner = TestIdentity::new(1);
    let bob = TestIdentity::new(2);
    let mut bob_storage = TransactionalOpenMlsStorage::new();
    let mut client = PigeonClient::new(MemoryStateStore::default(), owner).unwrap();
    let first = client.execute(create_group()).unwrap();
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
    let first_request =
        wire_proto::OutboundItem::decode(first.outbound[0].encode().as_slice()).unwrap();
    let bob_material = issue_join_material(&first_request, &bob, &mut bob_storage);
    client
        .execute(
            ClientCommand::apply_group_join_material(
                "first-response",
                "command-1:join:0",
                bob_material.encode(),
            )
            .unwrap(),
        )
        .unwrap();

    let replay = client.execute(
        ClientCommand::apply_group_join_material(
            "replayed-response",
            "other-group:join:0",
            bob_material.encode(),
        )
        .unwrap(),
    );

    assert!(matches!(replay, Err(Error::InvalidSignature)));
    assert_eq!(client.checkpoint_generation(), 3);
}

#[test]
fn member_issues_join_material_only_after_its_checkpoint_advances() {
    let creator = TestIdentity::new(1);
    let member = TestIdentity::new(2);
    let mut creator_client = PigeonClient::new(MemoryStateStore::default(), creator).unwrap();
    let pending = creator_client.execute(create_group()).unwrap();
    let request =
        wire_proto::OutboundItem::decode(pending.outbound[0].encode().as_slice()).unwrap();
    let mut member_client = PigeonClient::new(MemoryStateStore::default(), member).unwrap();

    let response = member_client
        .execute(
            ClientCommand::apply_group_join_request(
                "member-response",
                request.item_id,
                request.payload,
            )
            .unwrap(),
        )
        .unwrap();

    assert_eq!(response.checkpoint_generation, 1);
    assert_eq!(member_client.checkpoint_generation(), 1);
    assert!(response.events.is_empty());
    assert_eq!(response.outbound.len(), 1);
    let material =
        wire_proto::OutboundItem::decode(response.outbound[0].encode().as_slice()).unwrap();
    assert_eq!(
        material.kind,
        wire_proto::OutboundKind::GroupJoinMaterial as i32
    );
    assert_eq!(material.destination, TestIdentity::new(1).root_public());
    assert!(GroupJoinMaterial::decode(&material.payload).is_ok());
}

#[test]
fn policy_change_persists_before_releasing_a_coordinator_submission() {
    let owner = TestIdentity::new(1);
    let bob = TestIdentity::new(2);
    let carol = TestIdentity::new(3);
    let mut bob_storage = TransactionalOpenMlsStorage::new();
    let mut carol_storage = TransactionalOpenMlsStorage::new();
    let mut client = PigeonClient::new(MemoryStateStore::default(), owner).unwrap();
    let pending = client.execute(create_group()).unwrap();
    let requests: Vec<_> = pending
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .collect();
    let bob_material = issue_join_material(&requests[0], &bob, &mut bob_storage);
    let carol_material = issue_join_material(&requests[1], &carol, &mut carol_storage);
    client
        .execute(
            ClientCommand::apply_group_join_material(
                "material-1",
                "command-1:join:0",
                bob_material.encode(),
            )
            .unwrap(),
        )
        .unwrap();
    let created = client
        .execute(
            ClientCommand::apply_group_join_material(
                "material-2",
                "command-1:join:1",
                carol_material.encode(),
            )
            .unwrap(),
        )
        .unwrap();
    let event = wire_proto::AppEvent::decode(created.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupCreated(created_group) = event.body.unwrap() else {
        panic!("expected group creation");
    };
    let group_id = GroupId::from_bytes(created_group.group_id.try_into().unwrap());
    let initial_outbound = created
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupCoordinator as i32)
        .unwrap();
    let coordination_id: [u8; 32] = initial_outbound.destination.as_slice().try_into().unwrap();
    let initial_submission =
        wire_proto::GroupCoordinatorSubmission::decode(initial_outbound.payload.as_slice())
            .unwrap();
    let initial_candidate = coordinator_candidate(&initial_submission, 1, [0; 32], coordination_id);
    let initial_receipt = CoordinatorReceipt::decode_candidate(&initial_candidate)
        .unwrap()
        .0;
    let anchored = client
        .execute(
            ClientCommand::apply_group_coordinator_candidate("initial-receipt", initial_candidate)
                .unwrap(),
        )
        .unwrap();
    assert!(anchored.events.is_empty());
    assert!(anchored.outbound.is_empty());

    let staged = client
        .execute(ClientCommand::rename_group("rename-1", group_id, "Best Friends").unwrap())
        .unwrap();

    assert_eq!(staged.checkpoint_generation, 5);
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
    assert_eq!(client.checkpoint_generation(), 5);

    let canonical = coordinator_candidate(
        &submission,
        2,
        initial_receipt.receipt_hash(),
        coordination_id,
    );
    let merged = client
        .execute(
            ClientCommand::apply_group_coordinator_candidate("rename-receipt", canonical).unwrap(),
        )
        .unwrap();
    assert_eq!(merged.checkpoint_generation, 6);
    assert_eq!(merged.events.len(), 1);
    assert!(merged.outbound.is_empty());
    let event = wire_proto::AppEvent::decode(merged.events[0].encode().as_slice()).unwrap();
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
fn added_member_is_granted_relay_access_and_welcome_only_after_canonical_merge() {
    let (mut owner_client, group_id, coordination_id, receipt_head) = create_anchored_group();
    let dave = TestIdentity::new(4);
    let invited = owner_client
        .execute(
            ClientCommand::add_group_member("invite-dave", group_id, dave.root_public()).unwrap(),
        )
        .unwrap();
    assert!(invited.events.is_empty());
    assert_eq!(invited.outbound.len(), 1);
    let request =
        wire_proto::OutboundItem::decode(invited.outbound[0].encode().as_slice()).unwrap();
    assert_eq!(
        request.kind,
        wire_proto::OutboundKind::GroupJoinRequest as i32
    );
    assert_eq!(request.destination, dave.root_public());

    let mut dave_client = PigeonClient::new(MemoryStateStore::default(), dave).unwrap();
    let response = dave_client
        .execute(
            ClientCommand::apply_group_join_request(
                "dave-material",
                request.item_id.clone(),
                request.payload,
            )
            .unwrap(),
        )
        .unwrap();
    let material =
        wire_proto::OutboundItem::decode(response.outbound[0].encode().as_slice()).unwrap();
    let staged = owner_client
        .execute(
            ClientCommand::apply_group_join_material(
                "apply-dave-material",
                request.item_id,
                material.payload,
            )
            .unwrap(),
        )
        .unwrap();
    assert!(staged.events.is_empty());
    assert_eq!(staged.outbound.len(), 1);
    let submission_item =
        wire_proto::OutboundItem::decode(staged.outbound[0].encode().as_slice()).unwrap();
    let submission =
        wire_proto::GroupCoordinatorSubmission::decode(submission_item.payload.as_slice()).unwrap();
    let canonical = coordinator_candidate(&submission, 2, receipt_head, coordination_id);

    let merged = owner_client
        .execute(ClientCommand::apply_group_coordinator_candidate("merge-dave", canonical).unwrap())
        .unwrap();
    assert_eq!(merged.events.len(), 1);
    let event = wire_proto::AppEvent::decode(merged.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupPolicyChanged(change) = event.body.unwrap() else {
        panic!("expected member-added policy event");
    };
    assert_eq!(
        change.kind,
        wire_proto::GroupPolicyChangeKind::MemberAdded as i32
    );
    assert_eq!(change.subject_identity, TestIdentity::new(4).root_public());
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
    assert_eq!(control.kind(), GroupRelayControlKind::Grant);
    assert_eq!(
        control.public_key(),
        TestIdentity::new(4).capability.verifying_key().to_bytes()
    );
    let welcome = outbound
        .iter()
        .find(|item| item.kind == wire_proto::OutboundKind::GroupWelcome as i32)
        .unwrap();
    assert_eq!(welcome.destination, TestIdentity::new(4).root_public());
    let joined = dave_client
        .execute(ClientCommand::apply_group_welcome("join-dave", welcome.payload.clone()).unwrap())
        .unwrap();
    assert_eq!(joined.events.len(), 1);
}
