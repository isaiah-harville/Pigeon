use ed25519_dalek::{Signer, SigningKey};
use pigeon_core::{
    ClientCommand, CoordinatorReceipt, Error, GroupId, GroupJoinMaterial, GroupJoinRequest,
    GroupMutationCandidate, GroupRelayControl, GroupRelayControlKind, GroupRelayRegistration,
    IdentityError, IdentityPurpose, MemoryStateStore, PigeonClient, SecureIdentity, StateStore,
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

struct AnchoredGroup {
    owner: PigeonClient<MemoryStateStore, TestIdentity>,
    group_id: GroupId,
    coordination_id: [u8; 32],
    receipt_head: [u8; 32],
    initial_candidate: Vec<u8>,
}

fn create_anchored_group() -> AnchoredGroup {
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
    let mut dave = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(4)).unwrap();
    let material_output = dave
        .execute(
            ClientCommand::apply_group_join_request(
                "helper-dave-material",
                request.item_id.clone(),
                request.payload,
            )
            .unwrap(),
        )
        .unwrap();
    let material =
        wire_proto::OutboundItem::decode(material_output.outbound[0].encode().as_slice()).unwrap();
    let staged = owner
        .execute(
            ClientCommand::apply_group_join_material(
                "helper-apply-dave",
                request.item_id,
                material.payload,
            )
            .unwrap(),
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
        .find(|item| item.kind == wire_proto::OutboundKind::GroupWelcome as i32)
        .unwrap();
    dave.execute(ClientCommand::apply_group_welcome("helper-join-dave", welcome.payload).unwrap())
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
    let encrypted = alice
        .execute(
            ClientCommand::send_pairwise_control(
                "encrypt-bob-request",
                TestIdentity::new(2).root_public(),
                wire_proto::OutboundKind::GroupJoinRequest,
                request.payload,
            )
            .unwrap(),
        )
        .unwrap();
    let envelope =
        wire_proto::OutboundItem::decode(encrypted.outbound[0].encode().as_slice()).unwrap();

    let decrypted = bob
        .execute(
            ClientCommand::apply_pairwise_control("bob-decrypts-request", envelope.payload)
                .unwrap(),
        )
        .unwrap();

    assert_eq!(decrypted.outbound.len(), 1);
    let material =
        wire_proto::OutboundItem::decode(decrypted.outbound[0].encode().as_slice()).unwrap();
    assert_eq!(
        material.kind,
        wire_proto::OutboundKind::GroupJoinMaterial as i32
    );
    assert_eq!(material.destination, TestIdentity::new(1).root_public());
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
    let mut transcript = b"pigeon.relay.group.challenge.v1".to_vec();
    transcript.extend_from_slice(&anchored.coordination_id);
    transcript.extend_from_slice(&capability_key);
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
    let mut client = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(1)).unwrap();
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
    let second_receipt_head = CoordinatorReceipt::decode_candidate(&canonical)
        .unwrap()
        .0
        .receipt_hash();

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
    let event = wire_proto::AppEvent::decode(removed.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupPolicyChanged(change) = event.body.unwrap() else {
        panic!("expected member-removed policy event");
    };
    assert_eq!(
        change.kind,
        wire_proto::GroupPolicyChangeKind::MemberRemoved as i32
    );
    let revoke_item =
        wire_proto::OutboundItem::decode(removed.outbound[0].encode().as_slice()).unwrap();
    let revoke = GroupRelayControl::decode(&revoke_item.payload).unwrap();
    assert_eq!(revoke.kind(), GroupRelayControlKind::Revoke);
    assert_eq!(
        revoke.public_key(),
        TestIdentity::new(4).capability.verifying_key().to_bytes()
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

    let proposed = dave
        .execute(ClientCommand::leave_group("dave-leaves", group_id).unwrap())
        .unwrap();
    assert!(proposed.events.is_empty());
    assert_eq!(proposed.outbound.len(), 1);
    let proposal =
        wire_proto::OutboundItem::decode(proposed.outbound[0].encode().as_slice()).unwrap();
    assert_eq!(
        proposal.kind,
        wire_proto::OutboundKind::GroupLeaveProposal as i32
    );
    let leave = wire_proto::GroupLeaveProposal::decode(proposal.payload.as_slice()).unwrap();
    assert_eq!(leave.departing_identity, TestIdentity::new(4).root_public());

    let staged = owner
        .execute(
            ClientCommand::apply_group_leave_proposal("owner-commits-leave", proposal.payload)
                .unwrap(),
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
    assert_eq!(mutation.proposals()[0], leave.proposal);

    let canonical = coordinator_candidate(&submission, 3, receipt_head, coordination_id);
    let merged = owner
        .execute(
            ClientCommand::apply_group_coordinator_candidate("merge-dave-leave", canonical.clone())
                .unwrap(),
        )
        .unwrap();
    let event = wire_proto::AppEvent::decode(merged.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupPolicyChanged(change) = event.body.unwrap() else {
        panic!("expected member-left policy event");
    };
    assert_eq!(
        change.kind,
        wire_proto::GroupPolicyChangeKind::MemberLeft as i32
    );
    assert_eq!(change.subject_identity, TestIdentity::new(4).root_public());
    let revoke_item =
        wire_proto::OutboundItem::decode(merged.outbound[0].encode().as_slice()).unwrap();
    let revoke = GroupRelayControl::decode(&revoke_item.payload).unwrap();
    assert_eq!(revoke.kind(), GroupRelayControlKind::Revoke);
    assert_eq!(
        revoke.public_key(),
        TestIdentity::new(4).capability.verifying_key().to_bytes()
    );

    let departed = dave
        .execute(
            ClientCommand::apply_group_coordinator_candidate("observe-own-leave", canonical)
                .unwrap(),
        )
        .unwrap();
    assert_eq!(departed.events.len(), 1);
    assert!(departed.outbound.is_empty());
}
