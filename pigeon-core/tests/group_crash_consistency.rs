use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer, SigningKey};
use pigeon_core::{
    ClientCommand, Error, GroupCiphertext, GroupId, IdentityError, IdentityPurpose, PigeonClient,
    SealedCheckpoint, SecureIdentity, StateStore, StorageError, coordinator_receipt_transcript,
    wire_proto,
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

#[derive(Clone, Default)]
struct SwitchableStore {
    state: Arc<Mutex<StoreState>>,
}

#[derive(Default)]
struct StoreState {
    checkpoint: Option<SealedCheckpoint>,
    fail_replace: bool,
}

impl SwitchableStore {
    fn set_fail_replace(&self, fail: bool) {
        self.state.lock().unwrap().fail_replace = fail;
    }
}

impl StateStore for SwitchableStore {
    fn load(&self) -> Result<Option<SealedCheckpoint>, StorageError> {
        Ok(self.state.lock().unwrap().checkpoint.clone())
    }

    fn replace(
        &mut self,
        expected_generation: u64,
        next: SealedCheckpoint,
    ) -> Result<(), StorageError> {
        let mut state = self.state.lock().unwrap();
        if state.fail_replace {
            return Err(StorageError::Unavailable);
        }
        let current = state
            .checkpoint
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.generation);
        if current != expected_generation || next.generation != expected_generation + 1 {
            return Err(StorageError::Conflict);
        }
        state.checkpoint = Some(next);
        Ok(())
    }
}

type TestClient = PigeonClient<SwitchableStore, TestIdentity>;

fn pairwise_prekey(client: &TestClient) -> Vec<u8> {
    wire_proto::ClientSnapshot::decode(client.snapshot().unwrap().encode().as_slice())
        .unwrap()
        .pairwise_prekey_bundle
}

fn register_pairwise_peers(left: &mut TestClient, right: &mut TestClient, label: &str) {
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

fn receive_control(
    recipient: &mut TestClient,
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

fn create_group_with_members(
    store: SwitchableStore,
    identity_bytes: [u8; 3],
    command_id: &str,
    name: &str,
    coordinator: [u8; 32],
    mesh_enabled: bool,
) -> (
    TestClient,
    TestClient,
    TestClient,
    pigeon_core::ClientOutput,
) {
    let [owner_byte, bob_byte, carol_byte] = identity_bytes;
    let mut owner = PigeonClient::new(store, TestIdentity::new(owner_byte)).unwrap();
    let mut bob =
        PigeonClient::new(SwitchableStore::default(), TestIdentity::new(bob_byte)).unwrap();
    let mut carol =
        PigeonClient::new(SwitchableStore::default(), TestIdentity::new(carol_byte)).unwrap();
    register_pairwise_peers(&mut owner, &mut bob, &format!("{command_id}-bob"));
    register_pairwise_peers(&mut owner, &mut carol, &format!("{command_id}-carol"));
    let pending = owner
        .execute(
            ClientCommand::create_group(
                command_id,
                name,
                vec![
                    TestIdentity::new(bob_byte).root_public(),
                    TestIdentity::new(carol_byte).root_public(),
                ],
                "https://relay.example",
                coordinator,
                mesh_enabled,
            )
            .unwrap(),
        )
        .unwrap();
    let bob_material = receive_control(
        &mut bob,
        &format!("{command_id}-bob-material"),
        &pending.outbound[0],
    );
    let carol_material = receive_control(
        &mut carol,
        &format!("{command_id}-carol-material"),
        &pending.outbound[1],
    );
    receive_control(
        &mut owner,
        &format!("{command_id}-apply-bob"),
        &bob_material.outbound[0],
    );
    let created = receive_control(
        &mut owner,
        &format!("{command_id}-apply-carol"),
        &carol_material.outbound[0],
    );
    (owner, bob, carol, created)
}

fn coordinator_candidate(
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
fn failed_send_checkpoint_releases_no_ciphertext_and_retry_is_durable() {
    let store = SwitchableStore::default();
    let (mut client, _, _, created) = create_group_with_members(
        store.clone(),
        [1, 2, 3],
        "create",
        "Birds",
        TestIdentity::new(60).root_public(),
        false,
    );
    let created_event =
        wire_proto::AppEvent::decode(created.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupCreated(created_group) = created_event.body.unwrap()
    else {
        panic!("expected GroupCreated");
    };
    let group_id = GroupId::from_bytes(created_group.group_id.try_into().unwrap());
    let send = ClientCommand::send_group_text("send-1", group_id, b"hello".to_vec(), "").unwrap();
    let generation = client.checkpoint_generation();

    store.set_fail_replace(true);
    assert!(matches!(
        client.execute(send.clone()),
        Err(Error::Persistence(_))
    ));
    assert_eq!(client.checkpoint_generation(), generation);
    assert_eq!(store.load().unwrap().unwrap().generation, generation);

    store.set_fail_replace(false);
    let output = client.execute(send).unwrap();
    assert_eq!(output.checkpoint_generation, generation + 1);
    assert_eq!(output.events.len(), 2);
    let message_event = wire_proto::AppEvent::decode(output.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupMessageReceived(message) = message_event.body.unwrap()
    else {
        panic!("expected sender-local GroupMessageReceived before delivery state");
    };
    assert_eq!(message.body, b"hello");
    assert_eq!(message.sender_identity, TestIdentity::new(1).root_public());
    let delivery_event =
        wire_proto::AppEvent::decode(output.events[1].encode().as_slice()).unwrap();
    assert!(matches!(
        delivery_event.body,
        Some(wire_proto::app_event::Body::GroupDeliveryChanged(_))
    ));
    assert_eq!(output.outbound.len(), 1);
    let outbound =
        wire_proto::OutboundItem::decode(output.outbound[0].encode().as_slice()).unwrap();
    assert_eq!(outbound.kind, wire_proto::OutboundKind::GroupMessage as i32);
    assert!(GroupCiphertext::decode(&outbound.payload).is_ok());
    assert_eq!(store.load().unwrap().unwrap().generation, generation + 1);
}

#[test]
fn failed_recovery_checkpoint_releases_no_coordinator_work_and_retry_is_durable() {
    let coordinator = TestIdentity::new(60);
    let replacement_coordinator = TestIdentity::new(61);
    let replacement_coordination_id = [92; 32];
    let store = SwitchableStore::default();
    let (mut client, _, _, created) = create_group_with_members(
        store.clone(),
        [21, 22, 23],
        "create-recovery",
        "Recovery Birds",
        coordinator.root_public(),
        false,
    );
    let created_event =
        wire_proto::AppEvent::decode(created.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupCreated(created_group) = created_event.body.unwrap()
    else {
        panic!("expected GroupCreated");
    };
    let group_id = GroupId::from_bytes(created_group.group_id.try_into().unwrap());
    let submission_item = created
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupCoordinator as i32)
        .unwrap();
    let submission =
        wire_proto::GroupCoordinatorSubmission::decode(submission_item.payload.as_slice()).unwrap();
    let coordination_id = submission_item.destination.as_slice().try_into().unwrap();
    let canonical =
        coordinator_candidate(&submission, 1, [0; 32], coordination_id, &coordinator.root);
    client
        .execute(
            ClientCommand::apply_group_coordinator_candidate("anchor-recovery", canonical).unwrap(),
        )
        .unwrap();
    let generation_before_recovery = client.checkpoint_generation();
    let command = ClientCommand::begin_group_recovery(
        "recover-after-outage",
        group_id,
        "https://replacement-relay.example",
        replacement_coordination_id,
        replacement_coordinator.root_public(),
    )
    .unwrap();

    store.set_fail_replace(true);
    assert!(matches!(
        client.execute(command.clone()),
        Err(Error::Persistence(_))
    ));
    assert_eq!(client.checkpoint_generation(), generation_before_recovery);
    assert_eq!(
        store.load().unwrap().unwrap().generation,
        generation_before_recovery
    );

    store.set_fail_replace(false);
    let recovered = client.execute(command).unwrap();
    assert_eq!(
        recovered.checkpoint_generation,
        generation_before_recovery + 1
    );
    assert!(recovered.events.is_empty());
    assert_eq!(recovered.outbound.len(), 2);
    let kinds: Vec<_> = recovered
        .outbound
        .iter()
        .map(|item| {
            wire_proto::OutboundItem::decode(item.encode().as_slice())
                .unwrap()
                .kind
        })
        .collect();
    assert!(kinds.contains(&(wire_proto::OutboundKind::GroupRelayRegistration as i32)));
    assert!(kinds.contains(&(wire_proto::OutboundKind::GroupCoordinator as i32)));
}

#[test]
fn relay_and_mesh_copies_emit_one_received_event_and_one_acknowledgement() {
    let (mut owner_client, mut bob_client, _, created) = create_group_with_members(
        SwitchableStore::default(),
        [11, 12, 13],
        "create-mesh",
        "Mesh Birds",
        TestIdentity::new(60).root_public(),
        true,
    );
    let bob_store = bob_client.store().clone();
    let welcome = created
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| {
            item.kind == wire_proto::OutboundKind::Pairwise as i32
                && item.destination == TestIdentity::new(12).root_public()
        })
        .unwrap();
    let created_event =
        wire_proto::AppEvent::decode(created.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupCreated(created_group) = created_event.body.unwrap()
    else {
        panic!("expected GroupCreated");
    };
    let group_id = GroupId::from_bytes(created_group.group_id.try_into().unwrap());

    bob_client
        .execute(ClientCommand::apply_pairwise_control("welcome", welcome.payload).unwrap())
        .unwrap();

    let sent = owner_client
        .execute(
            ClientCommand::send_group_text("send-mesh", group_id, b"hello".to_vec(), "").unwrap(),
        )
        .unwrap();
    assert_eq!(sent.outbound.len(), 1, "MLS ciphertext is produced once");
    let ciphertext = wire_proto::OutboundItem::decode(sent.outbound[0].encode().as_slice())
        .unwrap()
        .payload;
    let mut future_hint =
        wire_proto::GroupApplicationCiphertext::decode(ciphertext.as_slice()).unwrap();
    future_hint.epoch += 1;
    let future = bob_client
        .execute(
            ClientCommand::apply_group_message("future-hint", future_hint.encode_to_vec()).unwrap(),
        )
        .unwrap();
    assert!(future.events.is_empty());
    assert_eq!(future.outbound.len(), 1);
    let fetch = wire_proto::OutboundItem::decode(future.outbound[0].encode().as_slice()).unwrap();
    assert_eq!(
        fetch.kind,
        wire_proto::OutboundKind::GroupCoordinator as i32
    );
    let fetch = wire_proto::GroupEpochFetch::decode(fetch.payload.as_slice()).unwrap();
    assert_eq!(fetch.from_epoch, 2);
    assert_eq!(fetch.through_epoch, 2);
    let relay_command =
        ClientCommand::apply_group_message("relay-copy", ciphertext.clone()).unwrap();
    let generation = bob_client.checkpoint_generation();
    bob_store.set_fail_replace(true);
    assert!(matches!(
        bob_client.execute(relay_command.clone()),
        Err(Error::Persistence(_))
    ));
    assert_eq!(bob_client.checkpoint_generation(), generation);
    bob_store.set_fail_replace(false);
    let relay = bob_client.execute(relay_command).unwrap();
    assert_eq!(relay.events.len(), 1);
    assert!(
        relay.outbound.is_empty(),
        "receipts are queued, not sent per message"
    );
    let flushed = bob_client
        .execute(ClientCommand::flush_group_acknowledgements("bob-flush", None).unwrap())
        .unwrap();
    assert_eq!(
        flushed.outbound.len(),
        1,
        "one batched acknowledgement is produced"
    );
    let acknowledgement =
        wire_proto::OutboundItem::decode(flushed.outbound[0].encode().as_slice()).unwrap();
    let delivered = owner_client
        .execute(ClientCommand::apply_group_message("bob-ack", acknowledgement.payload).unwrap())
        .unwrap();
    let delivery_event =
        wire_proto::AppEvent::decode(delivered.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupDeliveryChanged(delivery) = delivery_event.body.unwrap()
    else {
        panic!("expected GroupDeliveryChanged");
    };
    assert_eq!(
        delivery.state,
        wire_proto::GroupDeliveryState::DeliveredTo as i32
    );
    assert_eq!(delivery.delivered_count, 1);
    assert_eq!(delivery.intended_count, 2);

    let mesh = bob_client
        .execute(ClientCommand::apply_group_message("mesh-copy", ciphertext).unwrap())
        .unwrap();
    assert!(mesh.events.is_empty());
    assert!(mesh.outbound.is_empty());
    let reflushed = bob_client
        .execute(ClientCommand::flush_group_acknowledgements("bob-reflush", None).unwrap())
        .unwrap();
    assert!(
        reflushed.outbound.is_empty(),
        "the duplicate copy queues no receipt"
    );
}

struct ThreeMemberGroup {
    owner: PigeonClient<SwitchableStore, TestIdentity>,
    bob: PigeonClient<SwitchableStore, TestIdentity>,
    carol: PigeonClient<SwitchableStore, TestIdentity>,
    group_id: GroupId,
    bob_store: SwitchableStore,
}

fn three_member_group() -> ThreeMemberGroup {
    let (owner, mut bob, mut carol, created) = create_group_with_members(
        SwitchableStore::default(),
        [21, 22, 23],
        "create-receipts",
        "Receipt Birds",
        TestIdentity::new(61).root_public(),
        false,
    );
    let bob_public = TestIdentity::new(22).root_public();
    let carol_public = TestIdentity::new(23).root_public();
    let bob_store = bob.store().clone();
    let welcome_for = |member: [u8; 32]| {
        created
            .outbound
            .iter()
            .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
            .find(|item| {
                item.kind == wire_proto::OutboundKind::Pairwise as i32 && item.destination == member
            })
            .unwrap()
            .payload
    };
    let (bob_welcome, carol_welcome) = (welcome_for(bob_public), welcome_for(carol_public));
    let event = wire_proto::AppEvent::decode(created.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupCreated(group) = event.body.unwrap() else {
        panic!("expected GroupCreated");
    };
    bob.execute(ClientCommand::apply_pairwise_control("welcome-bob", bob_welcome).unwrap())
        .unwrap();
    carol
        .execute(ClientCommand::apply_pairwise_control("welcome-carol", carol_welcome).unwrap())
        .unwrap();
    ThreeMemberGroup {
        owner,
        bob,
        carol,
        group_id: GroupId::from_bytes(group.group_id.try_into().unwrap()),
        bob_store,
    }
}

fn group_text(
    client: &mut PigeonClient<SwitchableStore, TestIdentity>,
    command_id: &str,
    group_id: GroupId,
) -> Vec<u8> {
    let sent = client
        .execute(
            ClientCommand::send_group_text(
                command_id,
                group_id,
                command_id.as_bytes().to_vec(),
                "",
            )
            .unwrap(),
        )
        .unwrap();
    sent.outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupMessage as i32)
        .unwrap()
        .payload
}

fn delivery_counts(output: &pigeon_core::ClientOutput) -> Vec<(u32, u32)> {
    output
        .events
        .iter()
        .filter_map(|event| {
            match wire_proto::AppEvent::decode(event.encode().as_slice())
                .unwrap()
                .body?
            {
                wire_proto::app_event::Body::GroupDeliveryChanged(delivery) => {
                    Some((delivery.delivered_count, delivery.intended_count))
                }
                _ => None,
            }
        })
        .collect()
}

#[test]
fn malformed_group_entry_is_durably_rejected_before_next_valid_message() {
    let ThreeMemberGroup {
        mut owner,
        mut bob,
        bob_store: store,
        group_id,
        ..
    } = three_member_group();
    let valid = group_text(&mut owner, "after-poison", group_id);
    let malformed = ClientCommand::apply_group_message("relay-poison", vec![0xff]).unwrap();

    store.set_fail_replace(true);
    assert!(matches!(
        bob.execute(malformed.clone()),
        Err(Error::Persistence(_))
    ));
    store.set_fail_replace(false);
    let rejected = bob.execute(malformed).unwrap();
    assert_eq!(
        rejected.group_message_outcome,
        pigeon_core::GroupMessageOutcome::Rejected
    );
    assert!(rejected.events.is_empty());

    let mut relaunched = PigeonClient::new(store, TestIdentity::new(22)).unwrap();
    let accepted = relaunched
        .execute(ClientCommand::apply_group_message("relay-valid", valid).unwrap())
        .unwrap();
    assert_eq!(
        accepted.group_message_outcome,
        pigeon_core::GroupMessageOutcome::Accepted
    );
    assert_eq!(accepted.events.len(), 1);
}

#[test]
fn distant_future_epoch_is_durably_rejected_before_later_entries() {
    let ThreeMemberGroup {
        mut owner,
        mut bob,
        group_id,
        ..
    } = three_member_group();
    let valid = group_text(&mut owner, "future-after-epoch", group_id);
    let mut hinted = wire_proto::GroupApplicationCiphertext::decode(valid.as_slice()).unwrap();
    hinted.epoch += pigeon_core::MAX_FUTURE_EPOCHS as u64 + 1;
    let command =
        ClientCommand::apply_group_message("future-dependent", hinted.encode_to_vec()).unwrap();
    let generation = bob.checkpoint_generation();
    let rejected = bob.execute(command).unwrap();
    assert_eq!(
        rejected.group_message_outcome,
        pigeon_core::GroupMessageOutcome::Rejected
    );
    assert_eq!(bob.checkpoint_generation(), generation + 1);
}

#[test]
fn buffered_future_message_is_delivered_when_its_epoch_is_merged() {
    let ThreeMemberGroup {
        mut owner,
        mut bob,
        group_id,
        ..
    } = three_member_group();
    let coordinator = TestIdentity::new(61);
    let owner_snapshot =
        wire_proto::ClientSnapshot::decode(owner.snapshot().unwrap().encode().as_slice()).unwrap();
    let initial = owner_snapshot
        .pending_outbound
        .iter()
        .find(|item| item.kind == wire_proto::OutboundKind::GroupCoordinator as i32)
        .unwrap();
    let coordination_id: [u8; 32] = initial.destination.as_slice().try_into().unwrap();
    let initial_submission =
        wire_proto::GroupCoordinatorSubmission::decode(initial.payload.as_slice()).unwrap();
    let initial_candidate = coordinator_candidate(
        &initial_submission,
        1,
        [0; 32],
        coordination_id,
        &coordinator.root,
    );
    let initial_head = pigeon_core::CoordinatorReceipt::decode_candidate(&initial_candidate)
        .unwrap()
        .0
        .receipt_hash();
    owner
        .execute(
            ClientCommand::apply_group_coordinator_candidate(
                "anchor-owner",
                initial_candidate.clone(),
            )
            .unwrap(),
        )
        .unwrap();
    bob.execute(
        ClientCommand::apply_group_coordinator_candidate("anchor-bob", initial_candidate).unwrap(),
    )
    .unwrap();

    let changed = owner
        .execute(ClientCommand::rename_group("rename", group_id, "Swifts").unwrap())
        .unwrap();
    let submission = changed
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupCoordinator as i32)
        .unwrap();
    let submission =
        wire_proto::GroupCoordinatorSubmission::decode(submission.payload.as_slice()).unwrap();
    let candidate = coordinator_candidate(
        &submission,
        2,
        initial_head,
        coordination_id,
        &coordinator.root,
    );
    owner
        .execute(
            ClientCommand::apply_group_coordinator_candidate("merge-owner", candidate.clone())
                .unwrap(),
        )
        .unwrap();
    let ciphertext = group_text(&mut owner, "after-rename", group_id);
    let early = bob
        .execute(ClientCommand::apply_group_message("early", ciphertext).unwrap())
        .unwrap();
    assert!(early.events.is_empty());
    let merged = bob
        .execute(ClientCommand::apply_group_coordinator_candidate("merge-bob", candidate).unwrap())
        .unwrap();
    assert!(merged.events.iter().any(|event| {
        let event = wire_proto::AppEvent::decode(event.encode().as_slice()).unwrap();
        matches!(
            event.body,
            Some(wire_proto::app_event::Body::GroupMessageReceived(_))
        )
    }));
    let checkpoint = bob.store().load().unwrap().unwrap();
    let state = wire_proto::ClientCheckpoint::decode(checkpoint.bytes.as_slice()).unwrap();
    assert!(state.buffered_group_messages.is_empty());
}

#[test]
fn unauthenticated_future_message_id_cannot_suppress_another_ciphertext() {
    let ThreeMemberGroup {
        mut owner,
        mut bob,
        group_id,
        ..
    } = three_member_group();
    let first = group_text(&mut owner, "first-future", group_id);
    let second = group_text(&mut owner, "second-future", group_id);
    let mut first = wire_proto::GroupApplicationCiphertext::decode(first.as_slice()).unwrap();
    let mut second = wire_proto::GroupApplicationCiphertext::decode(second.as_slice()).unwrap();
    first.epoch += 1;
    second.epoch += 1;
    second.message_id = first.message_id.clone();
    bob.execute(ClientCommand::apply_group_message("future-one", first.encode_to_vec()).unwrap())
        .unwrap();
    bob.execute(ClientCommand::apply_group_message("future-two", second.encode_to_vec()).unwrap())
        .unwrap();
    let checkpoint = bob.store().load().unwrap().unwrap();
    let state = wire_proto::ClientCheckpoint::decode(checkpoint.bytes.as_slice()).unwrap();
    assert_eq!(state.buffered_group_messages.len(), 2);
}

#[test]
fn one_batched_receipt_settles_every_senders_messages_and_bystanders_ignore_it() {
    let ThreeMemberGroup {
        mut owner,
        mut bob,
        mut carol,
        group_id,
        ..
    } = three_member_group();
    let owner_first = group_text(&mut owner, "owner-first", group_id);
    let owner_second = group_text(&mut owner, "owner-second", group_id);
    let carol_text = group_text(&mut carol, "carol-text", group_id);
    for (index, message) in [owner_first, owner_second, carol_text]
        .into_iter()
        .enumerate()
    {
        let received = bob
            .execute(ClientCommand::apply_group_message(format!("bob-{index}"), message).unwrap())
            .unwrap();
        assert!(received.outbound.is_empty(), "no receipt per message");
    }

    let flushed = bob
        .execute(ClientCommand::flush_group_acknowledgements("bob-flush", Some(group_id)).unwrap())
        .unwrap();
    assert_eq!(
        flushed.outbound.len(),
        1,
        "three receipts share one ciphertext"
    );
    let batch = wire_proto::OutboundItem::decode(flushed.outbound[0].encode().as_slice())
        .unwrap()
        .payload;

    let owner_delivery = owner
        .execute(ClientCommand::apply_group_message("owner-receipts", batch.clone()).unwrap())
        .unwrap();
    assert_eq!(delivery_counts(&owner_delivery), vec![(1, 2), (1, 2)]);

    let carol_delivery = carol
        .execute(ClientCommand::apply_group_message("carol-receipts", batch).unwrap())
        .unwrap();
    assert_eq!(delivery_counts(&carol_delivery), vec![(1, 2)]);

    let generation = bob.checkpoint_generation();
    let idle = bob
        .execute(ClientCommand::flush_group_acknowledgements("bob-idle", None).unwrap())
        .unwrap();
    assert!(idle.outbound.is_empty(), "flushed receipts are not resent");
    assert_eq!(
        bob.checkpoint_generation(),
        generation,
        "an idle flush commits nothing"
    );
}

#[test]
fn a_full_receipt_batch_flushes_without_waiting_for_the_host() {
    let ThreeMemberGroup {
        mut owner,
        mut bob,
        group_id,
        ..
    } = three_member_group();
    let mut automatic = Vec::new();
    for index in 0..pigeon_core::MAX_GROUP_ACKNOWLEDGEMENT_BATCH {
        let message = group_text(&mut owner, &format!("burst-{index}"), group_id);
        let received = bob
            .execute(
                ClientCommand::apply_group_message(format!("bob-burst-{index}"), message).unwrap(),
            )
            .unwrap();
        automatic.extend(received.outbound);
    }
    assert_eq!(automatic.len(), 1, "the full batch is flushed exactly once");
    let batch = wire_proto::OutboundItem::decode(automatic[0].encode().as_slice())
        .unwrap()
        .payload;
    let delivered = owner
        .execute(ClientCommand::apply_group_message("owner-burst-receipts", batch).unwrap())
        .unwrap();
    assert_eq!(
        delivery_counts(&delivered).len(),
        pigeon_core::MAX_GROUP_ACKNOWLEDGEMENT_BATCH
    );
}

#[test]
fn acknowledgement_batches_are_bounded() {
    use pigeon_core::{AcknowledgedMessage, GroupApplication, GroupMessageId};
    assert!(GroupApplication::acknowledgements(Vec::new()).is_err());
    let one = AcknowledgedMessage {
        original_sender: [1; 32],
        message_id: GroupMessageId::from_bytes([2; 16]),
    };
    assert!(
        GroupApplication::acknowledgements(vec![one; pigeon_core::MAX_GROUP_ACKNOWLEDGEMENT_BATCH])
            .is_ok()
    );
    assert!(
        GroupApplication::acknowledgements(vec![
            one;
            pigeon_core::MAX_GROUP_ACKNOWLEDGEMENT_BATCH + 1
        ])
        .is_err()
    );
}
