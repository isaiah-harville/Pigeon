use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer, SigningKey};
use pigeon_core::{
    ClientCommand, Error, GroupCiphertext, GroupId, GroupJoinMaterial, GroupJoinRequest,
    IdentityError, IdentityPurpose, PigeonClient, SealedCheckpoint, SecureIdentity, StateStore,
    StorageError, TransactionalOpenMlsStorage, coordinator_receipt_transcript, wire_proto,
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

    fn with_checkpoint(checkpoint: SealedCheckpoint) -> Self {
        Self {
            state: Arc::new(Mutex::new(StoreState {
                checkpoint: Some(checkpoint),
                fail_replace: false,
            })),
        }
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

fn issue_join_material(
    item: &pigeon_core::OutboundItem,
    member: &TestIdentity,
    storage: &mut TransactionalOpenMlsStorage,
) -> GroupJoinMaterial {
    let item = wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap();
    let request = GroupJoinRequest::decode(&item.payload).unwrap();
    assert_eq!(item.destination, member.root_public());
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
    let owner = TestIdentity::new(1);
    let bob = TestIdentity::new(2);
    let carol = TestIdentity::new(3);
    let mut bob_storage = TransactionalOpenMlsStorage::new();
    let mut carol_storage = TransactionalOpenMlsStorage::new();
    let store = SwitchableStore::default();
    let mut client = PigeonClient::new(store.clone(), owner).unwrap();
    let pending = client
        .execute(
            ClientCommand::create_group(
                "create",
                "Birds",
                vec![bob.root_public(), carol.root_public()],
                "https://relay.example",
                TestIdentity::new(60).root_public(),
                false,
            )
            .unwrap(),
        )
        .unwrap();
    let bob_material = issue_join_material(&pending.outbound[0], &bob, &mut bob_storage);
    let carol_material = issue_join_material(&pending.outbound[1], &carol, &mut carol_storage);
    client
        .execute(
            ClientCommand::apply_group_join_material(
                "bob-package",
                "create:join:0",
                bob_material.encode(),
            )
            .unwrap(),
        )
        .unwrap();
    let created = client
        .execute(
            ClientCommand::apply_group_join_material(
                "carol-package",
                "create:join:1",
                carol_material.encode(),
            )
            .unwrap(),
        )
        .unwrap();
    let created_event =
        wire_proto::AppEvent::decode(created.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupCreated(created_group) = created_event.body.unwrap()
    else {
        panic!("expected GroupCreated");
    };
    let group_id = GroupId::from_bytes(created_group.group_id.try_into().unwrap());
    let send = ClientCommand::send_group_text("send-1", group_id, b"hello".to_vec(), "").unwrap();

    store.set_fail_replace(true);
    assert!(matches!(
        client.execute(send.clone()),
        Err(Error::Persistence(_))
    ));
    assert_eq!(client.checkpoint_generation(), 3);
    assert_eq!(store.load().unwrap().unwrap().generation, 3);

    store.set_fail_replace(false);
    let output = client.execute(send).unwrap();
    assert_eq!(output.checkpoint_generation, 4);
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
    assert_eq!(store.load().unwrap().unwrap().generation, 4);
}

#[test]
fn failed_recovery_checkpoint_releases_no_coordinator_work_and_retry_is_durable() {
    let owner = TestIdentity::new(21);
    let bob = TestIdentity::new(22);
    let carol = TestIdentity::new(23);
    let coordinator = TestIdentity::new(60);
    let replacement_coordinator = TestIdentity::new(61);
    let replacement_coordination_id = [92; 32];
    let mut bob_storage = TransactionalOpenMlsStorage::new();
    let mut carol_storage = TransactionalOpenMlsStorage::new();
    let store = SwitchableStore::default();
    let mut client = PigeonClient::new(store.clone(), owner).unwrap();
    let pending = client
        .execute(
            ClientCommand::create_group(
                "create-recovery",
                "Recovery Birds",
                vec![bob.root_public(), carol.root_public()],
                "https://relay.example",
                coordinator.root_public(),
                false,
            )
            .unwrap(),
        )
        .unwrap();
    let bob_material = issue_join_material(&pending.outbound[0], &bob, &mut bob_storage);
    let carol_material = issue_join_material(&pending.outbound[1], &carol, &mut carol_storage);
    client
        .execute(
            ClientCommand::apply_group_join_material(
                "recovery-bob-package",
                "create-recovery:join:0",
                bob_material.encode(),
            )
            .unwrap(),
        )
        .unwrap();
    let created = client
        .execute(
            ClientCommand::apply_group_join_material(
                "recovery-carol-package",
                "create-recovery:join:1",
                carol_material.encode(),
            )
            .unwrap(),
        )
        .unwrap();
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
    let owner = TestIdentity::new(11);
    let bob = TestIdentity::new(12);
    let carol = TestIdentity::new(13);
    let mut bob_mls = TransactionalOpenMlsStorage::new();
    let mut carol_mls = TransactionalOpenMlsStorage::new();
    let mut owner_client = PigeonClient::new(SwitchableStore::default(), owner).unwrap();
    let pending = owner_client
        .execute(
            ClientCommand::create_group(
                "create-mesh",
                "Mesh Birds",
                vec![bob.root_public(), carol.root_public()],
                "https://relay.example",
                TestIdentity::new(60).root_public(),
                true,
            )
            .unwrap(),
        )
        .unwrap();
    let bob_material = issue_join_material(&pending.outbound[0], &bob, &mut bob_mls);
    let carol_material = issue_join_material(&pending.outbound[1], &carol, &mut carol_mls);
    owner_client
        .execute(
            ClientCommand::apply_group_join_material(
                "mesh-bob-package",
                "create-mesh:join:0",
                bob_material.encode(),
            )
            .unwrap(),
        )
        .unwrap();
    let created = owner_client
        .execute(
            ClientCommand::apply_group_join_material(
                "mesh-carol-package",
                "create-mesh:join:1",
                carol_material.encode(),
            )
            .unwrap(),
        )
        .unwrap();
    let welcome = created
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| {
            item.kind == wire_proto::OutboundKind::GroupWelcome as i32
                && item.destination == bob.root_public()
        })
        .unwrap();
    let created_event =
        wire_proto::AppEvent::decode(created.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupCreated(created_group) = created_event.body.unwrap()
    else {
        panic!("expected GroupCreated");
    };
    let group_id = GroupId::from_bytes(created_group.group_id.try_into().unwrap());

    let bob_checkpoint = wire_proto::ClientCheckpoint {
        version: 1,
        generation: 0,
        applied_command_ids: Vec::new(),
        groups: Vec::new(),
        openmls_checkpoint: bob_mls.export_checkpoint().unwrap(),
        pending_group_creations: Vec::new(),
        consumed_key_package_hashes: Vec::new(),
        processed_group_messages: Vec::new(),
        delivery_ledgers: Vec::new(),
        buffered_group_messages: Vec::new(),
        pending_group_mutations: Vec::new(),
        pending_group_additions: Vec::new(),
        pending_outbound: Vec::new(),
        pending_events: Vec::new(),
        pairwise_account_state: Vec::new(),
        pairwise_fallback_key: Vec::new(),
        pairwise_contacts: Vec::new(),
        pairwise_sessions: Vec::new(),
        consumed_pairwise_envelope_hashes: Vec::new(),
        deferred_events: Vec::new(),
        pending_group_recoveries: Vec::new(),
        pending_group_acknowledgements: Vec::new(),
        pending_group_leaves: Vec::new(),
    };
    let bytes = bob_checkpoint.encode_to_vec();
    let bob_store = SwitchableStore::with_checkpoint(SealedCheckpoint {
        generation: 0,
        sha256: Sha256::digest(&bytes).into(),
        bytes,
    });
    let mut bob_client = PigeonClient::new(bob_store.clone(), bob).unwrap();
    bob_client
        .execute(ClientCommand::apply_group_welcome("welcome", welcome.payload).unwrap())
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
    bob_store.set_fail_replace(true);
    assert!(matches!(
        bob_client.execute(relay_command.clone()),
        Err(Error::Persistence(_))
    ));
    assert_eq!(bob_client.checkpoint_generation(), 2);
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

fn joined_member(
    identity: TestIdentity,
    mls: &TransactionalOpenMlsStorage,
    welcome: Vec<u8>,
) -> (PigeonClient<SwitchableStore, TestIdentity>, SwitchableStore) {
    let checkpoint = wire_proto::ClientCheckpoint {
        version: 1,
        openmls_checkpoint: mls.export_checkpoint().unwrap(),
        ..Default::default()
    };
    let bytes = checkpoint.encode_to_vec();
    let store = SwitchableStore::with_checkpoint(SealedCheckpoint {
        generation: 0,
        sha256: Sha256::digest(&bytes).into(),
        bytes,
    });
    let mut client = PigeonClient::new(store.clone(), identity).unwrap();
    client
        .execute(ClientCommand::apply_group_welcome("welcome", welcome).unwrap())
        .unwrap();
    (client, store)
}

fn three_member_group() -> ThreeMemberGroup {
    let (bob, carol) = (TestIdentity::new(22), TestIdentity::new(23));
    let (bob_public, carol_public) = (bob.root_public(), carol.root_public());
    let mut bob_mls = TransactionalOpenMlsStorage::new();
    let mut carol_mls = TransactionalOpenMlsStorage::new();
    let mut owner = PigeonClient::new(SwitchableStore::default(), TestIdentity::new(21)).unwrap();
    let pending = owner
        .execute(
            ClientCommand::create_group(
                "create-receipts",
                "Receipt Birds",
                vec![bob_public, carol_public],
                "https://relay.example",
                TestIdentity::new(61).root_public(),
                false,
            )
            .unwrap(),
        )
        .unwrap();
    let bob_material = issue_join_material(&pending.outbound[0], &bob, &mut bob_mls);
    let carol_material = issue_join_material(&pending.outbound[1], &carol, &mut carol_mls);
    owner
        .execute(
            ClientCommand::apply_group_join_material(
                "receipts-bob-package",
                "create-receipts:join:0",
                bob_material.encode(),
            )
            .unwrap(),
        )
        .unwrap();
    let created = owner
        .execute(
            ClientCommand::apply_group_join_material(
                "receipts-carol-package",
                "create-receipts:join:1",
                carol_material.encode(),
            )
            .unwrap(),
        )
        .unwrap();
    let welcome_for = |member: [u8; 32]| {
        created
            .outbound
            .iter()
            .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
            .find(|item| {
                item.kind == wire_proto::OutboundKind::GroupWelcome as i32
                    && item.destination == member
            })
            .unwrap()
            .payload
    };
    let (bob_welcome, carol_welcome) = (welcome_for(bob_public), welcome_for(carol_public));
    let event = wire_proto::AppEvent::decode(created.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupCreated(group) = event.body.unwrap() else {
        panic!("expected GroupCreated");
    };
    let (bob_client, bob_store) = joined_member(bob, &bob_mls, bob_welcome);
    let (carol_client, _) = joined_member(carol, &carol_mls, carol_welcome);
    ThreeMemberGroup {
        owner,
        bob: bob_client,
        carol: carol_client,
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
