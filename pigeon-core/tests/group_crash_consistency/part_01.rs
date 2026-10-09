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
