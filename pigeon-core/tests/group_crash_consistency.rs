use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer, SigningKey};
use pigeon_core::{
    ClientCommand, Error, GroupCiphertext, GroupId, IdentityError, IdentityPurpose, PigeonClient,
    ReservedKeyPackage, SealedCheckpoint, SecureIdentity, StateStore, StorageError,
    TransactionalOpenMlsStorage, wire_proto,
};
use prost::Message;
use sha2::{Digest, Sha256};

struct TestIdentity {
    root: SigningKey,
    mls: SigningKey,
}

impl TestIdentity {
    fn new(byte: u8) -> Self {
        Self {
            root: SigningKey::from_bytes(&[byte; 32]),
            mls: SigningKey::from_bytes(&[byte.wrapping_add(64); 32]),
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
            _ => return Err(IdentityError::Unavailable),
        })
    }

    fn sign(&self, purpose: IdentityPurpose, message: &[u8]) -> Result<[u8; 64], IdentityError> {
        let key = match purpose {
            IdentityPurpose::Root => &self.root,
            IdentityPurpose::Mls => &self.mls,
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

#[test]
fn failed_send_checkpoint_releases_no_ciphertext_and_retry_is_durable() {
    let owner = TestIdentity::new(1);
    let bob = TestIdentity::new(2);
    let carol = TestIdentity::new(3);
    let mut bob_storage = TransactionalOpenMlsStorage::new();
    let mut carol_storage = TransactionalOpenMlsStorage::new();
    let bob_package =
        ReservedKeyPackage::issue(&bob, owner.root_public(), &mut bob_storage).unwrap();
    let carol_package =
        ReservedKeyPackage::issue(&carol, owner.root_public(), &mut carol_storage).unwrap();
    let store = SwitchableStore::default();
    let mut client = PigeonClient::new(store.clone(), owner).unwrap();
    client
        .execute(
            ClientCommand::create_group(
                "create",
                "Birds",
                vec![bob.root_public(), carol.root_public()],
                "https://relay.example",
                false,
            )
            .unwrap(),
        )
        .unwrap();
    client
        .execute(
            ClientCommand::apply_key_package(
                "bob-package",
                "create:key-package:0",
                bob_package.encode(),
            )
            .unwrap(),
        )
        .unwrap();
    let created = client
        .execute(
            ClientCommand::apply_key_package(
                "carol-package",
                "create:key-package:1",
                carol_package.encode(),
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
    assert_eq!(output.events.len(), 1);
    assert_eq!(output.outbound.len(), 1);
    let outbound =
        wire_proto::OutboundItem::decode(output.outbound[0].encode().as_slice()).unwrap();
    assert_eq!(outbound.kind, wire_proto::OutboundKind::GroupMessage as i32);
    assert!(GroupCiphertext::decode(&outbound.payload).is_ok());
    assert_eq!(store.load().unwrap().unwrap().generation, 4);
}

#[test]
fn relay_and_mesh_copies_emit_one_received_event_and_one_acknowledgement() {
    let owner = TestIdentity::new(11);
    let bob = TestIdentity::new(12);
    let carol = TestIdentity::new(13);
    let mut bob_mls = TransactionalOpenMlsStorage::new();
    let mut carol_mls = TransactionalOpenMlsStorage::new();
    let bob_package = ReservedKeyPackage::issue(&bob, owner.root_public(), &mut bob_mls).unwrap();
    let carol_package =
        ReservedKeyPackage::issue(&carol, owner.root_public(), &mut carol_mls).unwrap();
    let mut owner_client = PigeonClient::new(SwitchableStore::default(), owner).unwrap();
    owner_client
        .execute(
            ClientCommand::create_group(
                "create-mesh",
                "Mesh Birds",
                vec![bob.root_public(), carol.root_public()],
                "https://relay.example",
                true,
            )
            .unwrap(),
        )
        .unwrap();
    owner_client
        .execute(
            ClientCommand::apply_key_package(
                "mesh-bob-package",
                "create-mesh:key-package:0",
                bob_package.encode(),
            )
            .unwrap(),
        )
        .unwrap();
    let created = owner_client
        .execute(
            ClientCommand::apply_key_package(
                "mesh-carol-package",
                "create-mesh:key-package:1",
                carol_package.encode(),
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
    assert_eq!(relay.outbound.len(), 1, "one acknowledgement is produced");
    let acknowledgement =
        wire_proto::OutboundItem::decode(relay.outbound[0].encode().as_slice()).unwrap();
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
}
