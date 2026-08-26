use ed25519_dalek::{Signer, SigningKey};
use pigeon_core::{
    ClientCommand, Error, IdentityError, IdentityPurpose, MemoryStateStore, PigeonClient,
    PigeonGroupPolicy, ReservedKeyPackage, SecureIdentity, StateStore, TransactionalOpenMlsStorage,
    wire_proto,
};
use prost::Message;

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
fn final_reserved_key_package_atomically_creates_the_real_mls_group() {
    let owner = TestIdentity::new(1);
    let bob = TestIdentity::new(2);
    let carol = TestIdentity::new(3);
    let mut bob_storage = TransactionalOpenMlsStorage::new();
    let mut carol_storage = TransactionalOpenMlsStorage::new();
    let bob_package =
        ReservedKeyPackage::issue(&bob, owner.root_public(), &mut bob_storage).unwrap();
    let carol_package =
        ReservedKeyPackage::issue(&carol, owner.root_public(), &mut carol_storage).unwrap();
    let mut client = PigeonClient::new(MemoryStateStore::default(), owner).unwrap();

    let pending = client.execute(create_group()).unwrap();
    assert!(pending.events.is_empty());
    assert_eq!(pending.outbound.len(), 2);

    let one = client
        .execute(
            ClientCommand::apply_key_package(
                "command-2",
                "command-1:key-package:0",
                bob_package.encode(),
            )
            .unwrap(),
        )
        .unwrap();
    assert!(one.events.is_empty());
    assert!(one.outbound.is_empty());

    let created = client
        .execute(
            ClientCommand::apply_key_package(
                "command-3",
                "command-1:key-package:1",
                carol_package.encode(),
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(created.checkpoint_generation, 3);
    assert_eq!(created.events.len(), 1);
    assert_eq!(created.outbound.len(), 3);
    let event = wire_proto::AppEvent::decode(created.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupCreated(group) = event.body.unwrap() else {
        panic!("final KeyPackage must emit GroupCreated");
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
    let registration = outbound
        .iter()
        .find(|item| item.item_id.ends_with(":register"))
        .unwrap();
    assert!(
        PigeonGroupPolicy::decode(&registration.payload).is_err(),
        "the zero-knowledge coordinator must receive an opaque MLS commit, not plaintext policy"
    );
    assert_eq!(client.checkpoint_generation(), 3);
}

#[test]
fn one_reserved_key_package_cannot_fill_two_group_drafts() {
    let owner = TestIdentity::new(1);
    let bob = TestIdentity::new(2);
    let mut bob_storage = TransactionalOpenMlsStorage::new();
    let bob_package =
        ReservedKeyPackage::issue(&bob, owner.root_public(), &mut bob_storage).unwrap();
    let mut client = PigeonClient::new(MemoryStateStore::default(), owner).unwrap();
    client.execute(create_group()).unwrap();
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
    client
        .execute(
            ClientCommand::apply_key_package(
                "first-response",
                "command-1:key-package:0",
                bob_package.encode(),
            )
            .unwrap(),
        )
        .unwrap();

    let replay = client.execute(
        ClientCommand::apply_key_package(
            "replayed-response",
            "other-group:key-package:0",
            bob_package.encode(),
        )
        .unwrap(),
    );

    assert!(matches!(replay, Err(Error::InvalidSignature)));
    assert_eq!(client.checkpoint_generation(), 3);
}
