use ed25519_dalek::{Signer, SigningKey};
use pigeon_core::{
    ClientCommand, Error, GroupJoinMaterial, GroupJoinRequest, GroupRelayRegistration,
    IdentityError, IdentityPurpose, MemoryStateStore, PigeonClient, SecureIdentity, StateStore,
    TransactionalOpenMlsStorage, wire_proto,
};
use prost::Message;

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
        request.creator_identity(),
        request.group_id(),
        request.coordination_id(),
        storage,
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
