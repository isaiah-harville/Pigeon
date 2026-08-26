use ed25519_dalek::{Signer, SigningKey};
use pigeon_core::{
    BufferDisposition, DeliveryLedger, GroupAction, GroupApplication, GroupDeliveryState,
    GroupEngine, IdentityError, IdentityPurpose, ReservedKeyPackage, SecureIdentity,
    TransactionalOpenMlsStorage,
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

#[test]
fn joiner_reads_join_epoch_but_not_prejoin_ciphertext() {
    let alice = TestIdentity::new(1);
    let bob = TestIdentity::new(2);
    let carol = TestIdentity::new(3);
    let dave = TestIdentity::new(4);
    let mut alice_storage = TransactionalOpenMlsStorage::new();
    let mut bob_storage = TransactionalOpenMlsStorage::new();
    let mut carol_storage = TransactionalOpenMlsStorage::new();
    let mut dave_storage = TransactionalOpenMlsStorage::new();

    let bob_package =
        ReservedKeyPackage::issue(&bob, alice.root_public(), &mut bob_storage).unwrap();
    let carol_package =
        ReservedKeyPackage::issue(&carol, alice.root_public(), &mut carol_storage).unwrap();
    let (mut alice_group, welcome) = GroupEngine::create(
        &alice,
        &mut alice_storage,
        "Birds",
        "https://relay.example",
        [7; 32],
        vec![bob_package, carol_package],
    )
    .unwrap();
    let mut bob_group = GroupEngine::join_welcome(&bob, &mut bob_storage, &welcome).unwrap();
    let mut carol_group = GroupEngine::join_welcome(&carol, &mut carol_storage, &welcome).unwrap();

    let before = alice_group
        .encrypt_application(
            &alice,
            &mut alice_storage,
            GroupApplication::text(b"before".to_vec(), None, 1),
        )
        .unwrap();
    let dave_package =
        ReservedKeyPackage::issue(&dave, alice.root_public(), &mut dave_storage).unwrap();
    let add = alice_group
        .stage_candidate(
            &alice,
            &mut alice_storage,
            GroupAction::Add {
                actor: alice.root_public(),
                subject: dave.root_public(),
            },
            Some(dave_package),
        )
        .unwrap();
    alice_group
        .merge_canonical(&mut alice_storage, add.commit())
        .unwrap();
    bob_group
        .merge_canonical(&mut bob_storage, add.commit())
        .unwrap();
    carol_group
        .merge_canonical(&mut carol_storage, add.commit())
        .unwrap();
    let mut dave_group =
        GroupEngine::join_welcome(&dave, &mut dave_storage, add.welcome().unwrap()).unwrap();

    assert_eq!(
        bob_group
            .decrypt_application(&mut bob_storage, &before)
            .unwrap()
            .application()
            .text_body(),
        Some(b"before".as_slice())
    );
    assert!(
        dave_group
            .decrypt_application(&mut dave_storage, &before)
            .is_err()
    );
    let after = alice_group
        .encrypt_application(
            &alice,
            &mut alice_storage,
            GroupApplication::text(b"after".to_vec(), None, 2),
        )
        .unwrap();
    let received = dave_group
        .decrypt_application(&mut dave_storage, &after)
        .unwrap();
    assert_eq!(received.sender_identity(), alice.root_public());
    assert_eq!(
        received.application().text_body(),
        Some(b"after".as_slice())
    );
}

#[test]
fn removed_member_cannot_read_the_next_epoch() {
    let alice = TestIdentity::new(11);
    let bob = TestIdentity::new(12);
    let carol = TestIdentity::new(13);
    let dave = TestIdentity::new(14);
    let mut alice_storage = TransactionalOpenMlsStorage::new();
    let mut bob_storage = TransactionalOpenMlsStorage::new();
    let mut carol_storage = TransactionalOpenMlsStorage::new();
    let mut dave_storage = TransactionalOpenMlsStorage::new();
    let packages = [&bob, &carol, &dave]
        .into_iter()
        .map(|member| {
            ReservedKeyPackage::issue(
                member,
                alice.root_public(),
                match member.root_public() {
                    id if id == bob.root_public() => &mut bob_storage,
                    id if id == carol.root_public() => &mut carol_storage,
                    _ => &mut dave_storage,
                },
            )
            .unwrap()
        })
        .collect();
    let (mut alice_group, welcome) = GroupEngine::create(
        &alice,
        &mut alice_storage,
        "Birds",
        "https://relay.example",
        [8; 32],
        packages,
    )
    .unwrap();
    let mut bob_group = GroupEngine::join_welcome(&bob, &mut bob_storage, &welcome).unwrap();
    let mut carol_group = GroupEngine::join_welcome(&carol, &mut carol_storage, &welcome).unwrap();
    let mut dave_group = GroupEngine::join_welcome(&dave, &mut dave_storage, &welcome).unwrap();

    let remove = alice_group
        .stage_candidate(
            &alice,
            &mut alice_storage,
            GroupAction::Remove {
                actor: alice.root_public(),
                subject: dave.root_public(),
            },
            None,
        )
        .unwrap();
    alice_group
        .merge_canonical(&mut alice_storage, remove.commit())
        .unwrap();
    bob_group
        .merge_canonical(&mut bob_storage, remove.commit())
        .unwrap();
    carol_group
        .merge_canonical(&mut carol_storage, remove.commit())
        .unwrap();
    dave_group
        .merge_canonical(&mut dave_storage, remove.commit())
        .unwrap();

    let ciphertext = alice_group
        .encrypt_application(
            &alice,
            &mut alice_storage,
            GroupApplication::text(b"after removal".to_vec(), None, 3),
        )
        .unwrap();
    assert!(
        dave_group
            .decrypt_application(&mut dave_storage, &ciphertext)
            .is_err()
    );
}

#[test]
fn ciphertext_hints_are_checked_against_authenticated_content() {
    let alice = TestIdentity::new(21);
    let bob = TestIdentity::new(22);
    let carol = TestIdentity::new(23);
    let mut alice_storage = TransactionalOpenMlsStorage::new();
    let mut bob_storage = TransactionalOpenMlsStorage::new();
    let mut carol_storage = TransactionalOpenMlsStorage::new();
    let bob_package =
        ReservedKeyPackage::issue(&bob, alice.root_public(), &mut bob_storage).unwrap();
    let carol_package =
        ReservedKeyPackage::issue(&carol, alice.root_public(), &mut carol_storage).unwrap();
    let (mut alice_group, welcome) = GroupEngine::create(
        &alice,
        &mut alice_storage,
        "Birds",
        "https://relay.example",
        [9; 32],
        vec![bob_package, carol_package],
    )
    .unwrap();
    let mut bob_group = GroupEngine::join_welcome(&bob, &mut bob_storage, &welcome).unwrap();
    let ciphertext = alice_group
        .encrypt_application(
            &alice,
            &mut alice_storage,
            GroupApplication::text(b"authenticated".to_vec(), None, 4),
        )
        .unwrap();

    let mut wire =
        pigeon_core::wire_proto::GroupApplicationCiphertext::decode(ciphertext.encode().as_slice())
            .unwrap();
    wire.message_id[0] ^= 1;
    let substituted = pigeon_core::GroupCiphertext::decode(&wire.encode_to_vec()).unwrap();
    assert!(
        bob_group
            .decrypt_application(&mut bob_storage, &substituted)
            .is_err()
    );
}

#[test]
fn processed_secret_tree_state_survives_checkpoint_reload() {
    let alice = TestIdentity::new(31);
    let bob = TestIdentity::new(32);
    let carol = TestIdentity::new(33);
    let mut alice_storage = TransactionalOpenMlsStorage::new();
    let mut bob_storage = TransactionalOpenMlsStorage::new();
    let mut carol_storage = TransactionalOpenMlsStorage::new();
    let bob_package =
        ReservedKeyPackage::issue(&bob, alice.root_public(), &mut bob_storage).unwrap();
    let carol_package =
        ReservedKeyPackage::issue(&carol, alice.root_public(), &mut carol_storage).unwrap();
    let (mut alice_group, welcome) = GroupEngine::create(
        &alice,
        &mut alice_storage,
        "Birds",
        "https://relay.example",
        [10; 32],
        vec![bob_package, carol_package],
    )
    .unwrap();
    let mut bob_group = GroupEngine::join_welcome(&bob, &mut bob_storage, &welcome).unwrap();
    let ciphertext = alice_group
        .encrypt_application(
            &alice,
            &mut alice_storage,
            GroupApplication::text(b"once".to_vec(), None, 5),
        )
        .unwrap();
    bob_group
        .decrypt_application(&mut bob_storage, &ciphertext)
        .unwrap();

    let checkpoint = bob_storage.export_checkpoint().unwrap();
    let mut restored = TransactionalOpenMlsStorage::from_checkpoint(&checkpoint).unwrap();
    assert!(
        bob_group
            .decrypt_application(&mut restored, &ciphertext)
            .is_err()
    );
}

#[test]
fn acknowledgements_only_settle_the_authenticated_members_slot() {
    let group_id = pigeon_core::GroupId::from_bytes([1; 32]);
    let message_id = pigeon_core::GroupMessageId::from_bytes([2; 16]);
    let alice = [3; 32];
    let bob = [4; 32];
    let carol = [5; 32];
    let mut ledger = DeliveryLedger::new(group_id, message_id, 7, alice, vec![bob, carol]).unwrap();

    assert_eq!(ledger.state(), GroupDeliveryState::Sending);
    ledger.mark_sent();
    assert_eq!(ledger.state(), GroupDeliveryState::Sent);
    assert!(ledger.acknowledge(bob, carol, message_id).is_err());
    assert_eq!(ledger.state(), GroupDeliveryState::Sent);
    assert!(ledger.acknowledge(bob, alice, message_id).unwrap());
    assert_eq!(
        ledger.state(),
        GroupDeliveryState::DeliveredTo {
            delivered: 1,
            intended: 2,
        }
    );
    assert!(!ledger.acknowledge(bob, alice, message_id).unwrap());
    assert!(ledger.acknowledge(carol, alice, message_id).unwrap());
    assert_eq!(ledger.state(), GroupDeliveryState::Delivered);
}

#[test]
fn future_epoch_buffer_is_bounded_and_requests_missing_epochs() {
    let mut buffer = pigeon_core::EpochBuffer::new(2, 2 * 1024 * 1024, 2);
    let group_id = pigeon_core::GroupId::from_bytes([8; 32]);
    let first = test_ciphertext(group_id, 6, [1; 16]);
    let duplicate = first.clone();
    let too_far = test_ciphertext(group_id, 8, [2; 16]);

    assert_eq!(
        buffer.push(5, first).unwrap(),
        BufferDisposition::Buffered {
            missing_from: 6,
            missing_to: 6,
        }
    );
    assert_eq!(
        buffer.push(5, duplicate).unwrap(),
        BufferDisposition::Duplicate
    );
    assert_eq!(
        buffer.push(5, too_far).unwrap(),
        BufferDisposition::DroppedFutureGap
    );
    assert_eq!(buffer.drain_epoch(6).len(), 1);
}

fn test_ciphertext(
    group_id: pigeon_core::GroupId,
    epoch: u64,
    message_id: [u8; 16],
) -> pigeon_core::GroupCiphertext {
    let wire = pigeon_core::wire_proto::GroupApplicationCiphertext {
        version: 1,
        group_id: group_id.as_bytes().to_vec(),
        epoch,
        message_id: message_id.to_vec(),
        ciphertext: vec![0; 32],
    };
    pigeon_core::GroupCiphertext::decode(&wire.encode_to_vec()).unwrap()
}
