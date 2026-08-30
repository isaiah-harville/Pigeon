use super::protocol::{
    challenge_transcript, gate_group_message, registration_transcript, verify_challenge,
    verify_registration, CapabilityWire, GroupClientMsg, GroupProtocolGate, GroupServerMsg,
};
use super::store::{
    CapabilityRegistration, Config, GroupCapability, GroupRegistration, Store, StoreError,
};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use pigeon_core::{
    GroupId, GroupRelayRegistration, IdentityError, IdentityPurpose, SecureIdentity,
};

struct CoreIdentity(SigningKey);

impl SecureIdentity for CoreIdentity {
    fn ensure_public_key(&self, purpose: IdentityPurpose) -> Result<[u8; 32], IdentityError> {
        match purpose {
            IdentityPurpose::GroupCapability(_) => Ok(self.0.verifying_key().to_bytes()),
            _ => Err(IdentityError::Unavailable),
        }
    }

    fn sign(&self, purpose: IdentityPurpose, message: &[u8]) -> Result<[u8; 64], IdentityError> {
        match purpose {
            IdentityPurpose::GroupCapability(_) => Ok(self.0.sign(message).to_bytes()),
            _ => Err(IdentityError::Unavailable),
        }
    }
}

fn config() -> Config {
    Config {
        ttl_secs: 60,
        max_groups: 4,
        max_capabilities_per_group: 128,
        max_entry_bytes: 1024,
        max_entries_per_group: 4,
        max_total_bytes: 4096,
        max_fetch_batch_bytes: 2048,
    }
}

fn registration(readers: usize) -> GroupRegistration {
    GroupRegistration {
        coordination_id: [9; 32],
        capabilities: (0..readers)
            .map(|index| CapabilityRegistration {
                public_key: [(index + 1) as u8; 32],
                can_append: true,
                can_read: true,
                can_control: index == 0,
            })
            .collect(),
    }
}

#[test]
fn group_one_opaque_entry_waits_for_every_active_reader() {
    let mut store = Store::bounded(config());
    let group = store.register(registration(3)).unwrap();
    let receipt = store
        .append(&group.writer(0), b"opaque ciphertext".to_vec(), 1)
        .unwrap();

    store.advance(&group.reader(0), receipt.sequence).unwrap();
    assert_eq!(store.entry_count(group.id()), 1);
    store.advance(&group.reader(1), receipt.sequence).unwrap();
    assert_eq!(store.entry_count(group.id()), 1);
    store.advance(&group.reader(2), receipt.sequence).unwrap();
    assert_eq!(store.entry_count(group.id()), 0);
}

#[test]
fn group_duplicate_append_is_stored_once() {
    let mut store = Store::bounded(config());
    let group = store.register(registration(3)).unwrap();
    let first = store
        .append(&group.writer(0), b"same ciphertext".to_vec(), 1)
        .unwrap();
    let replay = store
        .append(&group.writer(0), b"same ciphertext".to_vec(), 2)
        .unwrap();

    assert_eq!(first, replay);
    assert_eq!(store.entry_count(group.id()), 1);
}

#[test]
fn group_capability_and_cursor_checks_fail_closed() {
    let mut store = Store::bounded(config());
    let group = store.register(registration(3)).unwrap();
    let receipt = store
        .append(&group.writer(0), b"ciphertext".to_vec(), 1)
        .unwrap();
    store.advance(&group.reader(0), receipt.sequence).unwrap();

    assert_eq!(
        store.advance(&group.reader(0), receipt.sequence),
        Err(StoreError::StaleCursor)
    );
    let mut forged = group.reader(0);
    forged.public_key[0] ^= 1;
    assert_eq!(store.fetch(&forged, 0), Err(StoreError::Unauthorized));
}

#[test]
fn group_rejects_the_129th_capability() {
    let mut store = Store::bounded(config());
    assert_eq!(
        store.register(registration(129)),
        Err(StoreError::CapabilityLimit)
    );
}

#[test]
fn group_slow_reader_remains_bounded_by_explicit_quotas_and_ttl() {
    let mut limits = config();
    limits.max_entries_per_group = 2;
    limits.max_total_bytes = 8;
    let mut store = Store::bounded(limits);
    let group = store.register(registration(2)).unwrap();
    store.append(&group.writer(0), vec![1; 4], 1).unwrap();
    store.append(&group.writer(0), vec![2; 4], 2).unwrap();
    assert_eq!(
        store.append(&group.writer(0), vec![3; 4], 3),
        Err(StoreError::AtCapacity)
    );

    store.expire(62);
    assert_eq!(store.entry_count(group.id()), 0);
    assert_eq!(store.total_bytes(), 0);
}

#[test]
fn group_registration_and_challenge_require_valid_capability_signatures() {
    let controller = SigningKey::from_bytes(&[41; 32]);
    let reader = SigningKey::from_bytes(&[42; 32]);
    let registrations = vec![
        CapabilityRegistration {
            public_key: controller.verifying_key().to_bytes(),
            can_append: true,
            can_read: true,
            can_control: true,
        },
        CapabilityRegistration {
            public_key: reader.verifying_key().to_bytes(),
            can_append: true,
            can_read: true,
            can_control: false,
        },
    ];
    let wires = registrations
        .iter()
        .map(|capability| CapabilityWire {
            public_key: hex::encode(capability.public_key),
            can_append: capability.can_append,
            can_read: capability.can_read,
            can_control: capability.can_control,
        })
        .collect::<Vec<_>>();
    let transcript = registration_transcript([7; 32], &registrations);
    let signature = B64.encode(controller.sign(&transcript).to_bytes());
    assert!(verify_registration(&hex::encode([7; 32]), &wires, &signature).is_ok());

    let forged = B64.encode(reader.sign(&transcript).to_bytes());
    assert_eq!(
        verify_registration(&hex::encode([7; 32]), &wires, &forged),
        Err(StoreError::Unauthorized)
    );

    let capability = GroupCapability {
        coordination_id: [7; 32],
        public_key: reader.verifying_key().to_bytes(),
    };
    let nonce = [8; 32];
    let challenge_signature = B64.encode(
        reader
            .sign(&challenge_transcript(&capability, &nonce))
            .to_bytes(),
    );
    assert!(verify_challenge(&capability, &nonce, &challenge_signature));
    assert!(!verify_challenge(
        &capability,
        &[9; 32],
        &challenge_signature
    ));
}

#[test]
fn relay_accepts_the_registration_emitted_by_core() {
    let owner = CoreIdentity(SigningKey::from_bytes(&[71; 32]));
    let registration = GroupRelayRegistration::create(
        &owner,
        GroupId::from_bytes([72; 32]),
        [73; 32],
        [
            SigningKey::from_bytes(&[74; 32]).verifying_key().to_bytes(),
            SigningKey::from_bytes(&[75; 32]).verifying_key().to_bytes(),
        ],
    )
    .unwrap();
    let capabilities = registration
        .capabilities()
        .iter()
        .map(|capability| CapabilityWire {
            public_key: hex::encode(capability.public_key()),
            can_append: capability.can_append(),
            can_read: capability.can_read(),
            can_control: capability.can_control(),
        })
        .collect::<Vec<_>>();

    assert!(verify_registration(
        &hex::encode(registration.coordination_id()),
        &capabilities,
        &B64.encode(registration.signature()),
    )
    .is_ok());
}

#[test]
fn group_protocol_requires_current_version_negotiation() {
    let mut negotiated = false;
    assert!(matches!(
        gate_group_message(
            GroupClientMsg::Hello {
                min_protocol_version: 1,
                max_protocol_version: 1,
            },
            &mut negotiated
        ),
        GroupProtocolGate::Reply(GroupServerMsg::Incompatible { .. })
    ));
    assert!(!negotiated);
    assert!(matches!(
        gate_group_message(
            GroupClientMsg::Hello {
                min_protocol_version: 1,
                max_protocol_version: 3,
            },
            &mut negotiated
        ),
        GroupProtocolGate::Reply(GroupServerMsg::Compatible {
            protocol_version: 3,
            ..
        })
    ));
    assert!(negotiated);
}

#[test]
fn group_wake_and_error_frames_disclose_no_group_metadata() {
    assert_eq!(
        serde_json::to_string(&GroupServerMsg::Wake).unwrap(),
        r#"{"type":"wake"}"#
    );
    assert_eq!(
        serde_json::to_string(&GroupServerMsg::Error {
            message: "group operation rejected".into(),
        })
        .unwrap(),
        r#"{"type":"error","message":"group operation rejected"}"#
    );
}

#[test]
fn group_control_capability_rotates_and_revokes_without_resetting_entries() {
    let mut store = Store::bounded(config());
    let group = store.register(registration(3)).unwrap();
    store
        .append(&group.writer(0), b"ciphertext".to_vec(), 1)
        .unwrap();
    let replacement = CapabilityRegistration {
        public_key: [44; 32],
        can_append: true,
        can_read: true,
        can_control: false,
    };
    store
        .rotate_capability(&group.writer(0), [2; 32], replacement)
        .unwrap();
    assert_eq!(
        store.fetch(&group.reader(1), 0),
        Err(StoreError::Unauthorized)
    );
    let replacement = GroupCapability {
        coordination_id: *group.id(),
        public_key: [44; 32],
    };
    assert_eq!(store.fetch(&replacement, 0).unwrap().len(), 1);
    store.revoke_capability(&group.writer(0), [3; 32]).unwrap();
    assert_eq!(
        store.fetch(&group.reader(2), 0),
        Err(StoreError::Unauthorized)
    );
    assert_eq!(store.entry_count(group.id()), 1);
}

#[test]
fn controller_grants_members_from_the_current_cursor_only() {
    let mut store = Store::bounded(config());
    let group = store.register(registration(3)).unwrap();
    store
        .append(&group.writer(0), b"before join".to_vec(), 1)
        .unwrap();
    let granted = CapabilityRegistration {
        public_key: [44; 32],
        can_append: true,
        can_read: true,
        can_control: false,
    };

    store.grant_capability(&group.writer(0), granted).unwrap();
    let new_member = GroupCapability {
        coordination_id: *group.id(),
        public_key: [44; 32],
    };
    assert!(store.fetch(&new_member, 1).unwrap().is_empty());
    assert_eq!(store.fetch(&new_member, 0), Err(StoreError::StaleCursor));

    store
        .append(&group.writer(0), b"after join".to_vec(), 2)
        .unwrap();
    let entries = store.fetch(&new_member, 1).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].ciphertext, b"after join");
    assert_eq!(
        store.grant_capability(
            &group.writer(0),
            CapabilityRegistration {
                public_key: [44; 32],
                can_append: true,
                can_read: true,
                can_control: false,
            },
        ),
        Err(StoreError::Unauthorized)
    );
}

#[test]
fn capability_grants_enforce_controller_role_shape_and_group_cap() {
    let mut store = Store::bounded(config());
    let group = store.register(registration(3)).unwrap();
    let member = CapabilityRegistration {
        public_key: [44; 32],
        can_append: true,
        can_read: true,
        can_control: false,
    };
    assert_eq!(
        store.grant_capability(&group.writer(1), member.clone()),
        Err(StoreError::Unauthorized)
    );
    assert_eq!(
        store.grant_capability(
            &group.writer(0),
            CapabilityRegistration {
                can_control: true,
                ..member
            },
        ),
        Err(StoreError::InvalidRegistration)
    );

    let full = store.register(GroupRegistration {
        coordination_id: [10; 32],
        capabilities: registration(128).capabilities,
    });
    let full = full.unwrap();
    assert_eq!(
        store.grant_capability(
            &full.writer(0),
            CapabilityRegistration {
                public_key: [200; 32],
                can_append: true,
                can_read: true,
                can_control: false,
            },
        ),
        Err(StoreError::CapabilityLimit)
    );
}
