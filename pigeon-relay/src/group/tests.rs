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
use tempfile::tempdir;

use crate::durable::{DurableError, GroupJournal, GROUP_DATABASE};

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
        authorization_generation: 0,
        permanent_controller_public_key: [1; 32],
        capabilities: (0..readers)
            .map(|index| CapabilityRegistration {
                capability_id: [(index + 101) as u8; 32],
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

    store.advance(&group.reader(0), receipt.sequence).unwrap();
    assert_eq!(
        store.advance(&group.reader(0), receipt.sequence + 1),
        Err(StoreError::StaleCursor)
    );
    let mut forged = group.reader(0);
    forged.capability_id[0] ^= 1;
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
            capability_id: [81; 32],
            public_key: controller.verifying_key().to_bytes(),
            can_append: true,
            can_read: true,
            can_control: true,
        },
        CapabilityRegistration {
            capability_id: [82; 32],
            public_key: reader.verifying_key().to_bytes(),
            can_append: true,
            can_read: true,
            can_control: false,
        },
    ];
    let wires = registrations
        .iter()
        .map(|capability| CapabilityWire {
            capability_id: hex::encode(capability.capability_id),
            public_key: hex::encode(capability.public_key),
            can_append: capability.can_append,
            can_read: capability.can_read,
            can_control: capability.can_control,
        })
        .collect::<Vec<_>>();
    let permanent = controller.verifying_key().to_bytes();
    let transcript = registration_transcript([7; 32], 0, permanent, &registrations);
    let signature = B64.encode(controller.sign(&transcript).to_bytes());
    assert!(verify_registration(
        &hex::encode([7; 32]),
        0,
        &hex::encode(permanent),
        &wires,
        &signature
    )
    .is_ok());

    let forged = B64.encode(reader.sign(&transcript).to_bytes());
    assert_eq!(
        verify_registration(
            &hex::encode([7; 32]),
            0,
            &hex::encode(permanent),
            &wires,
            &forged,
        ),
        Err(StoreError::Unauthorized)
    );

    let capability = GroupCapability {
        coordination_id: [7; 32],
        capability_id: [82; 32],
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
fn identical_group_registration_retry_is_idempotent_but_conflicts_fail() {
    let mut store = Store::bounded(config());
    let original = registration(3);

    store.register(original.clone()).unwrap();
    store.register(original).unwrap();

    let mut conflicting = registration(3);
    conflicting.capabilities[0].capability_id = [99; 32];
    assert_eq!(
        store.register(conflicting),
        Err(StoreError::AlreadyRegistered)
    );
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
                max_protocol_version: 6,
            },
            &mut negotiated
        ),
        GroupProtocolGate::Reply(GroupServerMsg::Compatible {
            protocol_version: 6,
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
fn atomic_replacement_rotates_all_ids_and_revokes_removed_members() {
    let mut store = Store::bounded(config());
    let group = store.register(registration(3)).unwrap();
    store
        .append(&group.writer(0), b"ciphertext".to_vec(), 1)
        .unwrap();
    let replacements = vec![
        CapabilityRegistration {
            capability_id: [111; 32],
            public_key: [1; 32],
            can_append: true,
            can_read: true,
            can_control: true,
        },
        CapabilityRegistration {
            capability_id: [112; 32],
            public_key: [2; 32],
            can_append: true,
            can_read: true,
            can_control: false,
        },
        CapabilityRegistration {
            capability_id: [114; 32],
            public_key: [4; 32],
            can_append: true,
            can_read: true,
            can_control: false,
        },
    ];
    store
        .replace_capabilities(&group.writer(0), 0, 1, [1; 32], replacements)
        .unwrap();

    for old in [group.reader(0), group.reader(1), group.reader(2)] {
        assert_eq!(store.fetch(&old, 0), Err(StoreError::Unauthorized));
    }
    let retained = store.resolve_capability(*group.id(), [112; 32]).unwrap();
    assert_eq!(store.fetch(&retained, 0).unwrap().len(), 1);
    let joined = store.resolve_capability(*group.id(), [114; 32]).unwrap();
    assert!(store.fetch(&joined, 0).unwrap().is_empty());
}

#[test]
fn replacement_rejects_replay_and_cannot_demote_permanent_owner() {
    let mut store = Store::bounded(config());
    let group = store.register(registration(3)).unwrap();
    let replacements = (0..3)
        .map(|index| CapabilityRegistration {
            capability_id: [(index + 111) as u8; 32],
            public_key: [(index + 1) as u8; 32],
            can_append: true,
            can_read: true,
            can_control: index == 0,
        })
        .collect::<Vec<_>>();
    store
        .replace_capabilities(&group.writer(0), 0, 1, [1; 32], replacements.clone())
        .unwrap();
    let owner = store.resolve_capability(*group.id(), [111; 32]).unwrap();
    assert_eq!(
        store.replace_capabilities(&owner, 0, 1, [1; 32], replacements.clone()),
        Err(StoreError::StaleGeneration)
    );
    let mut demoted = replacements;
    demoted[0].can_control = false;
    assert_eq!(
        store.replace_capabilities(&owner, 1, 2, [1; 32], demoted),
        Err(StoreError::InvalidRegistration)
    );
}

#[test]
fn permanent_owner_tombstones_group_until_offline_readers_can_fetch_dissolution() {
    let mut store = Store::bounded(config());
    let group = store.register(registration(3)).unwrap();
    store
        .append(&group.writer(0), b"ciphertext".to_vec(), 1)
        .unwrap();

    store.revoke_group(&group.writer(0), 0, 10).unwrap();

    assert_eq!(store.entry_count(group.id()), 1);
    assert_eq!(store.fetch(&group.reader(1), 0).unwrap().len(), 1);
    assert_eq!(
        store.append(&group.writer(0), b"later".to_vec(), 11),
        Err(StoreError::Unauthorized)
    );
    assert_eq!(
        store.replace_capabilities(&group.writer(0), 0, 1, [1; 32], vec![]),
        Err(StoreError::Unauthorized)
    );

    store.expire_at(71);
    assert_eq!(
        store.fetch(&group.reader(1), 0),
        Err(StoreError::Unauthorized)
    );
    assert_eq!(store.total_bytes(), 0);
}

#[test]
fn durable_group_state_survives_restart_with_rotation_cursors_and_tombstone() {
    let directory = tempdir().unwrap();
    let mut store =
        Store::durable(config(), GroupJournal::open(directory.path()).unwrap(), 1).unwrap();
    let group = store.register(registration(3)).unwrap();
    let receipt = store
        .append(&group.writer(0), b"durable ciphertext".to_vec(), 2)
        .unwrap();
    store.advance(&group.reader(1), receipt.sequence).unwrap();
    let replacements = (0..3)
        .map(|index| CapabilityRegistration {
            capability_id: [(index + 111) as u8; 32],
            public_key: [(index + 1) as u8; 32],
            can_append: true,
            can_read: true,
            can_control: index == 0,
        })
        .collect::<Vec<_>>();
    store
        .replace_capabilities(&group.writer(0), 0, 1, [1; 32], replacements)
        .unwrap();
    let owner = store.resolve_capability(*group.id(), [111; 32]).unwrap();
    store.revoke_group(&owner, 1, 3).unwrap();
    drop(store);

    let mut restored =
        Store::durable(config(), GroupJournal::open(directory.path()).unwrap(), 4).unwrap();
    let reader = restored.resolve_capability(*group.id(), [112; 32]).unwrap();
    assert!(restored.fetch(&reader, 0).unwrap().is_empty());
    let unread = restored.resolve_capability(*group.id(), [113; 32]).unwrap();
    assert_eq!(restored.fetch(&unread, 0).unwrap().len(), 1);
    assert_eq!(
        restored.append(&owner, b"rejected".to_vec(), 4),
        Err(StoreError::Unauthorized)
    );

    restored.expire_at(64);
    drop(restored);
    let expired =
        Store::durable(config(), GroupJournal::open(directory.path()).unwrap(), 64).unwrap();
    assert!(expired.resolve_capability(*group.id(), [112; 32]).is_none());
}

#[test]
fn durable_group_state_rejects_corrupt_ciphertext_on_restart() {
    let directory = tempdir().unwrap();
    let mut store =
        Store::durable(config(), GroupJournal::open(directory.path()).unwrap(), 1).unwrap();
    let group = store.register(registration(3)).unwrap();
    store
        .append(&group.writer(0), b"durable ciphertext".to_vec(), 2)
        .unwrap();
    drop(store);

    let connection = rusqlite::Connection::open(directory.path().join(GROUP_DATABASE)).unwrap();
    connection
        .execute("UPDATE entries SET ciphertext = X''", [])
        .unwrap();
    drop(connection);

    assert!(matches!(
        Store::durable(config(), GroupJournal::open(directory.path()).unwrap(), 3),
        Err(DurableError::Corrupt("invalid group entry"))
    ));
}
