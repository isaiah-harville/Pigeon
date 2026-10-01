use super::protocol::{
    challenge_transcript, gate_group_message, registration_transcript, verify_admission_solution,
    verify_challenge, verify_registration, CapabilityWire, GroupClientMsg, GroupProtocolGate,
    GroupServerMsg,
};
use super::store::{
    CapabilityRegistration, Config, GroupCapability, GroupRegistration, Store, StoreError,
};
use super::{RegistrationAdmission, RegistrationAttempts};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use tempfile::tempdir;

use crate::durable::{
    reclaim_empty_group, CoordinatorJournal, DurableError, GroupJournal, GROUP_DATABASE,
};

fn config() -> Config {
    Config {
        ttl_secs: 60,
        lease_secs: 60,
        max_groups: 4,
        max_capabilities_per_group: 128,
        max_entry_bytes: 1024,
        max_entries_per_group: 4,
        max_total_bytes: 4096,
        max_fetch_batch_bytes: 2048,
    }
}

#[test]
fn registration_admission_limits_one_window_and_recovers_next_window() {
    let mut admission = RegistrationAdmission::default();
    for _ in 0..60 {
        assert!(admission.admit(100));
    }
    assert!(!admission.admit(159));
    assert!(admission.admit(160));
}

#[test]
fn admission_work_is_bound_to_challenge_and_registration() {
    let registration = registration(3);
    let transcript = registration_transcript(
        registration.coordination_id,
        registration.authorization_generation,
        registration.permanent_controller_public_key,
        &registration.capabilities,
    );
    let challenge = [7_u8; 32];
    let solution = (0_u64..)
        .find(|nonce| verify_admission_solution(&challenge, &transcript, &nonce.to_be_bytes(), 12))
        .unwrap()
        .to_be_bytes();
    assert!(verify_admission_solution(
        &challenge,
        &transcript,
        &solution,
        12
    ));
    assert!(!verify_admission_solution(
        &[8; 32],
        &transcript,
        &solution,
        12
    ));
    let mut other = transcript.clone();
    other.push(1);
    assert!(!verify_admission_solution(
        &challenge, &other, &solution, 12
    ));
}

#[test]
fn socket_registration_attempts_are_bounded() {
    let mut attempts = RegistrationAttempts::default();
    for _ in 0..8 {
        assert!(attempts.admit());
    }
    assert!(!attempts.admit());
}

#[test]
fn existing_registration_is_visible_to_admission_check() {
    let mut store = Store::bounded(config());
    let registration = registration(3);
    assert!(!store.contains_group(&registration.coordination_id));
    store.register(registration.clone()).unwrap();
    assert!(store.contains_group(&registration.coordination_id));
}

#[test]
fn owner_only_registration_can_submit_first_epoch_zero_commit() {
    let mut groups = Store::bounded(config());
    let group = groups.register(registration(1)).unwrap();
    assert!(groups.can_append(&group.writer(0)));
    let mut coordinator = crate::coordinator::store::Store::new(
        crate::coordinator::store::Config {
            max_logs: 1,
            max_candidates_per_log: 4,
            max_candidates_per_epoch: 4,
            max_candidates_per_capability_per_epoch: 4,
            max_candidate_bytes: 128,
            max_total_bytes: 1024,
            max_fetch_batch_bytes: 1024,
            ttl_secs: 60,
        },
        SigningKey::from_bytes(&[77; 32]),
    );
    let receipt = coordinator
        .submit(
            *group.id(),
            group.writer(0).capability_id,
            0,
            b"first".to_vec(),
            1,
        )
        .unwrap();
    assert_eq!(receipt.claimed_base_epoch, 0);
}

#[test]
fn inactive_group_reactivates_without_resetting_authorization_or_sequence() {
    let directory = tempdir().unwrap();
    let mut limits = config();
    limits.max_groups = 1;
    limits.lease_secs = 5;
    limits.ttl_secs = 60;
    let mut store = Store::durable(
        limits.clone(),
        GroupJournal::open(directory.path()).unwrap(),
        1,
    )
    .unwrap();
    let first = registration(3);
    let group = store.register_at(first.clone(), 1).unwrap();
    store.append(&group.writer(0), vec![1], 2).unwrap();
    store.expire_at(8);
    assert!(!store.groups_active_for_test(&first.coordination_id));
    assert_eq!(store.total_bytes(), 1);
    assert!(store.contains_group(&first.coordination_id));
    assert!(store.register_at(first.clone(), 8).is_ok());
    let mut stale = first.clone();
    stale.capabilities[1].capability_id = [44; 32];
    assert_eq!(
        store.register_at(stale, 8),
        Err(StoreError::AlreadyRegistered)
    );
    let mut second = registration(3);
    second.coordination_id = [8; 32];
    store.register_at(second, 8).unwrap();
    assert_eq!(
        store.activate(&group.reader(1), 8),
        Err(StoreError::AtCapacity)
    );
    drop(store);
    let mut store =
        Store::durable(limits, GroupJournal::open(directory.path()).unwrap(), 14).unwrap();
    let reader = store
        .resolve_capability(first.coordination_id, group.reader(1).capability_id)
        .unwrap();
    store.activate(&reader, 14).unwrap();
    assert_eq!(store.fetch(&reader, 0).unwrap()[0].ciphertext, vec![1]);
    assert_eq!(
        store
            .append(&group.writer(0), vec![2], 15)
            .unwrap()
            .sequence,
        2
    );
}

#[test]
fn removed_capability_cannot_reactivate_inactive_group() {
    let directory = tempdir().unwrap();
    let mut limits = config();
    limits.lease_secs = 5;
    let mut store =
        Store::durable(limits, GroupJournal::open(directory.path()).unwrap(), 1).unwrap();
    let group = store.register_at(registration(3), 1).unwrap();
    let removed = group.reader(2);
    let retained = group.reader(1);
    let mut replacements = registration(3).capabilities;
    replacements[2].capability_id = [104; 32];
    replacements[2].public_key = [4; 32];
    store
        .replace_capabilities(&group.writer(0), 0, 1, [1; 32], replacements)
        .unwrap();
    store.expire_at(7);
    assert!(store
        .resolve_capability(*group.id(), removed.capability_id)
        .is_none());
    assert_eq!(store.activate(&removed, 7), Err(StoreError::Unauthorized));
    store.activate(&retained, 7).unwrap();
    assert_eq!(
        store.append(&group.writer(0), vec![7], 8).unwrap().sequence,
        1
    );
}

#[test]
fn inactive_ciphertext_still_counts_toward_byte_quota_after_restart() {
    let directory = tempdir().unwrap();
    let mut limits = config();
    limits.lease_secs = 5;
    limits.ttl_secs = 60;
    limits.max_total_bytes = 1;
    let mut store = Store::durable(
        limits.clone(),
        GroupJournal::open(directory.path()).unwrap(),
        1,
    )
    .unwrap();
    let first = store.register_at(registration(3), 1).unwrap();
    store.append(&first.writer(0), vec![1], 2).unwrap();
    store.expire_at(8);
    drop(store);
    let mut store =
        Store::durable(limits, GroupJournal::open(directory.path()).unwrap(), 8).unwrap();
    assert_eq!(store.total_bytes(), 1);
    let mut second = registration(3);
    second.coordination_id = [8; 32];
    let second = store.register_at(second, 8).unwrap();
    assert_eq!(
        store.append(&second.writer(0), vec![2], 8),
        Err(StoreError::AtCapacity)
    );
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
fn unused_registrations_expire_but_used_groups_keep_their_authorization() {
    let mut limits = config();
    limits.max_groups = 2;
    let mut store = Store::bounded(limits);
    let idle = store.register(registration(3)).unwrap();
    let mut used_registration = registration(3);
    used_registration.coordination_id = [10; 32];
    let used = store.register(used_registration).unwrap();
    store.append(&used.writer(0), b"used".to_vec(), 1).unwrap();
    store.expire_at(62);

    assert!(store
        .resolve_capability(*idle.id(), idle.reader(0).capability_id)
        .is_none());
    assert!(store
        .resolve_capability(*used.id(), used.reader(0).capability_id)
        .is_some());
    let mut replacement = registration(3);
    replacement.coordination_id = [11; 32];
    assert!(store.register(replacement).is_ok());
}

#[test]
fn expired_registration_id_remains_bound_to_original_controller() {
    let mut store = Store::bounded(config());
    let original = registration(3);
    store.register(original.clone()).unwrap();
    store.expire_at(62);

    let mut takeover = original.clone();
    takeover.permanent_controller_public_key = [2; 32];
    takeover.capabilities[1].can_control = true;
    assert_eq!(store.register(takeover), Err(StoreError::AlreadyRegistered));
    assert!(store.register(original).is_ok());
}

#[test]
fn unused_registration_is_reclaimed_before_durable_capacity_check() {
    let directory = tempdir().unwrap();
    let mut limits = config();
    limits.max_groups = 1;
    let mut store = Store::durable(
        limits.clone(),
        GroupJournal::open(directory.path()).unwrap(),
        1,
    )
    .unwrap();
    store.register(registration(3)).unwrap();
    drop(store);

    let mut restored =
        Store::durable(limits, GroupJournal::open(directory.path()).unwrap(), 62).unwrap();
    let mut replacement = registration(3);
    replacement.coordination_id = [11; 32];
    assert!(restored.register(replacement).is_ok());
}

#[test]
fn durable_expired_id_rejects_a_new_controller_after_restart() {
    let directory = tempdir().unwrap();
    let mut store =
        Store::durable(config(), GroupJournal::open(directory.path()).unwrap(), 1).unwrap();
    let original = registration(3);
    store.register(original.clone()).unwrap();
    drop(store);
    let mut restored =
        Store::durable(config(), GroupJournal::open(directory.path()).unwrap(), 62).unwrap();
    let mut takeover = original;
    takeover.permanent_controller_public_key = [2; 32];
    takeover.capabilities[1].can_control = true;
    assert_eq!(
        restored.register(takeover),
        Err(StoreError::AlreadyRegistered)
    );
    let mut changed = registration(3);
    changed.authorization_generation = 1;
    assert_eq!(
        restored.register(changed),
        Err(StoreError::AlreadyRegistered)
    );
}

#[test]
fn coordinator_activity_keeps_group_authorization_across_restart() {
    let directory = tempdir().unwrap();
    let mut store =
        Store::durable(config(), GroupJournal::open(directory.path()).unwrap(), 1).unwrap();
    let group = store.register(registration(3)).unwrap();
    store.mark_coordinator_activity(group.id());
    drop(store);

    let restored =
        Store::durable(config(), GroupJournal::open(directory.path()).unwrap(), 62).unwrap();
    assert!(restored
        .resolve_capability(*group.id(), group.reader(0).capability_id)
        .is_some());
}

#[test]
fn operator_can_reclaim_empty_registration_across_restart() {
    let directory = tempdir().unwrap();
    CoordinatorJournal::open(directory.path(), [77; 32]).unwrap();
    let mut limits = config();
    limits.max_groups = 1;
    let mut store = Store::durable(
        limits.clone(),
        GroupJournal::open(directory.path()).unwrap(),
        1,
    )
    .unwrap();
    let idle = store.register(registration(3)).unwrap();
    drop(store);

    assert!(reclaim_empty_group(directory.path(), idle.id()).unwrap());
    let mut restored =
        Store::durable(limits, GroupJournal::open(directory.path()).unwrap(), 2).unwrap();
    let mut takeover = registration(3);
    takeover.permanent_controller_public_key = [2; 32];
    takeover.capabilities[1].can_control = true;
    assert_eq!(
        restored.register(takeover),
        Err(StoreError::AlreadyRegistered)
    );
    let mut replacement = registration(3);
    replacement.coordination_id = [11; 32];
    assert!(restored.register(replacement).is_ok());
}

#[test]
fn operator_reclamation_refuses_unread_ciphertext() {
    let directory = tempdir().unwrap();
    CoordinatorJournal::open(directory.path(), [77; 32]).unwrap();
    let mut store =
        Store::durable(config(), GroupJournal::open(directory.path()).unwrap(), 1).unwrap();
    let group = store.register(registration(3)).unwrap();
    store
        .append(&group.writer(0), b"unread".to_vec(), 2)
        .unwrap();
    drop(store);

    assert!(!reclaim_empty_group(directory.path(), group.id()).unwrap());
    let restored =
        Store::durable(config(), GroupJournal::open(directory.path()).unwrap(), 3).unwrap();
    assert_eq!(restored.fetch(&group.reader(1), 0).unwrap().len(), 1);
}

#[test]
fn operator_reclamation_preserves_coordinator_receipt_head() {
    let directory = tempdir().unwrap();
    let signer = SigningKey::from_bytes(&[77; 32]);
    let journal =
        CoordinatorJournal::open(directory.path(), signer.verifying_key().to_bytes()).unwrap();
    let mut coordinator = crate::coordinator::store::Store::durable(
        crate::coordinator::store::Config {
            max_logs: 1,
            max_candidates_per_log: 4,
            max_candidates_per_epoch: 4,
            max_candidates_per_capability_per_epoch: 4,
            max_candidate_bytes: 128,
            max_total_bytes: 1024,
            max_fetch_batch_bytes: 1024,
            ttl_secs: 60,
        },
        signer,
        journal,
        1,
    )
    .unwrap();
    let mut group_store =
        Store::durable(config(), GroupJournal::open(directory.path()).unwrap(), 1).unwrap();
    let group = group_store.register(registration(3)).unwrap();
    let first = coordinator
        .submit(*group.id(), [1; 32], 1, b"candidate".to_vec(), 1)
        .unwrap();
    coordinator.expire_at(62);
    drop(coordinator);
    drop(group_store);

    assert!(reclaim_empty_group(directory.path(), group.id()).unwrap());
    let signer = SigningKey::from_bytes(&[77; 32]);
    let journal =
        CoordinatorJournal::open(directory.path(), signer.verifying_key().to_bytes()).unwrap();
    let mut coordinator = crate::coordinator::store::Store::durable(
        crate::coordinator::store::Config {
            max_logs: 1,
            max_candidates_per_log: 4,
            max_candidates_per_epoch: 4,
            max_candidates_per_capability_per_epoch: 4,
            max_candidate_bytes: 128,
            max_total_bytes: 1024,
            max_fetch_batch_bytes: 1024,
            ttl_secs: 60,
        },
        signer,
        journal,
        62,
    )
    .unwrap();
    let next = coordinator
        .submit(*group.id(), [1; 32], 2, b"next".to_vec(), 62)
        .unwrap();
    assert_eq!(next.sequence, first.sequence + 1);
    assert_eq!(next.prior_receipt_hash, first.receipt_hash());
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
                max_protocol_version: 7,
            },
            &mut negotiated
        ),
        GroupProtocolGate::Reply(GroupServerMsg::Compatible {
            protocol_version: 7,
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
    assert_eq!(
        store.register(registration(3)),
        Err(StoreError::AlreadyRegistered)
    );
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
    let mut expired =
        Store::durable(config(), GroupJournal::open(directory.path()).unwrap(), 64).unwrap();
    assert!(expired.resolve_capability(*group.id(), [112; 32]).is_none());
    assert_eq!(
        expired.register(registration(3)),
        Err(StoreError::AlreadyRegistered)
    );
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
