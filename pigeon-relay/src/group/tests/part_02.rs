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
