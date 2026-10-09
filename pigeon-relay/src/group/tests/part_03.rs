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
