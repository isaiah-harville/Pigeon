#[test]
fn owner_settings_and_dissolution_are_canonical_mls_epochs() {
    let alice = TestIdentity::new(31);
    let bob = TestIdentity::new(32);
    let carol = TestIdentity::new(33);
    let mut alice_storage = TransactionalOpenMlsStorage::new();
    let mut bob_storage = TransactionalOpenMlsStorage::new();
    let mut carol_storage = TransactionalOpenMlsStorage::new();
    let group_id = GroupId::from_bytes([38; 32]);
    let coordination_id = [39; 32];
    let bob_material = join_material(&bob, &alice, group_id, coordination_id, &mut bob_storage);
    let carol_material = join_material(
        &carol,
        &alice,
        group_id,
        coordination_id,
        &mut carol_storage,
    );
    let (mut alice_group, welcome) = GroupEngine::create(
        &alice,
        &mut alice_storage,
        creation(group_id, coordination_id, "Settings Birds"),
        vec![bob_material, carol_material],
    )
    .unwrap();
    let mut bob_group = GroupEngine::join_welcome(&bob, &mut bob_storage, &welcome).unwrap();

    let actions = [
        GroupAction::SetMesh {
            actor: alice.root_public(),
            enabled: true,
        },
        GroupAction::SetRelay {
            actor: alice.root_public(),
            relay_url: "wss://new-relay.example".into(),
        },
        GroupAction::Dissolve {
            actor: alice.root_public(),
        },
    ];
    let expected = [
        PolicyEventKind::MeshChanged,
        PolicyEventKind::RelayChanged,
        PolicyEventKind::Dissolved,
    ];
    for (action, kind) in actions.into_iter().zip(expected) {
        let pending = alice_group
            .stage_candidate(&alice, &mut alice_storage, action, None)
            .unwrap();
        let local = alice_group
            .merge_canonical(&mut alice_storage, pending.commit())
            .unwrap();
        let remote = bob_group
            .merge_canonical(&mut bob_storage, pending.commit())
            .unwrap();
        assert_eq!(local.kind, kind);
        assert_eq!(local, remote);
    }
    assert_eq!(alice_group.epoch(), 4);
    assert_eq!(alice_group.policy(), bob_group.policy());
    assert!(
        alice_group
            .stage_candidate(
                &alice,
                &mut alice_storage,
                GroupAction::Rename {
                    actor: alice.root_public(),
                    name: "Too Late".into(),
                },
                None,
            )
            .is_err()
    );
}

#[test]
fn canonical_remote_commit_replaces_a_losing_local_candidate() {
    let alice = TestIdentity::new(41);
    let bob = TestIdentity::new(42);
    let carol = TestIdentity::new(43);
    let group_id = GroupId::from_bytes([41; 32]);
    let coordination_id = [42; 32];
    let mut alice_storage = TransactionalOpenMlsStorage::new();
    let mut bob_storage = TransactionalOpenMlsStorage::new();
    let mut carol_storage = TransactionalOpenMlsStorage::new();
    let bob_material = join_material(&bob, &alice, group_id, coordination_id, &mut bob_storage);
    let carol_material = join_material(
        &carol,
        &alice,
        group_id,
        coordination_id,
        &mut carol_storage,
    );
    let (mut alice_group, welcome) = GroupEngine::create(
        &alice,
        &mut alice_storage,
        creation(group_id, coordination_id, "Original"),
        vec![bob_material, carol_material],
    )
    .unwrap();
    let mut bob_group = GroupEngine::join_welcome(&bob, &mut bob_storage, &welcome).unwrap();
    let promote = alice_group
        .stage_candidate(
            &alice,
            &mut alice_storage,
            GroupAction::Promote {
                actor: alice.root_public(),
                subject: bob.root_public(),
            },
            None,
        )
        .unwrap();
    alice_group
        .merge_canonical(&mut alice_storage, promote.commit())
        .unwrap();
    bob_group
        .merge_canonical(&mut bob_storage, promote.commit())
        .unwrap();

    let winner = alice_group
        .stage_candidate(
            &alice,
            &mut alice_storage,
            GroupAction::Promote {
                actor: alice.root_public(),
                subject: carol.root_public(),
            },
            None,
        )
        .unwrap();
    bob_group
        .stage_candidate(
            &bob,
            &mut bob_storage,
            GroupAction::Promote {
                actor: bob.root_public(),
                subject: carol.root_public(),
            },
            None,
        )
        .unwrap();
    let canonical = GroupMutationCandidate::new(Vec::new(), winner.commit().to_vec()).unwrap();

    let event = bob_group
        .merge_canonical_candidate(&mut bob_storage, &canonical)
        .unwrap();

    assert_eq!(event.kind, PolicyEventKind::AdminPromoted);
    assert_eq!(event.actor, alice.root_public());
    assert!(bob_group.policy().is_admin(carol.root_public()));
}

#[test]
fn group_creation_accepts_the_three_and_128_member_boundaries() {
    for member_count in [3_usize, 32, 128] {
        let owner = TestIdentity::new(200);
        let mut owner_storage = TransactionalOpenMlsStorage::new();
        let group_id = GroupId::from_bytes([48; 32]);
        let coordination_id = [49; 32];
        let mut materials = Vec::with_capacity(member_count - 1);
        for byte in 1..member_count as u8 {
            let member = TestIdentity::new(byte);
            let mut member_storage = TransactionalOpenMlsStorage::new();
            materials.push(join_material(
                &member,
                &owner,
                group_id,
                coordination_id,
                &mut member_storage,
            ));
        }
        let (group, welcome) = GroupEngine::create(
            &owner,
            &mut owner_storage,
            creation(group_id, coordination_id, format!("{member_count} Birds")),
            materials,
        )
        .unwrap();
        assert_eq!(group.policy().members().len(), member_count);
        assert_eq!(group.epoch(), 1);
        assert!(!welcome.is_empty());
    }
}

#[test]
fn owner_can_create_group_before_any_invitees_join() {
    let owner = TestIdentity::new(200);
    let joiner = TestIdentity::new(201);
    let mut storage = TransactionalOpenMlsStorage::new();
    let mut joiner_storage = TransactionalOpenMlsStorage::new();
    let group_id = GroupId::from_bytes([51; 32]);
    let (mut group, welcome) = GroupEngine::create(
        &owner,
        &mut storage,
        creation(group_id, [52; 32], "Open Event"),
        Vec::new(),
    )
    .unwrap();
    assert_eq!(group.policy().members(), &[owner.root_public()]);
    assert_eq!(group.epoch(), 0);
    assert!(welcome.is_empty());
    let material = join_material(&joiner, &owner, group_id, [52; 32], &mut joiner_storage);
    let addition = group
        .stage_candidate(
            &owner,
            &mut storage,
            GroupAction::Add {
                actor: owner.root_public(),
                member_keys: Box::new(material.member_keys()),
            },
            Some(material),
        )
        .unwrap();
    assert_eq!(addition.next_policy().members().len(), 2);
    assert!(!addition.welcome().unwrap().is_empty());
}
