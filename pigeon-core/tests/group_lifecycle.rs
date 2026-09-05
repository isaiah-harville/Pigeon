use ed25519_dalek::{Signer, SigningKey};
use pigeon_core::{
    CoordinatorBinding, GroupAction, GroupCreationConfig, GroupEngine, GroupId, GroupJoinMaterial,
    GroupMutationCandidate, IdentityError, IdentityPurpose, PolicyEventKind, SecureIdentity,
    TransactionalOpenMlsStorage,
};

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

fn creation(
    group_id: GroupId,
    coordination_id: [u8; 32],
    name: impl Into<String>,
) -> GroupCreationConfig {
    GroupCreationConfig {
        group_id,
        name: name.into(),
        relay_url: "https://relay.example".into(),
        coordinator: CoordinatorBinding::new(coordination_id, TestIdentity::new(60).root_public()),
        mesh_enabled: false,
    }
}

fn join_material(
    member: &TestIdentity,
    owner: &TestIdentity,
    group_id: GroupId,
    coordination_id: [u8; 32],
    storage: &mut TransactionalOpenMlsStorage,
) -> GroupJoinMaterial {
    GroupJoinMaterial::issue(
        member,
        owner.root_public(),
        group_id,
        coordination_id,
        storage,
    )
    .unwrap()
}

#[test]
fn three_members_join_and_merge_an_owner_rename() {
    let alice = TestIdentity::new(1);
    let bob = TestIdentity::new(2);
    let carol = TestIdentity::new(3);
    let mut alice_storage = TransactionalOpenMlsStorage::new();
    let mut bob_storage = TransactionalOpenMlsStorage::new();
    let mut carol_storage = TransactionalOpenMlsStorage::new();

    let group_id = GroupId::from_bytes([8; 32]);
    let coordination_id = [9; 32];
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
        creation(group_id, coordination_id, "Bird Watchers"),
        vec![bob_material, carol_material],
    )
    .unwrap();

    let mut bob_group = GroupEngine::join_welcome(&bob, &mut bob_storage, &welcome).unwrap();
    let carol_group = GroupEngine::join_welcome(&carol, &mut carol_storage, &welcome).unwrap();

    assert_eq!(alice_group.group_id(), bob_group.group_id());
    assert_eq!(alice_group.group_id(), carol_group.group_id());
    assert_eq!(alice_group.epoch(), 1);
    assert_eq!(bob_group.epoch(), 1);
    assert_eq!(alice_group.policy().name(), "Bird Watchers");
    assert_eq!(alice_group.policy(), bob_group.policy());
    assert_eq!(alice_group.policy(), carol_group.policy());

    let unauthorized = bob_group.stage_candidate(
        &bob,
        &mut bob_storage,
        GroupAction::Rename {
            actor: bob.root_public(),
            name: "Mallards".into(),
        },
        None,
    );
    assert!(unauthorized.is_err());

    let pending = alice_group
        .stage_candidate(
            &alice,
            &mut alice_storage,
            GroupAction::Rename {
                actor: alice.root_public(),
                name: "Mallards".into(),
            },
            None,
        )
        .unwrap();
    assert_eq!(alice_group.policy().name(), "Bird Watchers");

    let local_event = alice_group
        .merge_canonical(&mut alice_storage, pending.commit())
        .unwrap();
    let remote_event = bob_group
        .merge_canonical(&mut bob_storage, pending.commit())
        .unwrap();

    assert_eq!(local_event.kind, PolicyEventKind::NameChanged);
    assert_eq!(local_event, remote_event);
    assert_eq!(alice_group.policy().name(), "Mallards");
    assert_eq!(alice_group.policy(), bob_group.policy());
    assert_eq!(alice_group.epoch(), 2);
    assert_eq!(bob_group.epoch(), 2);
}

#[test]
fn membership_and_admin_changes_share_one_authenticated_commit() {
    let alice = TestIdentity::new(11);
    let bob = TestIdentity::new(12);
    let carol = TestIdentity::new(13);
    let dave = TestIdentity::new(14);
    let mut alice_storage = TransactionalOpenMlsStorage::new();
    let mut bob_storage = TransactionalOpenMlsStorage::new();
    let mut carol_storage = TransactionalOpenMlsStorage::new();
    let mut dave_storage = TransactionalOpenMlsStorage::new();

    let group_id = GroupId::from_bytes([18; 32]);
    let coordination_id = [19; 32];
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
        creation(group_id, coordination_id, "Four Birds"),
        vec![bob_material, carol_material],
    )
    .unwrap();
    let mut bob_group = GroupEngine::join_welcome(&bob, &mut bob_storage, &welcome).unwrap();
    let mut carol_group = GroupEngine::join_welcome(&carol, &mut carol_storage, &welcome).unwrap();

    let dave_material = join_material(&dave, &alice, group_id, coordination_id, &mut dave_storage);
    let add = alice_group
        .stage_candidate(
            &alice,
            &mut alice_storage,
            GroupAction::Add {
                actor: alice.root_public(),
                member_keys: Box::new(dave_material.member_keys()),
            },
            Some(dave_material),
        )
        .unwrap();
    let dave_welcome = add.welcome().expect("an add commit must carry a Welcome");
    assert_eq!(
        alice_group
            .merge_canonical(&mut alice_storage, add.commit())
            .unwrap()
            .kind,
        PolicyEventKind::MemberAdded
    );
    bob_group
        .merge_canonical(&mut bob_storage, add.commit())
        .unwrap();
    carol_group
        .merge_canonical(&mut carol_storage, add.commit())
        .unwrap();
    let mut dave_group = GroupEngine::join_welcome(&dave, &mut dave_storage, dave_welcome).unwrap();
    assert_eq!(alice_group.policy(), dave_group.policy());

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
    assert_eq!(
        bob_group
            .merge_canonical(&mut bob_storage, promote.commit())
            .unwrap()
            .kind,
        PolicyEventKind::AdminPromoted
    );
    carol_group
        .merge_canonical(&mut carol_storage, promote.commit())
        .unwrap();
    dave_group
        .merge_canonical(&mut dave_storage, promote.commit())
        .unwrap();

    let remove = bob_group
        .stage_candidate(
            &bob,
            &mut bob_storage,
            GroupAction::Remove {
                actor: bob.root_public(),
                subject: dave.root_public(),
            },
            None,
        )
        .unwrap();
    bob_group
        .merge_canonical(&mut bob_storage, remove.commit())
        .unwrap();
    assert_eq!(
        alice_group
            .merge_canonical(&mut alice_storage, remove.commit())
            .unwrap()
            .kind,
        PolicyEventKind::MemberRemoved
    );
    carol_group
        .merge_canonical(&mut carol_storage, remove.commit())
        .unwrap();
    dave_group
        .merge_canonical(&mut dave_storage, remove.commit())
        .unwrap();
    assert_eq!(alice_group.policy().members().len(), 3);
    assert_eq!(alice_group.policy(), bob_group.policy());

    let demote = alice_group
        .stage_candidate(
            &alice,
            &mut alice_storage,
            GroupAction::Demote {
                actor: alice.root_public(),
                subject: bob.root_public(),
            },
            None,
        )
        .unwrap();
    alice_group
        .merge_canonical(&mut alice_storage, demote.commit())
        .unwrap();
    assert_eq!(
        bob_group
            .merge_canonical(&mut bob_storage, demote.commit())
            .unwrap()
            .kind,
        PolicyEventKind::AdminDemoted
    );
    carol_group
        .merge_canonical(&mut carol_storage, demote.commit())
        .unwrap();
    assert_eq!(alice_group.epoch(), 5);
    assert_eq!(alice_group.policy(), carol_group.policy());
}

#[test]
fn ordinary_member_leave_requires_their_signed_proposal_and_another_committer() {
    let alice = TestIdentity::new(21);
    let bob = TestIdentity::new(22);
    let carol = TestIdentity::new(23);
    let dave = TestIdentity::new(24);
    let mut alice_storage = TransactionalOpenMlsStorage::new();
    let mut bob_storage = TransactionalOpenMlsStorage::new();
    let mut carol_storage = TransactionalOpenMlsStorage::new();
    let mut dave_storage = TransactionalOpenMlsStorage::new();

    let group_id = GroupId::from_bytes([28; 32]);
    let coordination_id = [29; 32];
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
        creation(group_id, coordination_id, "Leaving Birds"),
        vec![bob_material, carol_material],
    )
    .unwrap();
    let mut bob_group = GroupEngine::join_welcome(&bob, &mut bob_storage, &welcome).unwrap();
    let mut carol_group = GroupEngine::join_welcome(&carol, &mut carol_storage, &welcome).unwrap();
    assert!(
        carol_group
            .propose_leave(&carol, &mut carol_storage)
            .is_err(),
        "a three-member group cannot shrink"
    );

    let dave_material = join_material(&dave, &alice, group_id, coordination_id, &mut dave_storage);
    let add = alice_group
        .stage_candidate(
            &alice,
            &mut alice_storage,
            GroupAction::Add {
                actor: alice.root_public(),
                member_keys: Box::new(dave_material.member_keys()),
            },
            Some(dave_material),
        )
        .unwrap();
    let dave_welcome = add.welcome().unwrap().to_vec();
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
        GroupEngine::join_welcome(&dave, &mut dave_storage, &dave_welcome).unwrap();

    assert!(
        alice_group
            .propose_leave(&alice, &mut alice_storage)
            .is_err(),
        "the permanent owner cannot leave"
    );
    let proposal = dave_group.propose_leave(&dave, &mut dave_storage).unwrap();
    let mut tampered = proposal.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(
        carol_group
            .stage_leave_candidate(&carol, &mut carol_storage, dave.root_public(), &tampered)
            .is_err()
    );
    let leave = alice_group
        .stage_leave_candidate(&alice, &mut alice_storage, dave.root_public(), &proposal)
        .unwrap();
    let canonical = GroupMutationCandidate::new(vec![proposal], leave.commit().to_vec()).unwrap();
    let event = alice_group
        .merge_canonical_candidate(&mut alice_storage, &canonical)
        .unwrap();
    assert_eq!(event.kind, PolicyEventKind::MemberLeft);
    assert_eq!(event.actor, dave.root_public());
    assert_eq!(event.subject, Some(dave.root_public()));
    assert_eq!(
        carol_group
            .merge_canonical_candidate(&mut carol_storage, &canonical)
            .unwrap(),
        event
    );
    bob_group
        .merge_canonical_candidate(&mut bob_storage, &canonical)
        .unwrap();
    dave_group
        .merge_canonical_candidate(&mut dave_storage, &canonical)
        .unwrap();
    assert_eq!(alice_group.policy().members().len(), 3);
}

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
