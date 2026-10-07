#[test]
fn owner_only_group_is_created_and_durable_in_one_transaction() {
    let mut client = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(1)).unwrap();
    let command = ClientCommand::create_group(
        "owner-only",
        "Open Event",
        vec![],
        "https://relay.example",
        TestIdentity::new(60).root_public(),
        false,
    )
    .unwrap();
    let output = client.execute(command).unwrap();
    assert_eq!(output.checkpoint_generation, 1);
    assert_eq!(output.outbound.len(), 1);
    assert_eq!(
        wire_proto::OutboundItem::decode(output.outbound[0].encode().as_slice())
            .unwrap()
            .kind,
        wire_proto::OutboundKind::GroupRelayRegistration as i32
    );
    assert_eq!(output.events.len(), 1);
    let checkpoint = client.store().load().unwrap().unwrap();
    let state = wire_proto::ClientCheckpoint::decode(checkpoint.bytes.as_slice()).unwrap();
    assert_eq!(state.groups.len(), 1);
    assert!(state.pending_group_creations.is_empty());
}

#[test]
fn final_join_material_atomically_creates_the_real_mls_group() {
    let (mut client, mut bob, mut carol) = group_clients();

    let pending = client.execute(create_group()).unwrap();
    assert!(pending.events.is_empty());
    assert_eq!(pending.outbound.len(), 2);
    let bob_material = receive_group_control(&mut bob, "bob-material", &pending.outbound[0]);
    let carol_material = receive_group_control(&mut carol, "carol-material", &pending.outbound[1]);

    let one = client
        .execute(
            ClientCommand::apply_pairwise_control(
                "command-2",
                wire_proto::OutboundItem::decode(bob_material.outbound[0].encode().as_slice())
                    .unwrap()
                    .payload,
            )
            .unwrap(),
        )
        .unwrap();
    assert!(one.events.is_empty());
    assert!(one.outbound.is_empty());

    let created = client
        .execute(
            ClientCommand::apply_pairwise_control(
                "command-3",
                wire_proto::OutboundItem::decode(carol_material.outbound[0].encode().as_slice())
                    .unwrap()
                    .payload,
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        created.checkpoint_generation,
        pending.checkpoint_generation + 2
    );
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
    assert_eq!(
        client.checkpoint_generation(),
        created.checkpoint_generation
    );
}

#[test]
fn snapshot_rebuilds_group_projection_without_advancing_checkpoint() {
    let anchored = create_anchored_group();
    let generation = anchored.owner.checkpoint_generation();

    let snapshot =
        wire_proto::ClientSnapshot::decode(anchored.owner.snapshot().unwrap().encode().as_slice())
            .unwrap();

    assert_eq!(snapshot.checkpoint_generation, generation);
    assert_eq!(anchored.owner.checkpoint_generation(), generation);
    assert_eq!(snapshot.groups.len(), 1);
    let group = &snapshot.groups[0];
    assert_eq!(group.group_id, anchored.group_id.as_bytes());
    assert_eq!(group.owner_identity, TestIdentity::new(1).root_public());
    assert_eq!(
        group.admin_identities,
        vec![TestIdentity::new(1).root_public()]
    );
    assert_eq!(group.member_identities.len(), 3);
    assert_eq!(group.name, "Friends");
    assert_eq!(group.relay_url, "https://relay.example");
    assert_eq!(group.coordination_id, anchored.coordination_id);
    assert_eq!(group.capability_public_key.len(), 32);
    assert_eq!(group.capability_id.len(), 32);
    assert_eq!(
        group.coordinator_public_key,
        TestIdentity::new(60).root_public()
    );
    assert_eq!(group.epoch, 1);
    assert_eq!(group.policy_revision, 0);
    assert!(!group.mesh_enabled);
    assert!(!group.dissolved);
}

#[test]
fn relay_challenge_signature_is_bound_to_the_authenticated_group_capability() {
    let anchored = create_anchored_group();
    let nonce = [42_u8; 32];

    let signature = anchored
        .owner
        .sign_group_relay_challenge(anchored.group_id, nonce)
        .unwrap();

    let snapshot =
        wire_proto::ClientSnapshot::decode(anchored.owner.snapshot().unwrap().encode().as_slice())
            .unwrap();
    let group = &snapshot.groups[0];
    let capability_key: [u8; 32] = group.capability_public_key.as_slice().try_into().unwrap();
    let capability_id: [u8; 32] = group.capability_id.as_slice().try_into().unwrap();
    let mut transcript = b"pigeon.relay.group.challenge.v2".to_vec();
    transcript.extend_from_slice(&anchored.coordination_id);
    transcript.extend_from_slice(&capability_id);
    transcript.extend_from_slice(&nonce);

    ed25519_dalek::VerifyingKey::from_bytes(&capability_key)
        .unwrap()
        .verify_strict(
            &transcript,
            &ed25519_dalek::Signature::from_bytes(&signature),
        )
        .unwrap();
}

#[test]
fn outbound_effects_remain_in_the_snapshot_until_explicitly_acknowledged() {
    let (mut client, _, _) = group_clients();
    let output = client.execute(create_group()).unwrap();
    let first = wire_proto::OutboundItem::decode(output.outbound[0].encode().as_slice()).unwrap();

    let snapshot =
        wire_proto::ClientSnapshot::decode(client.snapshot().unwrap().encode().as_slice()).unwrap();
    assert_eq!(snapshot.pending_outbound.len(), 2);

    client
        .execute(
            ClientCommand::acknowledge_effects("ack-first", vec![first.item_id], Vec::new())
                .unwrap(),
        )
        .unwrap();
    let snapshot =
        wire_proto::ClientSnapshot::decode(client.snapshot().unwrap().encode().as_slice()).unwrap();
    assert_eq!(snapshot.pending_outbound.len(), 1);
}

#[test]
fn one_join_material_cannot_fill_two_group_drafts() {
    let (mut client, mut bob, _) = group_clients();
    let mut bob_storage = TransactionalOpenMlsStorage::new();
    client.execute(create_group()).unwrap();
    let checkpoint = client.store().load().unwrap().unwrap();
    let state = wire_proto::ClientCheckpoint::decode(checkpoint.bytes.as_slice()).unwrap();
    let draft = &state.pending_group_creations[0];
    let bob_material = GroupJoinMaterial::issue(
        &TestIdentity::new(2),
        TestIdentity::new(1).root_public(),
        GroupId::from_bytes(draft.group_id.as_slice().try_into().unwrap()),
        draft.coordination_id.as_slice().try_into().unwrap(),
        &mut bob_storage,
    )
    .unwrap();
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
    let first_wrapped = bob
        .execute(
            ClientCommand::send_pairwise_control(
                "first-wrapper",
                TestIdentity::new(1).root_public(),
                wire_proto::OutboundKind::GroupJoinMaterial,
                bob_material.encode(),
            )
            .unwrap(),
        )
        .unwrap();
    receive_group_control(&mut client, "first-response", &first_wrapped.outbound[0]);
    let generation = client.checkpoint_generation();

    let replay_wrapped = bob
        .execute(
            ClientCommand::send_pairwise_control(
                "second-wrapper",
                TestIdentity::new(1).root_public(),
                wire_proto::OutboundKind::GroupJoinMaterial,
                bob_material.encode(),
            )
            .unwrap(),
        )
        .unwrap();
    let replay = client.execute(
        ClientCommand::apply_pairwise_control(
            "replayed-response",
            wire_proto::OutboundItem::decode(replay_wrapped.outbound[0].encode().as_slice())
                .unwrap()
                .payload,
        )
        .unwrap(),
    );

    assert!(matches!(replay, Err(Error::InvalidSignature)));
    assert_eq!(client.checkpoint_generation(), generation);
}

#[test]
fn member_issues_join_material_only_after_its_checkpoint_advances() {
    let (mut creator_client, mut member_client, _) = group_clients();
    let pending = creator_client.execute(create_group()).unwrap();
    let prior_generation = member_client.checkpoint_generation();

    let response =
        receive_group_control(&mut member_client, "member-response", &pending.outbound[0]);

    assert_eq!(response.checkpoint_generation, prior_generation + 1);
    assert_eq!(member_client.checkpoint_generation(), prior_generation + 1);
    assert!(response.events.is_empty());
    assert_eq!(response.outbound.len(), 1);
    let material =
        wire_proto::OutboundItem::decode(response.outbound[0].encode().as_slice()).unwrap();
    assert_eq!(material.kind, wire_proto::OutboundKind::Pairwise as i32);
    assert_eq!(material.destination, TestIdentity::new(1).root_public());
    let accepted = receive_group_control(
        &mut creator_client,
        "owner-receives-material",
        &response.outbound[0],
    );
    assert!(accepted.events.is_empty());
}

#[test]
fn policy_change_persists_before_releasing_a_coordinator_submission() {
    let anchored = create_anchored_group();
    let mut client = anchored.owner;
    let group_id = anchored.group_id;
    let coordination_id = anchored.coordination_id;
    let prior_generation = client.checkpoint_generation();

    let staged = client
        .execute(ClientCommand::rename_group("rename-1", group_id, "Best Friends").unwrap())
        .unwrap();

    assert_eq!(staged.checkpoint_generation, prior_generation + 1);
    assert!(staged.events.is_empty());
    assert_eq!(staged.outbound.len(), 1);
    let outbound =
        wire_proto::OutboundItem::decode(staged.outbound[0].encode().as_slice()).unwrap();
    assert_eq!(
        outbound.kind,
        wire_proto::OutboundKind::GroupCoordinator as i32
    );
    let submission =
        wire_proto::GroupCoordinatorSubmission::decode(outbound.payload.as_slice()).unwrap();
    assert_eq!(submission.claimed_base_epoch, 1);
    assert!(!submission.candidate.is_empty());
    assert!(
        client
            .execute(
                ClientCommand::rename_group("rename-while-pending", group_id, "Other").unwrap()
            )
            .is_err()
    );
    assert_eq!(client.checkpoint_generation(), prior_generation + 1);

    let canonical = coordinator_candidate(&submission, 2, anchored.receipt_head, coordination_id);
    let merged = client
        .execute(
            ClientCommand::apply_group_coordinator_candidate("rename-receipt", canonical).unwrap(),
        )
        .unwrap();
    assert_eq!(merged.checkpoint_generation, prior_generation + 2);
    assert!(merged.events.is_empty());
    assert_eq!(merged.outbound.len(), 1);
    let control = wire_proto::OutboundItem::decode(merged.outbound[0].encode().as_slice()).unwrap();
    assert_eq!(
        control.kind,
        wire_proto::OutboundKind::GroupRelayControl as i32
    );
    let acknowledged = client
        .execute(
            ClientCommand::acknowledge_effects(
                "ack-rename-relay-control",
                vec![control.item_id],
                Vec::new(),
            )
            .unwrap(),
        )
        .unwrap();
    let event = wire_proto::AppEvent::decode(acknowledged.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupPolicyChanged(change) = event.body.unwrap() else {
        panic!("expected canonical policy event");
    };
    assert_eq!(
        change.kind,
        wire_proto::GroupPolicyChangeKind::NameChanged as i32
    );
    assert_eq!(change.name, "Best Friends");
    assert_eq!(change.epoch, 2);
    assert_eq!(change.policy_revision, 1);
}
