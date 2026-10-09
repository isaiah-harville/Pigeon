#[test]
fn snapshot_exposes_durable_coordinator_cursor() {
    let anchored = create_anchored_group();
    let snapshot =
        wire_proto::ClientSnapshot::decode(anchored.owner.snapshot().unwrap().encode().as_slice())
            .unwrap();

    assert_eq!(snapshot.groups.len(), 1);
    assert_eq!(snapshot.groups[0].coordinator_sequence, 1);
}

#[test]
fn invalid_coordinator_entry_is_consumed_before_a_later_valid_commit() {
    let anchored = create_anchored_group();
    let mut owner = anchored.owner;
    let staged = owner
        .execute(
            ClientCommand::rename_group("stage-valid-rename", anchored.group_id, "Swifts").unwrap(),
        )
        .unwrap();
    let outbound =
        wire_proto::OutboundItem::decode(staged.outbound[0].encode().as_slice()).unwrap();
    let valid_submission =
        wire_proto::GroupCoordinatorSubmission::decode(outbound.payload.as_slice()).unwrap();
    let mut invalid_submission = valid_submission.clone();
    invalid_submission.candidate = vec![0xff, 0x00, 0x01];
    let invalid = coordinator_candidate(
        &invalid_submission,
        2,
        anchored.receipt_head,
        anchored.coordination_id,
    );
    let invalid_receipt_head = CoordinatorReceipt::decode_candidate(&invalid)
        .unwrap()
        .0
        .receipt_hash();

    let rejected = owner
        .execute(
            ClientCommand::apply_group_coordinator_candidate("consume-invalid", invalid).unwrap(),
        )
        .unwrap();
    assert_eq!(rejected.events.len(), 1);
    let warning = wire_proto::AppEvent::decode(rejected.events[0].encode().as_slice()).unwrap();
    assert!(matches!(
        warning.body,
        Some(wire_proto::app_event::Body::GroupSecurityWarning(_))
    ));
    let after_invalid =
        wire_proto::ClientSnapshot::decode(owner.snapshot().unwrap().encode().as_slice()).unwrap();
    assert_eq!(after_invalid.groups[0].coordinator_sequence, 2);
    assert_eq!(after_invalid.groups[0].name, "Friends");

    let valid = coordinator_candidate(
        &valid_submission,
        3,
        invalid_receipt_head,
        anchored.coordination_id,
    );
    owner
        .execute(
            ClientCommand::apply_group_coordinator_candidate("merge-valid-after-invalid", valid)
                .unwrap(),
        )
        .unwrap();
    let merged =
        wire_proto::ClientSnapshot::decode(owner.snapshot().unwrap().encode().as_slice()).unwrap();
    assert_eq!(merged.groups[0].coordinator_sequence, 3);
    assert_eq!(merged.groups[0].name, "Swifts");
}

#[test]
fn invalid_sequenced_group_message_is_durably_classified() {
    let anchored = create_anchored_group();
    let mut owner = anchored.owner;
    let generation = owner.checkpoint_generation();
    let command =
        ClientCommand::apply_group_message("relay-group-sequence-2", vec![0xff, 0x00, 0x01])
            .unwrap();

    let rejected = owner.execute(command).unwrap();

    assert!(rejected.events.is_empty());
    assert!(rejected.outbound.is_empty());
    assert_eq!(owner.checkpoint_generation(), generation + 1);
    let replay = owner
        .execute(
            ClientCommand::apply_group_message("relay-group-sequence-2", vec![0xff, 0x00, 0x01])
                .unwrap(),
        )
        .unwrap();
    assert!(replay.events.is_empty());
    assert!(replay.outbound.is_empty());
    assert_eq!(owner.checkpoint_generation(), generation + 1);
}

struct GroupWithDave {
    owner: PigeonClient<MemoryStateStore, TestIdentity>,
    dave: PigeonClient<MemoryStateStore, TestIdentity>,
    group_id: GroupId,
    coordination_id: [u8; 32],
    receipt_head: [u8; 32],
}

fn create_group_with_dave() -> GroupWithDave {
    let anchored = create_anchored_group();
    let mut owner = anchored.owner;
    let group_id = anchored.group_id;
    let coordination_id = anchored.coordination_id;
    let receipt_head = anchored.receipt_head;
    let mut dave = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(4)).unwrap();
    register_pairwise_peers(&mut owner, &mut dave, "helper-dave");
    let invited = owner
        .execute(
            ClientCommand::add_group_member(
                "helper-invite-dave",
                group_id,
                TestIdentity::new(4).root_public(),
            )
            .unwrap(),
        )
        .unwrap();
    let request =
        wire_proto::OutboundItem::decode(invited.outbound[0].encode().as_slice()).unwrap();
    let material_output = dave
        .execute(
            ClientCommand::apply_pairwise_control("helper-dave-material", request.payload).unwrap(),
        )
        .unwrap();
    let material =
        wire_proto::OutboundItem::decode(material_output.outbound[0].encode().as_slice()).unwrap();
    let staged = owner
        .execute(
            ClientCommand::apply_pairwise_control("helper-apply-dave", material.payload).unwrap(),
        )
        .unwrap();
    let submission_item =
        wire_proto::OutboundItem::decode(staged.outbound[0].encode().as_slice()).unwrap();
    let submission =
        wire_proto::GroupCoordinatorSubmission::decode(submission_item.payload.as_slice()).unwrap();
    let canonical = coordinator_candidate(&submission, 2, receipt_head, coordination_id);
    let receipt_head = CoordinatorReceipt::decode_candidate(&canonical)
        .unwrap()
        .0
        .receipt_hash();
    let merged = owner
        .execute(
            ClientCommand::apply_group_coordinator_candidate(
                "helper-merge-dave",
                canonical.clone(),
            )
            .unwrap(),
        )
        .unwrap();
    let welcome = merged
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| {
            item.kind == wire_proto::OutboundKind::Pairwise as i32
                && item.destination == TestIdentity::new(4).root_public()
        })
        .unwrap();
    let relay_control = merged
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupRelayControl as i32)
        .unwrap();
    owner
        .execute(
            ClientCommand::acknowledge_effects(
                "helper-ack-add-relay-control",
                vec![relay_control.item_id],
                Vec::new(),
            )
            .unwrap(),
        )
        .unwrap();
    dave.execute(
        ClientCommand::apply_pairwise_control("helper-join-dave", welcome.payload).unwrap(),
    )
    .unwrap();
    dave.execute(
        ClientCommand::apply_group_coordinator_candidate(
            "helper-anchor-initial",
            anchored.initial_candidate,
        )
        .unwrap(),
    )
    .unwrap();
    dave.execute(
        ClientCommand::apply_group_coordinator_candidate("helper-anchor-add", canonical).unwrap(),
    )
    .unwrap();
    GroupWithDave {
        owner,
        dave,
        group_id,
        coordination_id,
        receipt_head,
    }
}

#[test]
fn non_admin_policy_event_waits_for_replacement_relay_authentication() {
    let group = create_group_with_dave();
    let mut owner = group.owner;
    let mut dave = group.dave;

    let staged = owner
        .execute(ClientCommand::rename_group("rename", group.group_id, "Renamed").unwrap())
        .unwrap();
    let submission_item =
        wire_proto::OutboundItem::decode(staged.outbound[0].encode().as_slice()).unwrap();
    let submission =
        wire_proto::GroupCoordinatorSubmission::decode(submission_item.payload.as_slice()).unwrap();
    let canonical =
        coordinator_candidate(&submission, 3, group.receipt_head, group.coordination_id);

    owner
        .execute(
            ClientCommand::apply_group_coordinator_candidate(
                "owner-merges-rename",
                canonical.clone(),
            )
            .unwrap(),
        )
        .unwrap();
    let observed = dave
        .execute(
            ClientCommand::apply_group_coordinator_candidate("dave-observes-rename", canonical)
                .unwrap(),
        )
        .unwrap();
    assert!(observed.events.is_empty());
    assert!(observed.outbound.is_empty());

    let snapshot =
        wire_proto::ClientSnapshot::decode(dave.snapshot().unwrap().encode().as_slice()).unwrap();
    let capability_id: [u8; 32] = snapshot.groups[0]
        .capability_id
        .as_slice()
        .try_into()
        .unwrap();
    assert!(
        dave.execute(
            ClientCommand::confirm_group_relay_authorization(
                "reject-wrong-relay-generation",
                group.group_id,
                [9; 32],
            )
            .unwrap(),
        )
        .is_err()
    );
    let confirmed = dave
        .execute(
            ClientCommand::confirm_group_relay_authorization(
                "confirm-renamed-relay-generation",
                group.group_id,
                capability_id,
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(confirmed.events.len(), 1);
    let event = wire_proto::AppEvent::decode(confirmed.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupPolicyChanged(change) = event.body.unwrap() else {
        panic!("expected policy event after relay authentication");
    };
    assert_eq!(
        change.kind,
        wire_proto::GroupPolicyChangeKind::NameChanged as i32
    );
    assert_eq!(change.name, "Renamed");
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
fn pairwise_account_is_persisted_before_its_public_prekey_is_exposed() {
    let identity = TestIdentity::new(1);
    let expected_identity = identity.root_public();
    let mut client = PigeonClient::new(MemoryStateStore::default(), identity).unwrap();

    let output = client
        .execute(ClientCommand::ensure_pairwise_account("pairwise-setup").unwrap())
        .unwrap();
    assert_eq!(output.checkpoint_generation, 1);
    let snapshot =
        wire_proto::ClientSnapshot::decode(client.snapshot().unwrap().encode().as_slice()).unwrap();
    let published = pigeon_core::PrekeyBundle::decode(&snapshot.pairwise_prekey_bundle).unwrap();
    published.verify().unwrap();
    assert_eq!(published.identity.identity_key, expected_identity);

    let stored = client.store().load().unwrap().unwrap();
    let mut reloaded = PigeonClient::new(
        CheckpointFixtureStore::from_checkpoint(stored),
        TestIdentity::new(1),
    )
    .unwrap();
    let reloaded_snapshot =
        wire_proto::ClientSnapshot::decode(reloaded.snapshot().unwrap().encode().as_slice())
            .unwrap();
    assert_eq!(
        reloaded_snapshot.pairwise_prekey_bundle,
        snapshot.pairwise_prekey_bundle
    );

    let duplicate = reloaded
        .execute(ClientCommand::ensure_pairwise_account("pairwise-setup-again").unwrap())
        .unwrap();
    assert_eq!(duplicate.checkpoint_generation, 2);
    let duplicate_snapshot =
        wire_proto::ClientSnapshot::decode(reloaded.snapshot().unwrap().encode().as_slice())
            .unwrap();
    assert_eq!(
        duplicate_snapshot.pairwise_prekey_bundle,
        snapshot.pairwise_prekey_bundle
    );
}

#[test]
fn pairwise_control_ratchet_is_persisted_before_envelopes_are_released() {
    let mut bob = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(2)).unwrap();
    bob.execute(ClientCommand::ensure_pairwise_account("bob-pairwise").unwrap())
        .unwrap();
    let bob_snapshot =
        wire_proto::ClientSnapshot::decode(bob.snapshot().unwrap().encode().as_slice()).unwrap();

    let mut alice = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(1)).unwrap();
    alice
        .execute(ClientCommand::ensure_pairwise_account("alice-pairwise").unwrap())
        .unwrap();
    alice
        .execute(
            ClientCommand::register_pairwise_contact(
                "register-bob",
                bob_snapshot.pairwise_prekey_bundle,
                "https://bob-relay.example",
            )
            .unwrap(),
        )
        .unwrap();

    let first = alice
        .execute(
            ClientCommand::send_pairwise_control(
                "send-first",
                TestIdentity::new(2).root_public(),
                wire_proto::OutboundKind::GroupJoinRequest,
                b"first control".to_vec(),
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(first.outbound.len(), 1);
    let first_item =
        wire_proto::OutboundItem::decode(first.outbound[0].encode().as_slice()).unwrap();
    assert_eq!(first_item.kind, wire_proto::OutboundKind::Pairwise as i32);
    assert_eq!(first_item.destination, TestIdentity::new(2).root_public());
    assert_eq!(first_item.relay_url, "https://bob-relay.example");
    let first_envelope =
        wire_proto::PairwiseEnvelope::decode(first_item.payload.as_slice()).unwrap();
    assert!(matches!(
        first_envelope.body,
        Some(wire_proto::pairwise_envelope::Body::Initiation(_))
    ));

    let second = alice
        .execute(
            ClientCommand::send_pairwise_control(
                "send-second",
                TestIdentity::new(2).root_public(),
                wire_proto::OutboundKind::GroupWelcome,
                b"second control".to_vec(),
            )
            .unwrap(),
        )
        .unwrap();
    let second_item =
        wire_proto::OutboundItem::decode(second.outbound[0].encode().as_slice()).unwrap();
    let second_envelope =
        wire_proto::PairwiseEnvelope::decode(second_item.payload.as_slice()).unwrap();
    assert!(matches!(
        second_envelope.body,
        Some(wire_proto::pairwise_envelope::Body::Message(_))
    ));
}
