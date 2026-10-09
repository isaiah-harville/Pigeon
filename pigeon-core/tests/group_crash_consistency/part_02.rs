#[test]
fn relay_and_mesh_copies_emit_one_received_event_and_one_acknowledgement() {
    let (mut owner_client, mut bob_client, _, created) = create_group_with_members(
        SwitchableStore::default(),
        [11, 12, 13],
        "create-mesh",
        "Mesh Birds",
        TestIdentity::new(60).root_public(),
        true,
    );
    let bob_store = bob_client.store().clone();
    let welcome = created
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| {
            item.kind == wire_proto::OutboundKind::Pairwise as i32
                && item.destination == TestIdentity::new(12).root_public()
        })
        .unwrap();
    let created_event =
        wire_proto::AppEvent::decode(created.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupCreated(created_group) = created_event.body.unwrap()
    else {
        panic!("expected GroupCreated");
    };
    let group_id = GroupId::from_bytes(created_group.group_id.try_into().unwrap());

    bob_client
        .execute(ClientCommand::apply_pairwise_control("welcome", welcome.payload).unwrap())
        .unwrap();

    let sent = owner_client
        .execute(
            ClientCommand::send_group_text("send-mesh", group_id, b"hello".to_vec(), "").unwrap(),
        )
        .unwrap();
    assert_eq!(sent.outbound.len(), 1, "MLS ciphertext is produced once");
    let ciphertext = wire_proto::OutboundItem::decode(sent.outbound[0].encode().as_slice())
        .unwrap()
        .payload;
    let mut future_hint =
        wire_proto::GroupApplicationCiphertext::decode(ciphertext.as_slice()).unwrap();
    future_hint.epoch += 1;
    let future = bob_client
        .execute(
            ClientCommand::apply_group_message("future-hint", future_hint.encode_to_vec()).unwrap(),
        )
        .unwrap();
    assert!(future.events.is_empty());
    assert_eq!(future.outbound.len(), 1);
    let fetch = wire_proto::OutboundItem::decode(future.outbound[0].encode().as_slice()).unwrap();
    assert_eq!(
        fetch.kind,
        wire_proto::OutboundKind::GroupCoordinator as i32
    );
    let fetch = wire_proto::GroupEpochFetch::decode(fetch.payload.as_slice()).unwrap();
    assert_eq!(fetch.from_epoch, 2);
    assert_eq!(fetch.through_epoch, 2);
    let relay_command =
        ClientCommand::apply_group_message("relay-copy", ciphertext.clone()).unwrap();
    let generation = bob_client.checkpoint_generation();
    bob_store.set_fail_replace(true);
    assert!(matches!(
        bob_client.execute(relay_command.clone()),
        Err(Error::Persistence(_))
    ));
    assert_eq!(bob_client.checkpoint_generation(), generation);
    bob_store.set_fail_replace(false);
    let relay = bob_client.execute(relay_command).unwrap();
    assert_eq!(relay.events.len(), 1);
    assert!(
        relay.outbound.is_empty(),
        "receipts are queued, not sent per message"
    );
    let flushed = bob_client
        .execute(ClientCommand::flush_group_acknowledgements("bob-flush", None).unwrap())
        .unwrap();
    assert_eq!(
        flushed.outbound.len(),
        1,
        "one batched acknowledgement is produced"
    );
    let acknowledgement =
        wire_proto::OutboundItem::decode(flushed.outbound[0].encode().as_slice()).unwrap();
    let delivered = owner_client
        .execute(ClientCommand::apply_group_message("bob-ack", acknowledgement.payload).unwrap())
        .unwrap();
    let delivery_event =
        wire_proto::AppEvent::decode(delivered.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupDeliveryChanged(delivery) = delivery_event.body.unwrap()
    else {
        panic!("expected GroupDeliveryChanged");
    };
    assert_eq!(
        delivery.state,
        wire_proto::GroupDeliveryState::DeliveredTo as i32
    );
    assert_eq!(delivery.delivered_count, 1);
    assert_eq!(delivery.intended_count, 2);

    let mesh = bob_client
        .execute(ClientCommand::apply_group_message("mesh-copy", ciphertext).unwrap())
        .unwrap();
    assert!(mesh.events.is_empty());
    assert!(mesh.outbound.is_empty());
    let reflushed = bob_client
        .execute(ClientCommand::flush_group_acknowledgements("bob-reflush", None).unwrap())
        .unwrap();
    assert!(
        reflushed.outbound.is_empty(),
        "the duplicate copy queues no receipt"
    );
}

struct ThreeMemberGroup {
    owner: PigeonClient<SwitchableStore, TestIdentity>,
    bob: PigeonClient<SwitchableStore, TestIdentity>,
    carol: PigeonClient<SwitchableStore, TestIdentity>,
    group_id: GroupId,
    bob_store: SwitchableStore,
}

fn three_member_group() -> ThreeMemberGroup {
    let (owner, mut bob, mut carol, created) = create_group_with_members(
        SwitchableStore::default(),
        [21, 22, 23],
        "create-receipts",
        "Receipt Birds",
        TestIdentity::new(61).root_public(),
        false,
    );
    let bob_public = TestIdentity::new(22).root_public();
    let carol_public = TestIdentity::new(23).root_public();
    let bob_store = bob.store().clone();
    let welcome_for = |member: [u8; 32]| {
        created
            .outbound
            .iter()
            .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
            .find(|item| {
                item.kind == wire_proto::OutboundKind::Pairwise as i32 && item.destination == member
            })
            .unwrap()
            .payload
    };
    let (bob_welcome, carol_welcome) = (welcome_for(bob_public), welcome_for(carol_public));
    let event = wire_proto::AppEvent::decode(created.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupCreated(group) = event.body.unwrap() else {
        panic!("expected GroupCreated");
    };
    bob.execute(ClientCommand::apply_pairwise_control("welcome-bob", bob_welcome).unwrap())
        .unwrap();
    carol
        .execute(ClientCommand::apply_pairwise_control("welcome-carol", carol_welcome).unwrap())
        .unwrap();
    ThreeMemberGroup {
        owner,
        bob,
        carol,
        group_id: GroupId::from_bytes(group.group_id.try_into().unwrap()),
        bob_store,
    }
}

fn group_text(
    client: &mut PigeonClient<SwitchableStore, TestIdentity>,
    command_id: &str,
    group_id: GroupId,
) -> Vec<u8> {
    let sent = client
        .execute(
            ClientCommand::send_group_text(
                command_id,
                group_id,
                command_id.as_bytes().to_vec(),
                "",
            )
            .unwrap(),
        )
        .unwrap();
    sent.outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupMessage as i32)
        .unwrap()
        .payload
}

fn delivery_counts(output: &pigeon_core::ClientOutput) -> Vec<(u32, u32)> {
    output
        .events
        .iter()
        .filter_map(|event| {
            match wire_proto::AppEvent::decode(event.encode().as_slice())
                .unwrap()
                .body?
            {
                wire_proto::app_event::Body::GroupDeliveryChanged(delivery) => {
                    Some((delivery.delivered_count, delivery.intended_count))
                }
                _ => None,
            }
        })
        .collect()
}

#[test]
fn malformed_group_entry_is_durably_rejected_before_next_valid_message() {
    let ThreeMemberGroup {
        mut owner,
        mut bob,
        bob_store: store,
        group_id,
        ..
    } = three_member_group();
    let valid = group_text(&mut owner, "after-poison", group_id);
    let malformed = ClientCommand::apply_group_message("relay-poison", vec![0xff]).unwrap();

    store.set_fail_replace(true);
    assert!(matches!(
        bob.execute(malformed.clone()),
        Err(Error::Persistence(_))
    ));
    store.set_fail_replace(false);
    let rejected = bob.execute(malformed).unwrap();
    assert_eq!(
        rejected.group_message_outcome,
        pigeon_core::GroupMessageOutcome::Rejected
    );
    assert!(rejected.events.is_empty());

    let mut relaunched = PigeonClient::new(store, TestIdentity::new(22)).unwrap();
    let accepted = relaunched
        .execute(ClientCommand::apply_group_message("relay-valid", valid).unwrap())
        .unwrap();
    assert_eq!(
        accepted.group_message_outcome,
        pigeon_core::GroupMessageOutcome::Accepted
    );
    assert_eq!(accepted.events.len(), 1);
}

#[test]
fn distant_future_epoch_is_durably_rejected_before_later_entries() {
    let ThreeMemberGroup {
        mut owner,
        mut bob,
        group_id,
        ..
    } = three_member_group();
    let valid = group_text(&mut owner, "future-after-epoch", group_id);
    let mut hinted = wire_proto::GroupApplicationCiphertext::decode(valid.as_slice()).unwrap();
    hinted.epoch += pigeon_core::MAX_FUTURE_EPOCHS as u64 + 1;
    let command =
        ClientCommand::apply_group_message("future-dependent", hinted.encode_to_vec()).unwrap();
    let generation = bob.checkpoint_generation();
    let rejected = bob.execute(command).unwrap();
    assert_eq!(
        rejected.group_message_outcome,
        pigeon_core::GroupMessageOutcome::Rejected
    );
    assert_eq!(bob.checkpoint_generation(), generation + 1);
}

#[test]
fn buffered_future_message_is_delivered_when_its_epoch_is_merged() {
    let ThreeMemberGroup {
        mut owner,
        mut bob,
        group_id,
        ..
    } = three_member_group();
    let coordinator = TestIdentity::new(61);
    let owner_snapshot =
        wire_proto::ClientSnapshot::decode(owner.snapshot().unwrap().encode().as_slice()).unwrap();
    let initial = owner_snapshot
        .pending_outbound
        .iter()
        .find(|item| item.kind == wire_proto::OutboundKind::GroupCoordinator as i32)
        .unwrap();
    let coordination_id: [u8; 32] = initial.destination.as_slice().try_into().unwrap();
    let initial_submission =
        wire_proto::GroupCoordinatorSubmission::decode(initial.payload.as_slice()).unwrap();
    let initial_candidate = coordinator_candidate(
        &initial_submission,
        1,
        [0; 32],
        coordination_id,
        &coordinator.root,
    );
    let initial_head = pigeon_core::CoordinatorReceipt::decode_candidate(&initial_candidate)
        .unwrap()
        .0
        .receipt_hash();
    owner
        .execute(
            ClientCommand::apply_group_coordinator_candidate(
                "anchor-owner",
                initial_candidate.clone(),
            )
            .unwrap(),
        )
        .unwrap();
    bob.execute(
        ClientCommand::apply_group_coordinator_candidate("anchor-bob", initial_candidate).unwrap(),
    )
    .unwrap();

    let changed = owner
        .execute(ClientCommand::rename_group("rename", group_id, "Swifts").unwrap())
        .unwrap();
    let submission = changed
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupCoordinator as i32)
        .unwrap();
    let submission =
        wire_proto::GroupCoordinatorSubmission::decode(submission.payload.as_slice()).unwrap();
    let candidate = coordinator_candidate(
        &submission,
        2,
        initial_head,
        coordination_id,
        &coordinator.root,
    );
    owner
        .execute(
            ClientCommand::apply_group_coordinator_candidate("merge-owner", candidate.clone())
                .unwrap(),
        )
        .unwrap();
    let ciphertext = group_text(&mut owner, "after-rename", group_id);
    let early = bob
        .execute(ClientCommand::apply_group_message("early", ciphertext).unwrap())
        .unwrap();
    assert!(early.events.is_empty());
    let merged = bob
        .execute(ClientCommand::apply_group_coordinator_candidate("merge-bob", candidate).unwrap())
        .unwrap();
    assert!(merged.events.iter().any(|event| {
        let event = wire_proto::AppEvent::decode(event.encode().as_slice()).unwrap();
        matches!(
            event.body,
            Some(wire_proto::app_event::Body::GroupMessageReceived(_))
        )
    }));
    let checkpoint = bob.store().load().unwrap().unwrap();
    let state = wire_proto::ClientCheckpoint::decode(checkpoint.bytes.as_slice()).unwrap();
    assert!(state.buffered_group_messages.is_empty());
}

#[test]
fn unauthenticated_future_message_id_cannot_suppress_another_ciphertext() {
    let ThreeMemberGroup {
        mut owner,
        mut bob,
        group_id,
        ..
    } = three_member_group();
    let first = group_text(&mut owner, "first-future", group_id);
    let second = group_text(&mut owner, "second-future", group_id);
    let mut first = wire_proto::GroupApplicationCiphertext::decode(first.as_slice()).unwrap();
    let mut second = wire_proto::GroupApplicationCiphertext::decode(second.as_slice()).unwrap();
    first.epoch += 1;
    second.epoch += 1;
    second.message_id = first.message_id.clone();
    bob.execute(ClientCommand::apply_group_message("future-one", first.encode_to_vec()).unwrap())
        .unwrap();
    bob.execute(ClientCommand::apply_group_message("future-two", second.encode_to_vec()).unwrap())
        .unwrap();
    let checkpoint = bob.store().load().unwrap().unwrap();
    let state = wire_proto::ClientCheckpoint::decode(checkpoint.bytes.as_slice()).unwrap();
    assert_eq!(state.buffered_group_messages.len(), 2);
}
