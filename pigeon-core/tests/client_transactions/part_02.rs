#[test]
fn canonical_policy_change_cancels_a_stale_pending_recovery() {
    let group = create_group_with_dave();
    let mut owner = group.owner;
    let dave_identity = TestIdentity::new(4).root_public();

    let promotion = owner
        .execute(
            ClientCommand::promote_group_admin(
                "promote-before-recovery",
                group.group_id,
                dave_identity,
            )
            .unwrap(),
        )
        .unwrap();
    let promotion_submission = promotion
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupCoordinator as i32)
        .unwrap();
    let promotion_submission =
        wire_proto::GroupCoordinatorSubmission::decode(promotion_submission.payload.as_slice())
            .unwrap();
    let promoted = coordinator_candidate(
        &promotion_submission,
        3,
        group.receipt_head,
        group.coordination_id,
    );
    let promoted_head = CoordinatorReceipt::decode_candidate(&promoted)
        .unwrap()
        .0
        .receipt_hash();
    owner
        .execute(
            ClientCommand::apply_group_coordinator_candidate("merge-promotion", promoted).unwrap(),
        )
        .unwrap();

    let pending = owner
        .execute(
            ClientCommand::begin_group_recovery(
                "begin-stale-recovery",
                group.group_id,
                "https://replacement-one.example",
                [81; 32],
                TestIdentity::new(63).root_public(),
            )
            .unwrap(),
        )
        .unwrap();
    assert!(pending.outbound.iter().any(|item| {
        wire_proto::OutboundItem::decode(item.encode().as_slice())
            .unwrap()
            .kind
            == wire_proto::OutboundKind::GroupMessage as i32
    }));

    let rename = owner
        .execute(
            ClientCommand::rename_group("rename-during-recovery", group.group_id, "Birds Two")
                .unwrap(),
        )
        .unwrap();
    let rename_submission = rename
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupCoordinator as i32)
        .unwrap();
    let rename_submission =
        wire_proto::GroupCoordinatorSubmission::decode(rename_submission.payload.as_slice())
            .unwrap();
    let renamed =
        coordinator_candidate(&rename_submission, 4, promoted_head, group.coordination_id);
    owner
        .execute(ClientCommand::apply_group_coordinator_candidate("merge-rename", renamed).unwrap())
        .unwrap();

    let retry = owner.execute(
        ClientCommand::begin_group_recovery(
            "begin-fresh-recovery",
            group.group_id,
            "https://replacement-two.example",
            [82; 32],
            TestIdentity::new(64).root_public(),
        )
        .unwrap(),
    );
    assert!(retry.is_ok());
}

#[test]
fn recovery_quorum_round_trips_inside_mls_group_ciphertext() {
    let group = create_group_with_dave();
    let mut owner = group.owner;
    let mut dave = group.dave;
    let dave_identity = TestIdentity::new(4).root_public();

    let promotion = owner
        .execute(
            ClientCommand::promote_group_admin(
                "promote-quorum-admin",
                group.group_id,
                dave_identity,
            )
            .unwrap(),
        )
        .unwrap();
    let promotion_submission = promotion
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupCoordinator as i32)
        .unwrap();
    let promotion_submission =
        wire_proto::GroupCoordinatorSubmission::decode(promotion_submission.payload.as_slice())
            .unwrap();
    let promoted = coordinator_candidate(
        &promotion_submission,
        3,
        group.receipt_head,
        group.coordination_id,
    );
    owner
        .execute(
            ClientCommand::apply_group_coordinator_candidate(
                "owner-merges-quorum-promotion",
                promoted.clone(),
            )
            .unwrap(),
        )
        .unwrap();
    dave.execute(
        ClientCommand::apply_group_coordinator_candidate("dave-merges-quorum-promotion", promoted)
            .unwrap(),
    )
    .unwrap();

    let proposal = owner
        .execute(
            ClientCommand::begin_group_recovery(
                "owner-begins-quorum-recovery",
                group.group_id,
                "https://replacement-quorum.example",
                [83; 32],
                TestIdentity::new(65).root_public(),
            )
            .unwrap(),
        )
        .unwrap();
    let proposal = proposal
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupMessage as i32)
        .unwrap();
    let endorsement = dave
        .execute(
            ClientCommand::apply_group_message("dave-endorses-recovery", proposal.payload).unwrap(),
        )
        .unwrap();
    assert!(endorsement.events.is_empty());
    let endorsement = endorsement
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupMessage as i32)
        .unwrap();

    let finalized = owner
        .execute(
            ClientCommand::apply_group_message("owner-accepts-endorsement", endorsement.payload)
                .unwrap(),
        )
        .unwrap();
    let kinds = finalized
        .outbound
        .iter()
        .map(|item| {
            wire_proto::OutboundItem::decode(item.encode().as_slice())
                .unwrap()
                .kind
        })
        .collect::<Vec<_>>();
    assert!(kinds.contains(&(wire_proto::OutboundKind::GroupRelayRegistration as i32)));
    assert!(kinds.contains(&(wire_proto::OutboundKind::GroupCoordinator as i32)));
}

#[test]
fn endorsement_arriving_after_recovery_was_cancelled_is_consumed() {
    let group = create_group_with_dave();
    let mut owner = group.owner;
    let mut dave = group.dave;
    let dave_identity = TestIdentity::new(4).root_public();

    let promotion = owner
        .execute(
            ClientCommand::promote_group_admin("promote-late-admin", group.group_id, dave_identity)
                .unwrap(),
        )
        .unwrap();
    let promotion_submission = promotion
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupCoordinator as i32)
        .unwrap();
    let promotion_submission =
        wire_proto::GroupCoordinatorSubmission::decode(promotion_submission.payload.as_slice())
            .unwrap();
    let promoted = coordinator_candidate(
        &promotion_submission,
        3,
        group.receipt_head,
        group.coordination_id,
    );
    let promoted_head = CoordinatorReceipt::decode_candidate(&promoted)
        .unwrap()
        .0
        .receipt_hash();
    owner
        .execute(
            ClientCommand::apply_group_coordinator_candidate(
                "owner-merges-late-promotion",
                promoted.clone(),
            )
            .unwrap(),
        )
        .unwrap();
    dave.execute(
        ClientCommand::apply_group_coordinator_candidate("dave-merges-late-promotion", promoted)
            .unwrap(),
    )
    .unwrap();

    let proposal = owner
        .execute(
            ClientCommand::begin_group_recovery(
                "owner-begins-late-recovery",
                group.group_id,
                "https://replacement-late.example",
                [84; 32],
                TestIdentity::new(66).root_public(),
            )
            .unwrap(),
        )
        .unwrap();
    let proposal = proposal
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupMessage as i32)
        .unwrap();
    let endorsement = dave
        .execute(
            ClientCommand::apply_group_message("dave-endorses-late", proposal.payload).unwrap(),
        )
        .unwrap();
    let endorsement = endorsement
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupMessage as i32)
        .unwrap();

    // A canonical rename lands first and cancels the pending recovery.
    let rename = owner
        .execute(
            ClientCommand::rename_group("rename-before-endorsement", group.group_id, "Birds Two")
                .unwrap(),
        )
        .unwrap();
    let rename_submission = rename
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupCoordinator as i32)
        .unwrap();
    let rename_submission =
        wire_proto::GroupCoordinatorSubmission::decode(rename_submission.payload.as_slice())
            .unwrap();
    let renamed =
        coordinator_candidate(&rename_submission, 4, promoted_head, group.coordination_id);
    owner
        .execute(
            ClientCommand::apply_group_coordinator_candidate("merge-rename-first", renamed)
                .unwrap(),
        )
        .unwrap();

    let late = owner
        .execute(
            ClientCommand::apply_group_message("owner-gets-late-endorsement", endorsement.payload)
                .unwrap(),
        )
        .unwrap();
    assert!(late.outbound.iter().all(|item| {
        wire_proto::OutboundItem::decode(item.encode().as_slice())
            .unwrap()
            .kind
            != wire_proto::OutboundKind::GroupRelayRegistration as i32
    }));

    // The group is not wedged: a fresh recovery can still begin.
    owner
        .execute(
            ClientCommand::begin_group_recovery(
                "owner-begins-after-late",
                group.group_id,
                "https://replacement-after.example",
                [85; 32],
                TestIdentity::new(67).root_public(),
            )
            .unwrap(),
        )
        .unwrap();
}

struct AnchoredGroup {
    owner: PigeonClient<MemoryStateStore, TestIdentity>,
    group_id: GroupId,
    coordination_id: [u8; 32],
    receipt_head: [u8; 32],
    initial_candidate: Vec<u8>,
}

fn create_anchored_group() -> AnchoredGroup {
    let mut client = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(1)).unwrap();
    let mut bob = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(2)).unwrap();
    let mut carol = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(3)).unwrap();
    for peer in [&mut client, &mut bob, &mut carol] {
        peer.execute(ClientCommand::ensure_pairwise_account("group-account").unwrap())
            .unwrap();
    }
    let owner_prekey = pairwise_prekey(&client);
    for (name, peer) in [("bob", &mut bob), ("carol", &mut carol)] {
        client
            .execute(
                ClientCommand::register_pairwise_contact(
                    format!("register-{name}"),
                    pairwise_prekey(peer),
                    "https://relay.example",
                )
                .unwrap(),
            )
            .unwrap();
        peer.execute(
            ClientCommand::register_pairwise_contact(
                "register-owner",
                owner_prekey.clone(),
                "https://relay.example",
            )
            .unwrap(),
        )
        .unwrap();
    }
    let pending = client.execute(create_group()).unwrap();
    let requests: Vec<_> = pending
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .collect();
    let bob_material = bob
        .execute(
            ClientCommand::apply_pairwise_control("bob-joins", requests[0].payload.clone())
                .unwrap(),
        )
        .unwrap();
    let carol_material = carol
        .execute(
            ClientCommand::apply_pairwise_control("carol-joins", requests[1].payload.clone())
                .unwrap(),
        )
        .unwrap();
    client
        .execute(
            ClientCommand::apply_pairwise_control(
                "anchor-material-1",
                wire_proto::OutboundItem::decode(bob_material.outbound[0].encode().as_slice())
                    .unwrap()
                    .payload,
            )
            .unwrap(),
        )
        .unwrap();
    let created = client
        .execute(
            ClientCommand::apply_pairwise_control(
                "anchor-material-2",
                wire_proto::OutboundItem::decode(carol_material.outbound[0].encode().as_slice())
                    .unwrap()
                    .payload,
            )
            .unwrap(),
        )
        .unwrap();
    let event = wire_proto::AppEvent::decode(created.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupCreated(group) = event.body.unwrap() else {
        panic!("expected group creation");
    };
    let group_id = GroupId::from_bytes(group.group_id.try_into().unwrap());
    let coordinator = created
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupCoordinator as i32)
        .unwrap();
    let coordination_id = coordinator.destination.as_slice().try_into().unwrap();
    let submission =
        wire_proto::GroupCoordinatorSubmission::decode(coordinator.payload.as_slice()).unwrap();
    let candidate = coordinator_candidate(&submission, 1, [0; 32], coordination_id);
    let receipt_hash = CoordinatorReceipt::decode_candidate(&candidate)
        .unwrap()
        .0
        .receipt_hash();
    client
        .execute(
            ClientCommand::apply_group_coordinator_candidate("anchor-receipt", candidate.clone())
                .unwrap(),
        )
        .unwrap();
    AnchoredGroup {
        owner: client,
        group_id,
        coordination_id,
        receipt_head: receipt_hash,
        initial_candidate: candidate,
    }
}
