#[test]
fn coordinator_equivocation_is_durably_frozen_and_reported() {
    let anchored = create_anchored_group();
    let mut client = anchored.owner;
    let coordination_id = anchored.coordination_id;
    let accepted = anchored.initial_candidate;
    let fork_submission = wire_proto::GroupCoordinatorSubmission {
        version: 1,
        claimed_base_epoch: 0,
        candidate: GroupMutationCandidate::new(Vec::new(), b"conflicting commit".to_vec())
            .unwrap()
            .encode(),
    };
    let fork = coordinator_candidate(&fork_submission, 1, [0; 32], coordination_id);
    let generation = client.checkpoint_generation();

    let frozen = client
        .execute(ClientCommand::apply_group_coordinator_candidate("observe-fork", fork).unwrap())
        .unwrap();

    assert_eq!(frozen.checkpoint_generation, generation + 1);
    assert_eq!(frozen.events.len(), 1);
    assert!(frozen.outbound.is_empty());
    let event = wire_proto::AppEvent::decode(frozen.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupSecurityWarning(warning) = event.body.unwrap() else {
        panic!("expected coordinator security warning");
    };
    assert_eq!(warning.code, 1);
    assert_eq!(warning.epoch, 1);

    assert!(
        client
            .execute(
                ClientCommand::apply_group_coordinator_candidate("candidate-after-fork", accepted,)
                    .unwrap(),
            )
            .is_err()
    );
    assert_eq!(client.checkpoint_generation(), generation + 1);
}

#[test]
fn membership_changes_release_relay_controls_and_welcome_only_after_canonical_merge() {
    let anchored = create_anchored_group();
    let mut owner_client = anchored.owner;
    let group_id = anchored.group_id;
    let coordination_id = anchored.coordination_id;
    let receipt_head = anchored.receipt_head;
    let mut dave_client =
        PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(4)).unwrap();
    register_pairwise_peers(&mut owner_client, &mut dave_client, "membership-dave");
    let invited = owner_client
        .execute(
            ClientCommand::add_group_member(
                "invite-dave",
                group_id,
                TestIdentity::new(4).root_public(),
            )
            .unwrap(),
        )
        .unwrap();
    assert!(invited.events.is_empty());
    assert_eq!(invited.outbound.len(), 1);
    let request =
        wire_proto::OutboundItem::decode(invited.outbound[0].encode().as_slice()).unwrap();
    assert_eq!(request.kind, wire_proto::OutboundKind::Pairwise as i32);
    assert_eq!(request.destination, TestIdentity::new(4).root_public());

    let response = dave_client
        .execute(ClientCommand::apply_pairwise_control("dave-material", request.payload).unwrap())
        .unwrap();
    let material =
        wire_proto::OutboundItem::decode(response.outbound[0].encode().as_slice()).unwrap();
    let staged = owner_client
        .execute(
            ClientCommand::apply_pairwise_control("apply-dave-material", material.payload).unwrap(),
        )
        .unwrap();
    assert!(staged.events.is_empty());
    assert_eq!(staged.outbound.len(), 1);
    let submission_item =
        wire_proto::OutboundItem::decode(staged.outbound[0].encode().as_slice()).unwrap();
    let submission =
        wire_proto::GroupCoordinatorSubmission::decode(submission_item.payload.as_slice()).unwrap();
    let canonical = coordinator_candidate(&submission, 2, receipt_head, coordination_id);
    let second_receipt_head = CoordinatorReceipt::decode_candidate(&canonical)
        .unwrap()
        .0
        .receipt_hash();

    let before_merge =
        wire_proto::ClientSnapshot::decode(owner_client.snapshot().unwrap().encode().as_slice())
            .unwrap();
    let prior_capability_id = before_merge.groups[0].capability_id.clone();

    let merged = owner_client
        .execute(ClientCommand::apply_group_coordinator_candidate("merge-dave", canonical).unwrap())
        .unwrap();
    assert!(merged.events.is_empty());
    assert_eq!(merged.outbound.len(), 2);
    let outbound: Vec<_> = merged
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .collect();
    let control_item = outbound
        .iter()
        .find(|item| item.kind == wire_proto::OutboundKind::GroupRelayControl as i32)
        .unwrap();
    let control = GroupRelayControl::decode(&control_item.payload).unwrap();
    assert_eq!(control.kind(), GroupRelayControlKind::ReplaceAll);
    assert!(control.capabilities().iter().any(|capability| {
        capability.public_key() == TestIdentity::new(4).capability.verifying_key().to_bytes()
    }));
    let before_control_ack =
        wire_proto::ClientSnapshot::decode(owner_client.snapshot().unwrap().encode().as_slice())
            .unwrap();
    assert_eq!(
        before_control_ack.groups[0].capability_id,
        prior_capability_id
    );

    let acknowledged = owner_client
        .execute(
            ClientCommand::acknowledge_effects(
                "ack-add-relay-control",
                vec![control_item.item_id.clone()],
                Vec::new(),
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(acknowledged.events.len(), 1);
    let event = wire_proto::AppEvent::decode(acknowledged.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupPolicyChanged(change) = event.body.unwrap() else {
        panic!("expected member-added policy event");
    };
    assert_eq!(
        change.kind,
        wire_proto::GroupPolicyChangeKind::MemberAdded as i32
    );
    assert_eq!(change.subject_identity, TestIdentity::new(4).root_public());
    let after_control_ack =
        wire_proto::ClientSnapshot::decode(owner_client.snapshot().unwrap().encode().as_slice())
            .unwrap();
    assert_ne!(
        after_control_ack.groups[0].capability_id,
        prior_capability_id
    );

    let welcome = outbound
        .iter()
        .find(|item| {
            item.kind == wire_proto::OutboundKind::Pairwise as i32
                && item.destination == TestIdentity::new(4).root_public()
        })
        .unwrap();
    assert_eq!(welcome.destination, TestIdentity::new(4).root_public());
    let joined = dave_client
        .execute(
            ClientCommand::apply_pairwise_control("join-dave", welcome.payload.clone()).unwrap(),
        )
        .unwrap();
    assert_eq!(joined.events.len(), 1);

    let staged_remove = owner_client
        .execute(
            ClientCommand::remove_group_member(
                "remove-dave",
                group_id,
                TestIdentity::new(4).root_public(),
            )
            .unwrap(),
        )
        .unwrap();
    assert!(staged_remove.events.is_empty());
    let remove_item =
        wire_proto::OutboundItem::decode(staged_remove.outbound[0].encode().as_slice()).unwrap();
    let remove_submission =
        wire_proto::GroupCoordinatorSubmission::decode(remove_item.payload.as_slice()).unwrap();
    let canonical_remove =
        coordinator_candidate(&remove_submission, 3, second_receipt_head, coordination_id);
    let removed = owner_client
        .execute(
            ClientCommand::apply_group_coordinator_candidate("merge-remove", canonical_remove)
                .unwrap(),
        )
        .unwrap();
    assert!(removed.events.is_empty());
    let revoke_item = removed
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupRelayControl as i32)
        .unwrap();
    let revoke = GroupRelayControl::decode(&revoke_item.payload).unwrap();
    assert_eq!(revoke.kind(), GroupRelayControlKind::ReplaceAll);
    assert!(!revoke.capabilities().iter().any(|capability| {
        capability.public_key() == TestIdentity::new(4).capability.verifying_key().to_bytes()
    }));
    let acknowledged = owner_client
        .execute(
            ClientCommand::acknowledge_effects(
                "ack-remove-relay-control",
                vec![revoke_item.item_id],
                Vec::new(),
            )
            .unwrap(),
        )
        .unwrap();
    let event = wire_proto::AppEvent::decode(acknowledged.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupPolicyChanged(change) = event.body.unwrap() else {
        panic!("expected member-removed policy event");
    };
    assert_eq!(
        change.kind,
        wire_proto::GroupPolicyChangeKind::MemberRemoved as i32
    );
}

#[test]
fn ordinary_member_leave_is_committed_by_an_online_admin() {
    let group = create_group_with_dave();
    let mut owner = group.owner;
    let mut dave = group.dave;
    let group_id = group.group_id;
    let coordination_id = group.coordination_id;
    let receipt_head = group.receipt_head;
    let owner_pending =
        wire_proto::ClientSnapshot::decode(owner.snapshot().unwrap().encode().as_slice())
            .unwrap()
            .pending_outbound
            .into_iter()
            .map(|item| item.item_id)
            .collect();
    owner
        .execute(
            ClientCommand::acknowledge_effects(
                "clear-owner-fixture-effects",
                owner_pending,
                Vec::new(),
            )
            .unwrap(),
        )
        .unwrap();
    let dave_pending =
        wire_proto::ClientSnapshot::decode(dave.snapshot().unwrap().encode().as_slice())
            .unwrap()
            .pending_outbound
            .into_iter()
            .map(|item| item.item_id)
            .collect();
    dave.execute(
        ClientCommand::acknowledge_effects("clear-dave-fixture-effects", dave_pending, Vec::new())
            .unwrap(),
    )
    .unwrap();
    owner
        .execute(ClientCommand::ensure_pairwise_account("owner-pairwise-account").unwrap())
        .unwrap();
    dave.execute(ClientCommand::ensure_pairwise_account("dave-pairwise-account").unwrap())
        .unwrap();
    let owner_prekey =
        wire_proto::ClientSnapshot::decode(owner.snapshot().unwrap().encode().as_slice())
            .unwrap()
            .pairwise_prekey_bundle;
    let dave_prekey =
        wire_proto::ClientSnapshot::decode(dave.snapshot().unwrap().encode().as_slice())
            .unwrap()
            .pairwise_prekey_bundle;
    owner
        .execute(
            ClientCommand::register_pairwise_contact(
                "owner-registers-dave",
                dave_prekey,
                "https://dave-relay.example",
            )
            .unwrap(),
        )
        .unwrap();
    dave.execute(
        ClientCommand::register_pairwise_contact(
            "dave-registers-owner",
            owner_prekey,
            "https://owner-relay.example",
        )
        .unwrap(),
    )
    .unwrap();

    let proposed = dave
        .execute(ClientCommand::leave_group("dave-leaves", group_id).unwrap())
        .unwrap();
    assert!(proposed.events.is_empty());
    assert_eq!(proposed.outbound.len(), 1);
    let proposal =
        wire_proto::OutboundItem::decode(proposed.outbound[0].encode().as_slice()).unwrap();
    assert_eq!(proposal.kind, wire_proto::OutboundKind::Pairwise as i32);
    assert_eq!(proposal.destination, TestIdentity::new(1).root_public());
    let pending_leave =
        wire_proto::ClientSnapshot::decode(dave.snapshot().unwrap().encode().as_slice()).unwrap();
    assert!(pending_leave.groups[0].local_leave_pending);

    let staged = owner
        .execute(
            ClientCommand::apply_pairwise_control("owner-commits-leave", proposal.payload).unwrap(),
        )
        .unwrap();
    assert!(staged.events.is_empty());
    assert_eq!(staged.outbound.len(), 1);
    let submission_item =
        wire_proto::OutboundItem::decode(staged.outbound[0].encode().as_slice()).unwrap();
    let submission =
        wire_proto::GroupCoordinatorSubmission::decode(submission_item.payload.as_slice()).unwrap();
    let mutation = GroupMutationCandidate::decode(&submission.candidate).unwrap();
    assert_eq!(mutation.proposals().len(), 1);

    let canonical = coordinator_candidate(&submission, 3, receipt_head, coordination_id);
    let merged = owner
        .execute(
            ClientCommand::apply_group_coordinator_candidate("merge-dave-leave", canonical.clone())
                .unwrap(),
        )
        .unwrap();
    assert!(merged.events.is_empty());
    let revoke_item = merged
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.kind == wire_proto::OutboundKind::GroupRelayControl as i32)
        .unwrap();
    let revoke = GroupRelayControl::decode(&revoke_item.payload).unwrap();
    assert_eq!(revoke.kind(), GroupRelayControlKind::ReplaceAll);
    assert!(!revoke.capabilities().iter().any(|capability| {
        capability.public_key() == TestIdentity::new(4).capability.verifying_key().to_bytes()
    }));
    let acknowledged = owner
        .execute(
            ClientCommand::acknowledge_effects(
                "ack-leave-relay-control",
                vec![revoke_item.item_id],
                Vec::new(),
            )
            .unwrap(),
        )
        .unwrap();
    let event = wire_proto::AppEvent::decode(acknowledged.events[0].encode().as_slice()).unwrap();
    let wire_proto::app_event::Body::GroupPolicyChanged(change) = event.body.unwrap() else {
        panic!("expected member-left policy event");
    };
    assert_eq!(
        change.kind,
        wire_proto::GroupPolicyChangeKind::MemberLeft as i32
    );
    assert_eq!(change.subject_identity, TestIdentity::new(4).root_public());
    let departed = dave
        .execute(
            ClientCommand::apply_group_coordinator_candidate("observe-own-leave", canonical)
                .unwrap(),
        )
        .unwrap();
    assert_eq!(departed.events.len(), 1);
    assert!(departed.outbound.is_empty());
    let departed_snapshot =
        wire_proto::ClientSnapshot::decode(dave.snapshot().unwrap().encode().as_slice()).unwrap();
    assert!(!departed_snapshot.groups[0].local_leave_pending);
}
