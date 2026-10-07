#[test]
fn one_batched_receipt_settles_every_senders_messages_and_bystanders_ignore_it() {
    let ThreeMemberGroup {
        mut owner,
        mut bob,
        mut carol,
        group_id,
        ..
    } = three_member_group();
    let owner_first = group_text(&mut owner, "owner-first", group_id);
    let owner_second = group_text(&mut owner, "owner-second", group_id);
    let carol_text = group_text(&mut carol, "carol-text", group_id);
    for (index, message) in [owner_first, owner_second, carol_text]
        .into_iter()
        .enumerate()
    {
        let received = bob
            .execute(ClientCommand::apply_group_message(format!("bob-{index}"), message).unwrap())
            .unwrap();
        assert!(received.outbound.is_empty(), "no receipt per message");
    }

    let flushed = bob
        .execute(ClientCommand::flush_group_acknowledgements("bob-flush", Some(group_id)).unwrap())
        .unwrap();
    assert_eq!(
        flushed.outbound.len(),
        1,
        "three receipts share one ciphertext"
    );
    let batch = wire_proto::OutboundItem::decode(flushed.outbound[0].encode().as_slice())
        .unwrap()
        .payload;

    let owner_delivery = owner
        .execute(ClientCommand::apply_group_message("owner-receipts", batch.clone()).unwrap())
        .unwrap();
    assert_eq!(delivery_counts(&owner_delivery), vec![(1, 2), (1, 2)]);

    let carol_delivery = carol
        .execute(ClientCommand::apply_group_message("carol-receipts", batch).unwrap())
        .unwrap();
    assert_eq!(delivery_counts(&carol_delivery), vec![(1, 2)]);

    let generation = bob.checkpoint_generation();
    let idle = bob
        .execute(ClientCommand::flush_group_acknowledgements("bob-idle", None).unwrap())
        .unwrap();
    assert!(idle.outbound.is_empty(), "flushed receipts are not resent");
    assert_eq!(
        bob.checkpoint_generation(),
        generation,
        "an idle flush commits nothing"
    );
}

#[test]
fn a_full_receipt_batch_flushes_without_waiting_for_the_host() {
    let ThreeMemberGroup {
        mut owner,
        mut bob,
        group_id,
        ..
    } = three_member_group();
    let mut automatic = Vec::new();
    for index in 0..pigeon_core::MAX_GROUP_ACKNOWLEDGEMENT_BATCH {
        let message = group_text(&mut owner, &format!("burst-{index}"), group_id);
        let received = bob
            .execute(
                ClientCommand::apply_group_message(format!("bob-burst-{index}"), message).unwrap(),
            )
            .unwrap();
        automatic.extend(received.outbound);
    }
    assert_eq!(automatic.len(), 1, "the full batch is flushed exactly once");
    let batch = wire_proto::OutboundItem::decode(automatic[0].encode().as_slice())
        .unwrap()
        .payload;
    let delivered = owner
        .execute(ClientCommand::apply_group_message("owner-burst-receipts", batch).unwrap())
        .unwrap();
    assert_eq!(
        delivery_counts(&delivered).len(),
        pigeon_core::MAX_GROUP_ACKNOWLEDGEMENT_BATCH
    );
}

#[test]
fn acknowledgement_batches_are_bounded() {
    use pigeon_core::{AcknowledgedMessage, GroupApplication, GroupMessageId};
    assert!(GroupApplication::acknowledgements(Vec::new()).is_err());
    let one = AcknowledgedMessage {
        original_sender: [1; 32],
        message_id: GroupMessageId::from_bytes([2; 16]),
    };
    assert!(
        GroupApplication::acknowledgements(vec![one; pigeon_core::MAX_GROUP_ACKNOWLEDGEMENT_BATCH])
            .is_ok()
    );
    assert!(
        GroupApplication::acknowledgements(vec![
            one;
            pigeon_core::MAX_GROUP_ACKNOWLEDGEMENT_BATCH + 1
        ])
        .is_err()
    );
}
