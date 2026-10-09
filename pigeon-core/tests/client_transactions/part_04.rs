#[test]
fn inbound_pairwise_control_is_decrypted_and_dispatched_inside_one_transaction() {
    let mut alice = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(1)).unwrap();
    let mut bob = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(2)).unwrap();
    alice
        .execute(ClientCommand::ensure_pairwise_account("alice-account").unwrap())
        .unwrap();
    bob.execute(ClientCommand::ensure_pairwise_account("bob-account").unwrap())
        .unwrap();
    let alice_prekey =
        wire_proto::ClientSnapshot::decode(alice.snapshot().unwrap().encode().as_slice())
            .unwrap()
            .pairwise_prekey_bundle;
    let bob_prekey =
        wire_proto::ClientSnapshot::decode(bob.snapshot().unwrap().encode().as_slice())
            .unwrap()
            .pairwise_prekey_bundle;
    alice
        .execute(
            ClientCommand::register_pairwise_contact(
                "alice-registers-bob",
                bob_prekey,
                "https://bob-relay.example",
            )
            .unwrap(),
        )
        .unwrap();
    bob.execute(
        ClientCommand::register_pairwise_contact(
            "bob-registers-alice",
            alice_prekey,
            "https://alice-relay.example",
        )
        .unwrap(),
    )
    .unwrap();

    let draft = alice.execute(create_group()).unwrap();
    let request = draft
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.destination == TestIdentity::new(2).root_public())
        .unwrap();
    assert_eq!(request.kind, wire_proto::OutboundKind::Pairwise as i32);

    let decrypted = bob
        .execute(
            ClientCommand::apply_pairwise_control("bob-decrypts-request", request.payload.clone())
                .unwrap(),
        )
        .unwrap();

    assert_eq!(decrypted.outbound.len(), 1);
    let material =
        wire_proto::OutboundItem::decode(decrypted.outbound[0].encode().as_slice()).unwrap();
    assert_eq!(material.kind, wire_proto::OutboundKind::Pairwise as i32);
    assert_eq!(material.destination, TestIdentity::new(1).root_public());

    let sent = bob
        .execute(
            ClientCommand::send_direct_text(
                "direct-message",
                TestIdentity::new(1).root_public(),
                "hello",
                "",
                1234,
            )
            .unwrap(),
        )
        .unwrap();
    let direct = wire_proto::OutboundItem::decode(sent.outbound[0].encode().as_slice()).unwrap();
    let envelope = wire_proto::PairwiseEnvelope::decode(direct.payload.as_slice()).unwrap();
    assert!(matches!(
        envelope.body,
        Some(wire_proto::pairwise_envelope::Body::Message(_))
    ));
    // Direct messages can arrive before earlier group controls on the same ratchet.
    let received = alice
        .execute(
            ClientCommand::apply_pairwise_control("direct-in", direct.payload.clone()).unwrap(),
        )
        .unwrap();
    let event = wire_proto::AppEvent::decode(received.events[0].encode().as_slice()).unwrap();
    let Some(wire_proto::app_event::Body::DirectApplicationReceived(application)) = event.body
    else {
        panic!("expected direct message")
    };
    assert_eq!(
        application.sender_identity,
        TestIdentity::new(2).root_public()
    );
    let Some(wire_proto::direct_application::Body::Message(message)) =
        application.application.unwrap().body
    else {
        panic!("expected direct message body")
    };
    assert_eq!(message.text, "hello");
    let duplicate = alice
        .execute(ClientCommand::apply_pairwise_control("direct-duplicate", direct.payload).unwrap())
        .unwrap();
    assert!(duplicate.events.is_empty());
    let snapshot =
        wire_proto::ClientSnapshot::decode(alice.snapshot().unwrap().encode().as_slice()).unwrap();
    assert!(
        snapshot
            .pending_events
            .iter()
            .any(|pending| pending.event_id == event.event_id)
    );

    let acknowledged = alice
        .execute(
            ClientCommand::send_direct_acknowledgement(
                "ack-direct-message",
                TestIdentity::new(2).root_public(),
                "direct-message",
            )
            .unwrap(),
        )
        .unwrap();
    let acknowledgement =
        wire_proto::OutboundItem::decode(acknowledged.outbound[0].encode().as_slice()).unwrap();
    let received_ack = bob
        .execute(
            ClientCommand::apply_pairwise_control(
                "bob-receives-direct-ack",
                acknowledgement.payload,
            )
            .unwrap(),
        )
        .unwrap();
    let ack_event =
        wire_proto::AppEvent::decode(received_ack.events[0].encode().as_slice()).unwrap();
    let Some(wire_proto::app_event::Body::DirectApplicationReceived(application)) = ack_event.body
    else {
        panic!("expected direct acknowledgement")
    };
    let Some(wire_proto::direct_application::Body::Acknowledgement(ack)) =
        application.application.unwrap().body
    else {
        panic!("expected direct acknowledgement body")
    };
    assert_eq!(ack.message_id, "direct-message");
    let bob_snapshot =
        wire_proto::ClientSnapshot::decode(bob.snapshot().unwrap().encode().as_slice()).unwrap();
    assert!(
        bob_snapshot
            .pending_outbound
            .iter()
            .all(|item| item.item_id != "direct-message")
    );

    alice
        .execute(
            ClientCommand::apply_pairwise_control(
                "independent-transport-delivery-id",
                material.payload,
            )
            .unwrap(),
        )
        .unwrap();

    let replay = bob
        .execute(
            ClientCommand::apply_pairwise_control(
                "bob-receives-republished-request",
                request.payload,
            )
            .unwrap(),
        )
        .unwrap();
    assert!(replay.events.is_empty());
    assert!(replay.outbound.is_empty());
}

#[test]
fn registering_a_contact_wraps_already_pending_group_controls() {
    let mut bob = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(2)).unwrap();
    bob.execute(ClientCommand::ensure_pairwise_account("bob-account").unwrap())
        .unwrap();
    let bob_prekey =
        wire_proto::ClientSnapshot::decode(bob.snapshot().unwrap().encode().as_slice())
            .unwrap()
            .pairwise_prekey_bundle;
    let mut alice = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(1)).unwrap();
    alice
        .execute(ClientCommand::ensure_pairwise_account("alice-account").unwrap())
        .unwrap();

    let draft = alice.execute(create_group()).unwrap();
    assert!(draft.outbound.is_empty());
    let before_registration =
        wire_proto::ClientSnapshot::decode(alice.snapshot().unwrap().encode().as_slice()).unwrap();
    assert!(before_registration.pending_outbound.is_empty());

    alice
        .execute(
            ClientCommand::register_pairwise_contact(
                "register-bob-late",
                bob_prekey,
                "https://bob-relay.example",
            )
            .unwrap(),
        )
        .unwrap();
    let snapshot =
        wire_proto::ClientSnapshot::decode(alice.snapshot().unwrap().encode().as_slice()).unwrap();
    let wrapped = snapshot
        .pending_outbound
        .iter()
        .find(|item| item.item_id == "command-1:join:0")
        .unwrap();
    assert_eq!(wrapped.kind, wire_proto::OutboundKind::Pairwise as i32);
    assert_eq!(wrapped.relay_url, "https://bob-relay.example");
}

#[test]
fn signed_group_join_request_requires_pairwise_envelope() {
    let mut bob = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(2)).unwrap();
    let request = GroupJoinRequest::create(
        &TestIdentity::new(1),
        GroupId::from_bytes([7; 32]),
        [8; 32],
        "https://relay.example",
    )
    .unwrap();
    let generation = bob.checkpoint_generation();
    assert!(matches!(
        bob.execute(
            ClientCommand::apply_group_join_request(
                "unwrapped-request",
                "join-request",
                request.encode(),
            )
            .unwrap(),
        ),
        Err(Error::InvalidSignature)
    ));
    assert_eq!(bob.checkpoint_generation(), generation);
}

#[test]
fn inbound_pairwise_rejects_an_unregistered_olm_key_for_a_known_root() {
    let mut original =
        PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(1)).unwrap();
    let mut replacement =
        PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(1)).unwrap();
    let mut bob = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(2)).unwrap();
    for client in [&mut original, &mut replacement, &mut bob] {
        client
            .execute(ClientCommand::ensure_pairwise_account("account").unwrap())
            .unwrap();
    }
    let original_bundle =
        wire_proto::ClientSnapshot::decode(original.snapshot().unwrap().encode().as_slice())
            .unwrap()
            .pairwise_prekey_bundle;
    let bob_bundle =
        wire_proto::ClientSnapshot::decode(bob.snapshot().unwrap().encode().as_slice())
            .unwrap()
            .pairwise_prekey_bundle;
    bob.execute(
        ClientCommand::register_pairwise_contact(
            "register",
            original_bundle,
            "https://alice-relay.example",
        )
        .unwrap(),
    )
    .unwrap();
    replacement
        .execute(
            ClientCommand::register_pairwise_contact(
                "register",
                bob_bundle,
                "https://bob-relay.example",
            )
            .unwrap(),
        )
        .unwrap();
    let draft = replacement.execute(create_group()).unwrap();
    let request = draft
        .outbound
        .iter()
        .map(|item| wire_proto::OutboundItem::decode(item.encode().as_slice()).unwrap())
        .find(|item| item.destination == TestIdentity::new(2).root_public())
        .unwrap();
    let before = bob.snapshot().unwrap().encode();
    let result = bob.execute(
        ClientCommand::apply_pairwise_control("unexpected-account", request.payload).unwrap(),
    );
    assert!(matches!(result, Err(Error::InvalidSignature)));
    assert_eq!(bob.snapshot().unwrap().encode(), before);
}

struct CheckpointFixtureStore {
    checkpoint: Option<pigeon_core::SealedCheckpoint>,
}

impl CheckpointFixtureStore {
    fn from_checkpoint(checkpoint: pigeon_core::SealedCheckpoint) -> Self {
        Self {
            checkpoint: Some(checkpoint),
        }
    }
}

impl StateStore for CheckpointFixtureStore {
    fn load(&self) -> Result<Option<pigeon_core::SealedCheckpoint>, pigeon_core::StorageError> {
        Ok(self.checkpoint.clone())
    }

    fn replace(
        &mut self,
        expected_generation: u64,
        next: pigeon_core::SealedCheckpoint,
    ) -> Result<(), pigeon_core::StorageError> {
        let current = self
            .checkpoint
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.generation);
        if current != expected_generation || next.generation != expected_generation + 1 {
            return Err(pigeon_core::StorageError::Conflict);
        }
        self.checkpoint = Some(next);
        Ok(())
    }
}

#[test]
fn checkpoint_rejects_unbounded_idempotency_history() {
    let mut client = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(1)).unwrap();
    client
        .execute(ClientCommand::ensure_pairwise_account("seed-checkpoint").unwrap())
        .unwrap();
    let checkpoint = client.store().load().unwrap().unwrap();
    let mut state = wire_proto::ClientCheckpoint::decode(checkpoint.bytes.as_slice()).unwrap();
    state.applied_command_ids = (0..=pigeon_core::MAX_PENDING_OUTBOUND_ENTRIES)
        .map(|index| format!("command-{index}"))
        .collect();
    let bytes = state.encode_to_vec();
    let oversized = pigeon_core::SealedCheckpoint {
        generation: state.generation,
        sha256: Sha256::digest(&bytes).into(),
        bytes,
    };

    let result = PigeonClient::new(
        CheckpointFixtureStore::from_checkpoint(oversized),
        TestIdentity::new(1),
    );

    assert!(matches!(
        result,
        Err(Error::Persistence(pigeon_core::StorageError::Corrupt))
    ));
}

#[test]
fn output_is_released_only_after_the_checkpoint_advances() {
    let (mut client, _, _) = group_clients();
    let previous_generation = client.checkpoint_generation();

    let output = client.execute(create_group()).unwrap();

    assert_eq!(output.checkpoint_generation, previous_generation + 1);
    assert!(output.events.is_empty());
    assert_eq!(output.outbound.len(), 2);
    assert_eq!(client.checkpoint_generation(), previous_generation + 1);
    assert_eq!(
        client.store().load().unwrap().unwrap().generation,
        previous_generation + 1
    );
}
