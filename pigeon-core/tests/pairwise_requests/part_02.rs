#[test]
fn malformed_legacy_session_rolls_back_the_whole_migration() {
    let legacy = Account::from_identity_seed([22; 32]);
    let mut client = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(22)).unwrap();
    let before = client.snapshot().unwrap().encode();

    let result = client.execute(
        ClientCommand::migrate_legacy_pairwise_state(
            "reject-legacy-pairwise",
            legacy.export_pairwise_state().unwrap(),
            legacy.export_fallback_key(),
            vec![([23; 32], vec![1, 2, 3])],
        )
        .unwrap(),
    );

    assert!(matches!(result, Err(Error::Serialization)));
    assert_eq!(client.snapshot().unwrap().encode(), before);
}

#[test]
fn legacy_migration_cannot_replace_an_initialized_core_account() {
    let legacy = Account::from_identity_seed([24; 32]);
    let mut client = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(24)).unwrap();
    client
        .execute(ClientCommand::ensure_pairwise_account("initialize-core").unwrap())
        .unwrap();
    let before = client.snapshot().unwrap().encode();

    let result = client.execute(
        ClientCommand::migrate_legacy_pairwise_state(
            "replace-core",
            legacy.export_pairwise_state().unwrap(),
            legacy.export_fallback_key(),
            Vec::new(),
        )
        .unwrap(),
    );

    assert!(matches!(result, Err(Error::InvalidSignature)));
    assert_eq!(client.snapshot().unwrap().encode(), before);
}

fn mutual_contacts() -> (
    PigeonClient<MemoryStateStore, TestIdentity>,
    PigeonClient<MemoryStateStore, TestIdentity>,
) {
    let mut alice = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(1)).unwrap();
    let mut bob = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(2)).unwrap();
    alice
        .execute(ClientCommand::ensure_pairwise_account("alice-account").unwrap())
        .unwrap();
    bob.execute(ClientCommand::ensure_pairwise_account("bob-account").unwrap())
        .unwrap();
    let (alice_prekey, bob_prekey) = (prekey(&alice), prekey(&bob));
    alice
        .execute(
            ClientCommand::register_pairwise_contact("alice-adds-bob", bob_prekey, "").unwrap(),
        )
        .unwrap();
    bob.execute(
        ClientCommand::register_pairwise_contact("bob-adds-alice", alice_prekey, "").unwrap(),
    )
    .unwrap();
    (alice, bob)
}

fn send_text(
    sender: &mut PigeonClient<MemoryStateStore, TestIdentity>,
    command_id: &str,
    recipient: [u8; 32],
) -> Vec<u8> {
    let output = sender
        .execute(ClientCommand::send_direct_text(command_id, recipient, command_id, "", 1).unwrap())
        .unwrap();
    wire_proto::OutboundItem::decode(output.outbound[0].encode().as_slice())
        .unwrap()
        .payload
}

fn received_text(
    recipient: &mut PigeonClient<MemoryStateStore, TestIdentity>,
    command_id: &str,
    envelope: Vec<u8>,
) -> String {
    let output = recipient
        .execute(ClientCommand::apply_pairwise_control(command_id, envelope).unwrap())
        .unwrap();
    let event = wire_proto::AppEvent::decode(output.events[0].encode().as_slice()).unwrap();
    let Some(wire_proto::app_event::Body::DirectApplicationReceived(received)) = event.body else {
        panic!("expected a direct application event")
    };
    let Some(wire_proto::direct_application::Body::Message(message)) =
        received.application.unwrap().body
    else {
        panic!("expected a direct message")
    };
    message.text
}

/// Re-encodes an envelope with a trailing unknown field: identical protocol
/// content under a different envelope hash, as a replay past the hash window.
fn rehashed(mut envelope: Vec<u8>) -> Vec<u8> {
    envelope.extend_from_slice(&[0x78, 0x01]);
    envelope
}

#[test]
fn crossing_initiations_between_contacts_converge() {
    let (mut alice, mut bob) = mutual_contacts();
    let (alice_id, bob_id) = (TestIdentity::new(1).public(), TestIdentity::new(2).public());

    // Both open a session before either sees the other's initiation.
    let alice_first = send_text(&mut alice, "alice-first", bob_id);
    let alice_queued = send_text(&mut alice, "alice-queued", bob_id);
    let bob_first = send_text(&mut bob, "bob-first", alice_id);

    assert_eq!(
        received_text(&mut bob, "bob-gets-first", alice_first),
        "alice-first"
    );
    assert_eq!(
        received_text(&mut alice, "alice-gets-first", bob_first),
        "bob-first"
    );
    // Ciphertext queued on Alice's original session still decrypts.
    assert_eq!(
        received_text(&mut bob, "bob-gets-queued", alice_queued),
        "alice-queued"
    );

    for round in 0..3 {
        let to_bob = send_text(&mut alice, &format!("alice-{round}"), bob_id);
        assert_eq!(
            received_text(&mut bob, &format!("bob-gets-{round}"), to_bob),
            format!("alice-{round}")
        );
        let to_alice = send_text(&mut bob, &format!("bob-{round}"), alice_id);
        assert_eq!(
            received_text(&mut alice, &format!("alice-gets-{round}"), to_alice),
            format!("bob-{round}")
        );
    }
}

#[test]
fn initiation_is_rejected_once_a_session_is_confirmed() {
    let (mut alice, mut bob) = mutual_contacts();
    let bob_id = TestIdentity::new(2).public();
    let initiation = send_text(&mut alice, "alice-first", bob_id);
    received_text(&mut bob, "bob-gets-first", initiation.clone());

    let replay = bob.execute(
        ClientCommand::apply_pairwise_control("bob-gets-replay", rehashed(initiation)).unwrap(),
    );
    assert!(matches!(replay, Err(Error::InvalidSignature)));
}

#[test]
fn crossing_initiations_admit_at_most_one_extra_session() {
    let (mut alice, mut bob) = mutual_contacts();
    let (alice_id, bob_id) = (TestIdentity::new(1).public(), TestIdentity::new(2).public());
    let alice_first = send_text(&mut alice, "alice-first", bob_id);
    send_text(&mut bob, "bob-first", alice_id);
    received_text(&mut bob, "bob-gets-first", alice_first.clone());

    let replay = bob.execute(
        ClientCommand::apply_pairwise_control("bob-gets-replay", rehashed(alice_first)).unwrap(),
    );
    assert!(matches!(replay, Err(Error::InvalidSignature)));
}

fn outgoing_requesters() -> (
    PigeonClient<MemoryStateStore, TestIdentity>,
    PigeonClient<MemoryStateStore, TestIdentity>,
) {
    let mut alice = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(1)).unwrap();
    let mut bob = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(2)).unwrap();
    alice
        .execute(ClientCommand::ensure_pairwise_account("alice-account").unwrap())
        .unwrap();
    bob.execute(ClientCommand::ensure_pairwise_account("bob-account").unwrap())
        .unwrap();
    let (alice_prekey, bob_prekey) = (prekey(&alice), prekey(&bob));
    alice
        .execute(
            ClientCommand::register_pairwise_contact_with_relationship(
                "alice-scans-bob",
                bob_prekey,
                "",
                wire_proto::PairwiseRelationship::OutgoingRequest,
            )
            .unwrap(),
        )
        .unwrap();
    bob.execute(
        ClientCommand::register_pairwise_contact_with_relationship(
            "bob-scans-alice",
            alice_prekey,
            "",
            wire_proto::PairwiseRelationship::OutgoingRequest,
        )
        .unwrap(),
    )
    .unwrap();
    (alice, bob)
}

fn send_request(
    sender: &mut PigeonClient<MemoryStateStore, TestIdentity>,
    sender_byte: u8,
    recipient: [u8; 32],
) -> Vec<u8> {
    let card = contact_card(&TestIdentity::new(sender_byte), prekey(sender), "");
    let output = sender
        .execute(
            ClientCommand::send_direct_message_request(
                format!("request-from-{sender_byte}"),
                recipient,
                "hello",
                1,
                card,
            )
            .unwrap(),
        )
        .unwrap();
    wire_proto::OutboundItem::decode(output.outbound[0].encode().as_slice())
        .unwrap()
        .payload
}

fn relationship(client: &PigeonClient<MemoryStateStore, TestIdentity>) -> i32 {
    wire_proto::ClientSnapshot::decode(client.snapshot().unwrap().encode().as_slice())
        .unwrap()
        .pairwise_contacts[0]
        .relationship
}

#[test]
fn crossing_message_requests_are_mutual_acceptance() {
    let (mut alice, mut bob) = outgoing_requesters();
    let (alice_id, bob_id) = (TestIdentity::new(1).public(), TestIdentity::new(2).public());
    let from_alice = send_request(&mut alice, 1, bob_id);
    let from_bob = send_request(&mut bob, 2, alice_id);

    assert_eq!(
        received_text(&mut bob, "bob-gets-request", from_alice),
        "hello"
    );
    assert_eq!(
        received_text(&mut alice, "alice-gets-request", from_bob),
        "hello"
    );
    let contact = wire_proto::PairwiseRelationship::Contact as i32;
    assert_eq!(relationship(&alice), contact);
    assert_eq!(relationship(&bob), contact);

    let to_bob = send_text(&mut alice, "after-acceptance", bob_id);
    assert_eq!(
        received_text(&mut bob, "bob-gets-after", to_bob),
        "after-acceptance"
    );
}
