fn pairwise_session_count(client: &PigeonClient<MemoryStateStore, TestIdentity>) -> usize {
    let sealed = pigeon_core::StateStore::load(client.store()).unwrap().unwrap();
    wire_proto::ClientCheckpoint::decode(sealed.bytes.as_slice())
        .unwrap()
        .pairwise_sessions
        .len()
}

#[test]
fn later_message_establishes_the_session_when_the_initiation_is_lost() {
    let (mut alice, mut bob) = mutual_contacts();
    let (alice_id, bob_id) = (TestIdentity::new(1).public(), TestIdentity::new(2).public());
    let lost = send_text(&mut alice, "alice-first", bob_id);
    let second = send_text(&mut alice, "alice-second", bob_id);

    assert_eq!(
        received_text(&mut bob, "bob-gets-second", second),
        "alice-second"
    );
    // The delayed first message decrypts on the session the second one opened.
    assert_eq!(
        received_text(&mut bob, "bob-gets-first", lost),
        "alice-first"
    );
    assert_eq!(pairwise_session_count(&bob), 1);

    let reply = send_text(&mut bob, "bob-reply", alice_id);
    assert_eq!(
        received_text(&mut alice, "alice-gets-reply", reply),
        "bob-reply"
    );
}

#[test]
fn message_request_after_a_rejected_first_message_reaches_the_recipient() {
    let mut alice = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(1)).unwrap();
    let mut bob = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(2)).unwrap();
    alice
        .execute(ClientCommand::ensure_pairwise_account("alice-account").unwrap())
        .unwrap();
    bob.execute(ClientCommand::ensure_pairwise_account("bob-account").unwrap())
        .unwrap();
    let bob_id = TestIdentity::new(2).public();
    // Alice scanned Bob in person, but Bob never scanned Alice back.
    alice
        .execute(
            ClientCommand::register_pairwise_contact("alice-scans-bob", prekey(&bob), "").unwrap(),
        )
        .unwrap();
    let unknown = send_text(&mut alice, "alice-first", bob_id);
    let rejected =
        bob.execute(ClientCommand::apply_pairwise_control("bob-rejects", unknown).unwrap());
    assert!(matches!(rejected, Err(Error::InvalidSignature)));

    alice
        .execute(
            ClientCommand::set_pairwise_relationship(
                "alice-sends-request",
                bob_id,
                wire_proto::PairwiseRelationship::OutgoingRequest,
            )
            .unwrap(),
        )
        .unwrap();
    let request = send_request(&mut alice, 1, bob_id);

    assert_eq!(
        received_text(&mut bob, "bob-gets-request", request),
        "hello"
    );
    assert_eq!(
        relationship(&bob),
        wire_proto::PairwiseRelationship::IncomingRequest as i32
    );
}

#[test]
fn replayed_prekey_message_does_not_open_a_second_session() {
    let (mut alice, mut bob) = mutual_contacts();
    let bob_id = TestIdentity::new(2).public();
    send_text(&mut alice, "alice-first", bob_id);
    let second = send_text(&mut alice, "alice-second", bob_id);
    received_text(&mut bob, "bob-gets-second", second.clone());

    let replay = bob.execute(
        ClientCommand::apply_pairwise_control("bob-gets-replay", rehashed(second)).unwrap(),
    );
    assert!(replay.is_err());
    assert_eq!(pairwise_session_count(&bob), 1);
}

#[test]
fn request_to_a_peer_who_already_added_us_opens_the_chat() {
    let (mut alice, mut bob) = mutual_contacts();
    let (alice_id, bob_id) = (TestIdentity::new(1).public(), TestIdentity::new(2).public());
    // Alice added Bob from his shared card; Bob scanned Alice in person.
    alice
        .execute(
            ClientCommand::set_pairwise_relationship(
                "alice-sends-request",
                bob_id,
                wire_proto::PairwiseRelationship::OutgoingRequest,
            )
            .unwrap(),
        )
        .unwrap();
    let request = send_request(&mut alice, 1, bob_id);
    assert_eq!(
        received_text(&mut bob, "bob-gets-request", request),
        "hello"
    );

    // Bob's reply is his acceptance.
    let reply = send_text(&mut bob, "bob-reply", alice_id);
    assert_eq!(
        received_text(&mut alice, "alice-gets-reply", reply),
        "bob-reply"
    );
    assert_eq!(
        relationship(&alice),
        wire_proto::PairwiseRelationship::Contact as i32
    );
    let follow_up = send_text(&mut alice, "alice-follow-up", bob_id);
    assert_eq!(
        received_text(&mut bob, "bob-gets-follow-up", follow_up),
        "alice-follow-up"
    );
}
