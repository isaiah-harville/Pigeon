use ed25519_dalek::{Signer, SigningKey};
use pigeon_core::{
    Account, ClientCommand, Error, IdentityError, IdentityPurpose, MemoryStateStore, PigeonClient,
    SecureIdentity, wire_proto,
};
use prost::Message;

struct TestIdentity(SigningKey);

impl TestIdentity {
    fn new(byte: u8) -> Self {
        Self(SigningKey::from_bytes(&[byte; 32]))
    }

    fn public(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
}

impl SecureIdentity for TestIdentity {
    fn ensure_public_key(&self, purpose: IdentityPurpose) -> Result<[u8; 32], IdentityError> {
        match purpose {
            IdentityPurpose::Root => Ok(self.public()),
            _ => Err(IdentityError::Unavailable),
        }
    }

    fn sign(&self, purpose: IdentityPurpose, message: &[u8]) -> Result<[u8; 64], IdentityError> {
        match purpose {
            IdentityPurpose::Root => Ok(self.0.sign(message).to_bytes()),
            _ => Err(IdentityError::Unavailable),
        }
    }
}

fn prekey(client: &PigeonClient<MemoryStateStore, TestIdentity>) -> Vec<u8> {
    wire_proto::ClientSnapshot::decode(client.snapshot().unwrap().encode().as_slice())
        .unwrap()
        .pairwise_prekey_bundle
}

fn contact_card(identity: &TestIdentity, prekey: Vec<u8>, relay: &str) -> Vec<u8> {
    let bundle = wire_proto::PrekeyBundle::decode(prekey.as_slice()).unwrap();
    let relay_urls = if relay.is_empty() {
        Vec::new()
    } else {
        vec![relay.into()]
    };
    let relay_signature = if relay.is_empty() {
        Vec::new()
    } else {
        identity.0.sign(relay.as_bytes()).to_bytes().to_vec()
    };
    wire_proto::ContactCard {
        version: 3,
        identity: bundle.identity,
        name: "Bob".into(),
        relay_urls,
        relay_signature,
        prekey_bundle: prekey.clone(),
        pairwise_control_prekey_bundle: prekey,
    }
    .encode_to_vec()
}

fn introduction_payload(
    sender_byte: u8,
    recipient_identity: [u8; 32],
    recipient_prekey: Vec<u8>,
) -> Vec<u8> {
    let sender_identity = TestIdentity::new(sender_byte);
    let mut sender =
        PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(sender_byte)).unwrap();
    sender
        .execute(ClientCommand::ensure_pairwise_account("sender-account").unwrap())
        .unwrap();
    sender
        .execute(
            ClientCommand::register_pairwise_contact_with_relationship(
                "register-recipient",
                recipient_prekey,
                "https://recipient-relay.example",
                wire_proto::PairwiseRelationship::OutgoingRequest,
            )
            .unwrap(),
        )
        .unwrap();
    let card = contact_card(
        &sender_identity,
        prekey(&sender),
        &format!("https://sender-{sender_byte}.relay.example"),
    );
    let sent = sender
        .execute(
            ClientCommand::send_direct_message_request(
                "introduction",
                recipient_identity,
                "hello",
                1,
                card,
            )
            .unwrap(),
        )
        .unwrap();
    wire_proto::OutboundItem::decode(sent.outbound[0].encode().as_slice())
        .unwrap()
        .payload
}

#[test]
fn unknown_sender_gets_exactly_one_authenticated_introduction() {
    let mut alice = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(1)).unwrap();
    let mut bob = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(2)).unwrap();
    alice
        .execute(ClientCommand::ensure_pairwise_account("alice-account").unwrap())
        .unwrap();
    bob.execute(ClientCommand::ensure_pairwise_account("bob-account").unwrap())
        .unwrap();
    let alice_prekey = prekey(&alice);
    let bob_prekey = prekey(&bob);
    bob.execute(
        ClientCommand::register_pairwise_contact_with_relationship(
            "bob-registers-alice",
            alice_prekey,
            "",
            wire_proto::PairwiseRelationship::OutgoingRequest,
        )
        .unwrap(),
    )
    .unwrap();
    let card = contact_card(&TestIdentity::new(2), bob_prekey, "");

    let introduction = bob
        .execute(
            ClientCommand::send_direct_message_request(
                "introduction",
                TestIdentity::new(1).public(),
                "Hello from Bob",
                1_234,
                card.clone(),
            )
            .unwrap(),
        )
        .unwrap();
    let item =
        wire_proto::OutboundItem::decode(introduction.outbound[0].encode().as_slice()).unwrap();
    let received = alice
        .execute(
            ClientCommand::apply_pairwise_control("receive-introduction", item.payload).unwrap(),
        )
        .unwrap();
    let event = wire_proto::AppEvent::decode(received.events[0].encode().as_slice()).unwrap();
    let Some(wire_proto::app_event::Body::DirectApplicationReceived(received)) = event.body else {
        panic!("expected direct introduction event")
    };
    assert_eq!(received.sender_identity, TestIdentity::new(2).public());
    assert_eq!(received.sender_contact_card, card);
    let alice_snapshot =
        wire_proto::ClientSnapshot::decode(alice.snapshot().unwrap().encode().as_slice()).unwrap();
    assert_eq!(alice_snapshot.pairwise_contacts.len(), 1);
    assert_eq!(
        alice_snapshot.pairwise_contacts[0].relationship,
        wire_proto::PairwiseRelationship::IncomingRequest as i32
    );
    assert!(alice_snapshot.pairwise_contacts[0].introduction_received);

    let acknowledgement = alice
        .execute(
            ClientCommand::send_direct_acknowledgement(
                "introduction-ack",
                TestIdentity::new(2).public(),
                "introduction",
            )
            .unwrap(),
        )
        .unwrap();
    let acknowledgement =
        wire_proto::OutboundItem::decode(acknowledgement.outbound[0].encode().as_slice()).unwrap();
    bob.execute(
        ClientCommand::apply_pairwise_control("receive-introduction-ack", acknowledgement.payload)
            .unwrap(),
    )
    .unwrap();

    let extra = bob.execute(
        ClientCommand::send_direct_text(
            "extra-before-acceptance",
            TestIdentity::new(1).public(),
            "This must not surface",
            "",
            1_235,
        )
        .unwrap(),
    );
    assert!(matches!(extra, Err(Error::InvalidSignature)));

    alice
        .execute(
            ClientCommand::set_pairwise_relationship(
                "accept-bob",
                TestIdentity::new(2).public(),
                wire_proto::PairwiseRelationship::Contact,
            )
            .unwrap(),
        )
        .unwrap();
    let acceptance = alice
        .execute(
            ClientCommand::send_direct_contact_acceptance(
                "acceptance-notice",
                TestIdentity::new(2).public(),
            )
            .unwrap(),
        )
        .unwrap();
    let item =
        wire_proto::OutboundItem::decode(acceptance.outbound[0].encode().as_slice()).unwrap();
    let received_acceptance = bob
        .execute(ClientCommand::apply_pairwise_control("receive-acceptance", item.payload).unwrap())
        .unwrap();
    assert_eq!(received_acceptance.events.len(), 1);
    let bob_snapshot =
        wire_proto::ClientSnapshot::decode(bob.snapshot().unwrap().encode().as_slice()).unwrap();
    assert_eq!(
        bob_snapshot.pairwise_contacts[0].relationship,
        wire_proto::PairwiseRelationship::Contact as i32
    );

    let followup = bob
        .execute(
            ClientCommand::send_direct_text(
                "accepted-followup",
                TestIdentity::new(1).public(),
                "Thanks",
                "",
                1_236,
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(followup.outbound.len(), 1);
}

#[test]
fn tampered_introduction_card_rolls_back_session_and_account_state() {
    let mut alice = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(3)).unwrap();
    let mut mallory = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(4)).unwrap();
    alice
        .execute(ClientCommand::ensure_pairwise_account("alice-account").unwrap())
        .unwrap();
    mallory
        .execute(ClientCommand::ensure_pairwise_account("mallory-account").unwrap())
        .unwrap();
    mallory
        .execute(
            ClientCommand::register_pairwise_contact_with_relationship(
                "mallory-registers-alice",
                prekey(&alice),
                "https://alice-relay.example",
                wire_proto::PairwiseRelationship::OutgoingRequest,
            )
            .unwrap(),
        )
        .unwrap();
    let mut card = contact_card(
        &TestIdentity::new(4),
        prekey(&mallory),
        "https://mallory-relay.example",
    );
    *card.last_mut().unwrap() ^= 1;
    let sent = mallory
        .execute(
            ClientCommand::send_direct_message_request(
                "tampered-introduction",
                TestIdentity::new(3).public(),
                "malicious",
                1,
                card,
            )
            .unwrap(),
        )
        .unwrap();
    let item = wire_proto::OutboundItem::decode(sent.outbound[0].encode().as_slice()).unwrap();
    let before = alice.snapshot().unwrap().encode();

    let result = alice.execute(
        ClientCommand::apply_pairwise_control("reject-tampered-card", item.payload).unwrap(),
    );

    assert!(matches!(
        result,
        Err(Error::InvalidSignature | Error::Serialization)
    ));
    assert_eq!(alice.snapshot().unwrap().encode(), before);
}

#[test]
fn incoming_request_admission_is_bounded_and_the_overflow_rolls_back() {
    let identity = TestIdentity::new(70);
    let mut recipient =
        PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(70)).unwrap();
    recipient
        .execute(ClientCommand::ensure_pairwise_account("recipient-account").unwrap())
        .unwrap();
    let recipient_prekey = prekey(&recipient);
    for sender_byte in 10..60 {
        let payload =
            introduction_payload(sender_byte, identity.public(), recipient_prekey.clone());
        let output = recipient
            .execute(
                ClientCommand::apply_pairwise_control(format!("admit-{sender_byte}"), payload)
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(output.events.len(), 1);
    }
    let overflow = introduction_payload(60, identity.public(), recipient_prekey);
    let before = recipient.snapshot().unwrap().encode();

    let result = recipient.execute(
        ClientCommand::apply_pairwise_control("reject-overflow", overflow.clone()).unwrap(),
    );

    assert!(matches!(result, Err(Error::ResourceLimit(_))));
    assert_eq!(recipient.snapshot().unwrap().encode(), before);

    recipient
        .execute(
            ClientCommand::remove_pairwise_contact(
                "purge-old-request",
                TestIdentity::new(10).public(),
            )
            .unwrap(),
        )
        .unwrap();
    let admitted = recipient
        .execute(ClientCommand::apply_pairwise_control("admit-after-purge", overflow).unwrap())
        .unwrap();
    assert_eq!(admitted.events.len(), 1);
}

#[test]
fn legacy_pairwise_account_migrates_without_changing_its_public_curve_key() {
    let legacy = Account::from_identity_seed([21; 32]);
    let legacy_prekey = legacy.signed_prekey_bundle();
    let mut client = PigeonClient::new(MemoryStateStore::default(), TestIdentity::new(21)).unwrap();

    client
        .execute(
            ClientCommand::migrate_legacy_pairwise_state(
                "migrate-legacy-pairwise",
                legacy.export_pairwise_state().unwrap(),
                legacy.export_fallback_key(),
                Vec::new(),
            )
            .unwrap(),
        )
        .unwrap();

    let migrated =
        wire_proto::ClientSnapshot::decode(client.snapshot().unwrap().encode().as_slice()).unwrap();
    let migrated_prekey =
        wire_proto::PrekeyBundle::decode(migrated.pairwise_prekey_bundle.as_slice()).unwrap();
    assert_eq!(
        migrated_prekey.identity.unwrap().curve_identity_key,
        legacy_prekey.identity.curve_identity_key
    );
}

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
