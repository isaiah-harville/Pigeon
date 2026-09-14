use ed25519_dalek::{Signer, SigningKey};
use pigeon_core::{
    ClientCommand, Error, IdentityError, IdentityPurpose, MemoryStateStore, PigeonClient,
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
