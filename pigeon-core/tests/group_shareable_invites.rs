use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use pigeon_core::{
    GroupId, GroupInviteInbox, GroupInviteIntent, GroupInviteMode, GroupInviteReplyInbox,
    GroupInviteReplyStatus, GroupInviteTicket, GroupJoinMaterial, GroupJoinRequest, IdentityError,
    IdentityPurpose, SecureIdentity, TransactionalOpenMlsStorage,
};

struct TestIdentity(SigningKey);

impl SecureIdentity for TestIdentity {
    fn ensure_public_key(&self, _purpose: IdentityPurpose) -> Result<[u8; 32], IdentityError> {
        Ok(self.0.verifying_key().to_bytes())
    }

    fn sign(&self, _purpose: IdentityPurpose, message: &[u8]) -> Result<[u8; 64], IdentityError> {
        Ok(self.0.sign(message).to_bytes())
    }
}

fn sample_ticket(mode: GroupInviteMode) -> GroupInviteTicket {
    GroupInviteTicket::new(
        GroupId::from_bytes([1; 32]),
        [2; 32],
        [3; 32],
        "wss://relay.example/group".to_owned(),
        [4; 32],
        [5; 32],
        [6; 32],
        mode,
        1_800_000_000_000,
    )
    .unwrap()
}

#[test]
fn invite_ticket_round_trips_without_issuer_root_identity() {
    let ticket = sample_ticket(GroupInviteMode::Public);
    let encoded = ticket.encode();
    let decoded = GroupInviteTicket::decode(&encoded).unwrap();
    assert_eq!(decoded, ticket);
    assert_eq!(decoded.mode(), GroupInviteMode::Public);
    assert_eq!(decoded.group_id(), GroupId::from_bytes([1; 32]));
    assert_eq!(decoded.inbox_address(), [4; 32]);
    assert!(decoded.validate(1_700_000_000_000).is_ok());
    assert!(decoded.validate(1_800_000_000_000).is_err());
    assert!(!encoded.windows(32).any(|window| window == [42; 32]));
}

#[test]
fn invite_ticket_rejects_invalid_relay_and_oversized_encoding() {
    assert!(
        GroupInviteTicket::new(
            GroupId::from_bytes([1; 32]),
            [2; 32],
            [3; 32],
            "http://relay.example".to_owned(),
            [4; 32],
            [5; 32],
            [6; 32],
            GroupInviteMode::Private,
            1_800_000_000_000,
        )
        .is_err()
    );
    assert!(GroupInviteTicket::decode(&vec![0; 4097]).is_err());
    let mut encoded = sample_ticket(GroupInviteMode::Public).encode();
    encoded.extend_from_slice(&[0x80, 0x3e, 0x01]);
    assert!(
        GroupInviteTicket::decode(&encoded).is_err(),
        "unknown fields must not alias a ticket digest"
    );
}

#[test]
fn invite_intent_binds_ticket_request_and_reply_key() {
    let identity = TestIdentity(SigningKey::from_bytes(&[42; 32]));
    let ticket = sample_ticket(GroupInviteMode::Private);
    let intent =
        GroupInviteIntent::create(&identity, &ticket, [7; 32], [8; 32], [9; 32], [10; 32]).unwrap();
    let decoded = GroupInviteIntent::decode(&intent.encode()).unwrap();
    decoded.verify(&ticket).unwrap();
    assert_eq!(
        decoded.requester_identity(),
        identity.0.verifying_key().to_bytes()
    );
    assert_eq!(decoded.request_id(), [7; 32]);
    assert_eq!(decoded.reply_address(), [8; 32]);
    assert!(
        decoded
            .verify(&sample_ticket(GroupInviteMode::Public))
            .is_err()
    );
    assert!(
        decoded
            .verify(&sample_ticket(GroupInviteMode::Private))
            .is_err()
    );
}

#[test]
fn encrypted_invite_request_survives_inbox_restore_and_rejects_replay() {
    let identity = TestIdentity(SigningKey::from_bytes(&[42; 32]));
    let (ticket, inbox) = GroupInviteInbox::create(
        GroupId::from_bytes([1; 32]),
        [2; 32],
        [3; 32],
        "wss://relay.example/group".to_owned(),
        GroupInviteMode::Private,
        1_800_000_000_000,
    )
    .unwrap();
    let intent =
        GroupInviteIntent::create(&identity, &ticket, [7; 32], [8; 32], [9; 32], [10; 32]).unwrap();
    let encrypted = GroupInviteInbox::seal_request(&ticket, &intent, 1_700_000_000_000).unwrap();
    assert!(
        !encrypted
            .windows(32)
            .any(|window| window == identity.0.verifying_key().as_bytes())
    );
    let state = inbox.export_state().unwrap();
    let mut restored = GroupInviteInbox::import_state(&state, &ticket).unwrap();
    let mailbox_key = VerifyingKey::from_bytes(&ticket.inbox_address()).unwrap();
    mailbox_key
        .verify(
            &[9; 32],
            &Signature::from_bytes(&restored.sign_mailbox_challenge(&[9; 32]).unwrap()),
        )
        .unwrap();
    let opened = restored
        .open_request(&ticket, &encrypted, 1_700_000_000_000)
        .unwrap();
    assert_eq!(opened.request_id(), [7; 32]);
    let after_open = restored.export_state().unwrap();
    let mut restored_again = GroupInviteInbox::import_state(&after_open, &ticket).unwrap();
    assert!(
        restored_again
            .open_request(&ticket, &encrypted, 1_700_000_000_000)
            .is_err()
    );
}

#[test]
fn encrypted_invite_request_rejects_tamper_wrong_ticket_and_expiry() {
    let identity = TestIdentity(SigningKey::from_bytes(&[42; 32]));
    let (ticket, mut inbox) = GroupInviteInbox::create(
        GroupId::from_bytes([1; 32]),
        [2; 32],
        [3; 32],
        "wss://relay.example/group".to_owned(),
        GroupInviteMode::Public,
        1_800_000_000_000,
    )
    .unwrap();
    let intent =
        GroupInviteIntent::create(&identity, &ticket, [7; 32], [8; 32], [9; 32], [10; 32]).unwrap();
    let encrypted = GroupInviteInbox::seal_request(&ticket, &intent, 1_700_000_000_000).unwrap();
    let mut tampered = encrypted.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(
        inbox
            .open_request(&ticket, &tampered, 1_700_000_000_000)
            .is_err()
    );
    assert!(
        inbox
            .open_request(
                &sample_ticket(GroupInviteMode::Public),
                &encrypted,
                1_700_000_000_000
            )
            .is_err()
    );
    assert!(
        inbox
            .open_request(&ticket, &encrypted, 1_800_000_000_000)
            .is_err()
    );
    assert_eq!(
        inbox
            .open_request(&ticket, &encrypted, 1_700_000_000_000)
            .unwrap()
            .request_id(),
        [7; 32]
    );
}

#[test]
fn approval_reply_is_encrypted_authenticated_and_durable() {
    let joiner = TestIdentity(SigningKey::from_bytes(&[42; 32]));
    let admin = TestIdentity(SigningKey::from_bytes(&[43; 32]));
    let (ticket, inbox) = GroupInviteInbox::create(
        GroupId::from_bytes([1; 32]),
        [2; 32],
        [3; 32],
        "wss://relay.example/group".to_owned(),
        GroupInviteMode::Private,
        1_800_000_000_000,
    )
    .unwrap();
    let reply = GroupInviteReplyInbox::create(&ticket, [7; 32]).unwrap();
    let intent = GroupInviteIntent::create(
        &joiner,
        &ticket,
        [7; 32],
        reply.address(),
        reply.curve_identity_key(),
        reply.fallback_prekey(),
    )
    .unwrap();
    let join_request = GroupJoinRequest::create_for_owner(
        &admin,
        admin.0.verifying_key().to_bytes(),
        ticket.group_id(),
        ticket.coordination_id(),
        ticket.relay_url(),
    )
    .unwrap();
    let ciphertext = inbox
        .seal_reply(
            &ticket,
            &intent,
            GroupInviteReplyStatus::Approved,
            Some(&join_request),
            1_700_000_000_000,
        )
        .unwrap();
    assert!(
        !ciphertext
            .windows(32)
            .any(|window| window == admin.0.verifying_key().as_bytes())
    );
    let state = reply.export_state().unwrap();
    let mut restored = GroupInviteReplyInbox::import_state(&state, &ticket).unwrap();
    let opened = restored
        .open_reply(&ticket, &ciphertext, 1_700_000_000_000)
        .unwrap();
    assert_eq!(opened.status(), GroupInviteReplyStatus::Approved);
    assert_eq!(
        opened.join_request().unwrap().requester_identity(),
        admin.0.verifying_key().to_bytes()
    );
    let state = restored.export_state().unwrap();
    let mut restored = GroupInviteReplyInbox::import_state(&state, &ticket).unwrap();
    assert!(
        restored
            .open_reply(&ticket, &ciphertext, 1_700_000_000_000)
            .is_err()
    );
}

#[test]
fn join_material_returns_only_through_encrypted_invite_inbox() {
    let joiner = TestIdentity(SigningKey::from_bytes(&[42; 32]));
    let admin = TestIdentity(SigningKey::from_bytes(&[43; 32]));
    let (ticket, mut inbox) = GroupInviteInbox::create(
        GroupId::from_bytes([1; 32]),
        [2; 32],
        [3; 32],
        "wss://relay.example/group".to_owned(),
        GroupInviteMode::Public,
        1_800_000_000_000,
    )
    .unwrap();
    let mut storage = TransactionalOpenMlsStorage::new();
    let material = GroupJoinMaterial::issue_for(
        &joiner,
        admin.0.verifying_key().to_bytes(),
        admin.0.verifying_key().to_bytes(),
        ticket.group_id(),
        ticket.coordination_id(),
        &mut storage,
    )
    .unwrap();
    let ciphertext =
        GroupInviteInbox::seal_material(&ticket, [7; 32], &material, 1_700_000_000_000).unwrap();
    assert!(
        !ciphertext
            .windows(32)
            .any(|window| window == joiner.0.verifying_key().as_bytes())
    );
    let opened = inbox
        .open_material(&ticket, &ciphertext, 1_700_000_000_000)
        .unwrap();
    assert_eq!(opened.request_id(), [7; 32]);
    assert_eq!(
        opened.material().member_identity(),
        joiner.0.verifying_key().to_bytes()
    );
}
