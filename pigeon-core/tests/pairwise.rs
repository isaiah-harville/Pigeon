//! Behavioral tests for the pairwise session core.
//!
//! These port the *intent* of the Swift `PigeonCrypto` suite (SecureSession,
//! DoubleRatchet, X3DH, SessionLifecycle) to the Olm-based core. Byte-format
//! assertions from the Swift tests do not carry over — the wire format is now
//! Olm's — so these assert observable behavior: async first contact, the
//! identity binding, one-time-prekey replay defence, out-of-order / skipped
//! message handling, forward secrecy, and persistence. The ratchet *math* is
//! vodozemac's and is covered by vodozemac's own vectors.

use pigeon_core::{Account, IdentityBundle, OlmMessage, PrekeyBundle, Session};

/// Alice opens a session to Bob via a prekey bundle and sends a first message;
/// Bob establishes the matching inbound session and recovers it. Returns the
/// two accounts and the two converged sessions (after one reply each way).
fn converged_pair() -> (Account, Account, Session, Session) {
    let alice = Account::new().unwrap();
    let mut bob = Account::new().unwrap();

    let bob_bundle = bob.take_one_time_prekey_bundles().pop().unwrap();

    let (mut alice_session, initiation) =
        Session::establish_outbound(&alice, &bob_bundle, b"hello bob").unwrap();

    let (mut bob_session, first) =
        Session::establish_inbound(&mut bob, &initiation.identity, &initiation.message).unwrap();
    assert_eq!(first, b"hello bob");

    // A reply settles the ratchet so both ends are fully converged.
    let reply = bob_session.encrypt(b"hi alice").unwrap();
    assert_eq!(alice_session.decrypt(&reply).unwrap(), b"hi alice");

    (alice, bob, alice_session, bob_session)
}

#[test]
fn first_contact_with_one_time_key() {
    let alice = Account::new().unwrap();
    let mut bob = Account::new().unwrap();

    let bundle = bob.take_one_time_prekey_bundles().pop().unwrap();
    assert!(bundle.one_time, "one-time bundles must be flagged as such");

    let (_alice_session, initiation) =
        Session::establish_outbound(&alice, &bundle, b"first").unwrap();
    let (_bob_session, plaintext) =
        Session::establish_inbound(&mut bob, &initiation.identity, &initiation.message).unwrap();

    assert_eq!(plaintext, b"first");
    // The session records the peer's verified identity for the safety-number check.
    assert_eq!(
        initiation.identity.identity_key,
        alice.identity_public_key()
    );
}

#[test]
fn first_contact_with_fallback_key() {
    let alice = Account::new().unwrap();
    let mut bob = Account::new().unwrap();

    // The fallback (signed-prekey) path works even with no one-time keys.
    let bundle = bob.signed_prekey_bundle();
    assert!(
        !bundle.one_time,
        "the fallback bundle must not be flagged one-time"
    );

    let (_a, initiation) = Session::establish_outbound(&alice, &bundle, b"async hi").unwrap();
    let (_b, plaintext) =
        Session::establish_inbound(&mut bob, &initiation.identity, &initiation.message).unwrap();
    assert_eq!(plaintext, b"async hi");
}

#[test]
fn remote_identity_key_is_the_verified_peer() {
    let (alice, bob, alice_session, bob_session) = converged_pair();
    assert_eq!(
        alice_session.remote_identity_key(),
        bob.identity_public_key()
    );
    assert_eq!(
        bob_session.remote_identity_key(),
        alice.identity_public_key()
    );
}

#[test]
fn out_of_order_and_skipped_messages_decrypt() {
    let (_alice, _bob, mut alice_session, mut bob_session) = converged_pair();

    // Bob sends five; Alice receives them shuffled (and thus with gaps).
    let plaintexts: [&[u8]; 5] = [b"m0", b"m1", b"m2", b"m3", b"m4"];
    let messages: Vec<OlmMessage> = plaintexts
        .iter()
        .map(|p| bob_session.encrypt(p).unwrap())
        .collect();

    for &i in &[2usize, 0, 4, 1, 3] {
        assert_eq!(alice_session.decrypt(&messages[i]).unwrap(), plaintexts[i]);
    }
}

#[test]
fn replaying_a_message_fails() {
    // Forward secrecy / single-use: a message key is consumed on first decrypt.
    let (_alice, _bob, mut alice_session, mut bob_session) = converged_pair();

    let message = bob_session.encrypt(b"only once").unwrap();
    assert_eq!(alice_session.decrypt(&message).unwrap(), b"only once");
    assert!(
        alice_session.decrypt(&message).is_err(),
        "replaying the same ciphertext must fail"
    );
}

#[test]
fn one_time_prekey_replay_is_rejected() {
    let alice = Account::new().unwrap();
    let mut bob = Account::new().unwrap();

    let bundle = bob.take_one_time_prekey_bundles().pop().unwrap();
    let (_a, initiation) = Session::establish_outbound(&alice, &bundle, b"hi").unwrap();

    // First inbound establishment consumes Bob's one-time key.
    let (_b, plaintext) =
        Session::establish_inbound(&mut bob, &initiation.identity, &initiation.message).unwrap();
    assert_eq!(plaintext, b"hi");

    // Replaying the same initiation must fail: the one-time key is gone.
    assert!(
        Session::establish_inbound(&mut bob, &initiation.identity, &initiation.message).is_err(),
        "a replayed one-time-prekey initiation must be rejected"
    );
}

#[test]
fn tampered_identity_binding_is_rejected() {
    let alice = Account::new().unwrap();
    let mut bob = Account::new().unwrap();

    let mut bundle = bob.take_one_time_prekey_bundles().pop().unwrap();
    bundle.identity.binding_signature[0] ^= 0x01;

    assert!(
        bundle.verify().is_err(),
        "a tampered identity binding must not verify"
    );
    assert!(
        Session::establish_outbound(&alice, &bundle, b"x").is_err(),
        "establishment must refuse a bundle whose binding does not verify"
    );

    // And a tampered initiator identity must be refused on the inbound side.
    let good = bob.signed_prekey_bundle();
    let (_a, mut initiation) = Session::establish_outbound(&alice, &good, b"y").unwrap();
    initiation.identity.binding_signature[0] ^= 0x01;
    assert!(
        Session::establish_inbound(&mut bob, &initiation.identity, &initiation.message).is_err(),
        "inbound establishment must refuse a tampered initiator identity"
    );
}

#[test]
fn tampered_prekey_is_rejected() {
    let alice = Account::new().unwrap();
    let mut bob = Account::new().unwrap();

    let mut bundle = bob.take_one_time_prekey_bundles().pop().unwrap();
    bundle.prekey[0] ^= 0x01; // key no longer matches its signature

    assert!(bundle.verify().is_err());
    assert!(Session::establish_outbound(&alice, &bundle, b"x").is_err());
}

#[test]
fn a_normal_message_cannot_start_a_session() {
    let (_alice, mut bob, mut alice_session, _bob_session) = converged_pair();

    // Once converged, Alice produces normal (non-pre-key) messages.
    let normal = alice_session.encrypt(b"normal").unwrap();
    assert!(matches!(normal, OlmMessage::Normal(_)));

    let identity = {
        let a = Account::new().unwrap();
        a.identity_bundle()
    };
    assert!(
        matches!(
            Session::establish_inbound(&mut bob, &identity, &normal),
            Err(pigeon_core::Error::NotAPreKeyMessage)
        ),
        "only a pre-key message may begin an inbound session"
    );
}

#[test]
fn account_persistence_preserves_identity_and_keys() {
    let alice = Account::new().unwrap();
    let mut bob = Account::new().unwrap();

    let bob_identity_before = bob.identity_public_key();
    let bundle = bob.take_one_time_prekey_bundles().pop().unwrap();

    // Alice prepares an initiation against Bob's published one-time key...
    let (_a, initiation) = Session::establish_outbound(&alice, &bundle, b"saved?").unwrap();

    // ...meanwhile Bob is persisted and reloaded (e.g. app relaunch).
    let seed = *bob.export_identity_seed();
    let pickle = bob.export_olm_pickle();
    let fallback = bob.export_fallback_key();
    let mut bob_reloaded = Account::import(seed, pickle, fallback);

    assert_eq!(
        bob_reloaded.identity_public_key(),
        bob_identity_before,
        "identity must survive a persistence round-trip"
    );

    // The reloaded account still holds the one-time key, so it can establish.
    let (_b, plaintext) =
        Session::establish_inbound(&mut bob_reloaded, &initiation.identity, &initiation.message)
            .unwrap();
    assert_eq!(plaintext, b"saved?");
}

#[test]
fn bundle_encodings_round_trip() {
    let mut bob = Account::new().unwrap();

    let identity = bob.identity_bundle();
    let decoded = IdentityBundle::decode(&identity.encode()).unwrap();
    assert_eq!(identity, decoded);
    assert!(decoded.verify().is_ok());

    let prekey = bob.take_one_time_prekey_bundles().pop().unwrap();
    let decoded = PrekeyBundle::decode(&prekey.encode()).unwrap();
    assert_eq!(prekey, decoded);
    assert!(decoded.verify().is_ok());

    // Wrong length is rejected.
    assert!(matches!(
        IdentityBundle::decode(&[0u8; 10]),
        Err(pigeon_core::Error::MalformedBundle)
    ));
    assert!(matches!(
        PrekeyBundle::decode(&[0u8; 10]),
        Err(pigeon_core::Error::MalformedBundle)
    ));
}
