//
//  SessionPersistenceTests.swift
//  PigeonTests
//
//  Locks down the fix for the relaunch-delivery bug: an established Olm session
//  (the Double Ratchet state) must survive being sealed to disk and reloaded, so
//  a cold-started recipient keeps decrypting messages deposited on the relay
//  while it was terminated — instead of losing the session and re-handshaking.
//

import CryptoKit
import PigeonFFI
import XCTest

@testable import Pigeon

@MainActor
final class SessionPersistenceTests: XCTestCase {

  /// Saving a snapshot that carries a live session, then re-attaching, restores
  /// a working session: the conversation continues across the round-trip with no
  /// fresh handshake. This is the persistence-layer counterpart of the FFI's
  /// session pickle round-trip, exercising the actual app wiring (PersistedContact
  /// ↔ SessionRegistry) the bug lived in.
  /// A clean pair of stores (bulk + crypto sibling) under a fresh key.
  private func freshStore() -> EncryptedStore {
    let store = EncryptedStore(key: SymmetricKey(size: .bits256))
    store.wipe()
    store.companion(suffix: ".crypto").wipe()
    return store
  }

  func testEstablishedSessionSurvivesSaveAndReload() throws {
    let store = freshStore()
    let persistence = SessionPersistence()

    // "Alice" is the local device; "Bob" is a contact. Establish a session and
    // settle the ratchet with a reply both ways.
    let alice = try PigeonAccount.generate()
    let bob = try PigeonAccount.generate()
    let prekey = try XCTUnwrap(bob.takeOneTimePrekeyBundles().first)
    let outbound = try alice.establishOutbound(
      peerBundle: prekey, firstPlaintext: Data("hello".utf8))
    let inbound = try bob.establishInbound(initiation: outbound.initiation)
    let reply = try inbound.session.encrypt(plaintext: Data("hi".utf8))
    XCTAssertEqual(try outbound.session.decrypt(message: reply), Data("hi".utf8))

    let bobContact = Contact(
      bundle: try PigeonIdentityBundle(decoding: bob.identityBundle()), displayName: "Bob")
    let contactID = bobContact.id

    // Attach to bind the store, then seal a snapshot carrying Alice's live session.
    _ = persistence.attach(store, identitySeed: alice.exportSeed())
    persistence.save(
      SessionPersistence.Snapshot(
        contacts: [bobContact],
        conversations: [:],
        ephemeralContactIDs: [],
        bluetoothChatIDs: [],
        myName: "Alice",
        account: alice,
        sessions: [contactID: outbound.session],
        pendingInitiation: [:],
        lastInitiationIn: [:],
        fallbackRotatedAt: nil))

    // Re-attach as if the app had been relaunched: the session must come back.
    let reloaded = persistence.attach(store, identitySeed: alice.exportSeed())
    let restored = try XCTUnwrap(reloaded.sessions[contactID])
    XCTAssertEqual(restored.remoteIdentityKey(), bob.identityPublicKey())

    // The restored ratchet keeps talking to Bob's (unrestored) live session.
    let afterRelaunch = try restored.encrypt(plaintext: Data("after relaunch".utf8))
    XCTAssertEqual(
      try inbound.session.decrypt(message: afterRelaunch), Data("after relaunch".utf8))
  }

  /// A pending initiation and the last-processed inbound initiation are persisted
  /// too, so a relaunch mid-establishment resends/dedupes correctly instead of
  /// dropping the in-flight handshake.
  func testInitiationBlobsRoundTrip() throws {
    let store = freshStore()
    let persistence = SessionPersistence()

    let alice = try PigeonAccount.generate()
    let bob = try PigeonAccount.generate()
    let bobContact = Contact(
      bundle: try PigeonIdentityBundle(decoding: bob.identityBundle()), displayName: "Bob")
    let contactID = bobContact.id
    let outBlob = Data("pending-out".utf8)
    let inBlob = Data("last-in".utf8)

    _ = persistence.attach(store, identitySeed: alice.exportSeed())
    persistence.save(
      SessionPersistence.Snapshot(
        contacts: [bobContact],
        conversations: [:],
        ephemeralContactIDs: [],
        bluetoothChatIDs: [],
        myName: "Alice",
        account: alice,
        sessions: [:],
        pendingInitiation: [contactID: outBlob],
        lastInitiationIn: [contactID: inBlob],
        fallbackRotatedAt: nil))

    let reloaded = persistence.attach(store, identitySeed: alice.exportSeed())
    XCTAssertNil(reloaded.sessions[contactID])  // no session was established
    XCTAssertEqual(reloaded.pendingInitiation[contactID], outBlob)
    XCTAssertEqual(reloaded.lastInitiationIn[contactID], inBlob)
  }

  /// The crypto-only fast path (`saveCrypto`) persists the account + session
  /// state and the fallback-rotation timestamp, and survives reload — without a
  /// preceding full `save`. This is what `sendEnvelope` calls on every ratchet
  /// advance.
  func testCryptoFastPathPersistsSessionAndRotationStamp() throws {
    let store = freshStore()
    let persistence = SessionPersistence()

    let alice = try PigeonAccount.generate()
    let bob = try PigeonAccount.generate()
    let prekey = try XCTUnwrap(bob.takeOneTimePrekeyBundles().first)
    let outbound = try alice.establishOutbound(peerBundle: prekey, firstPlaintext: Data("hi".utf8))
    _ = try bob.establishInbound(initiation: outbound.initiation)
    let contactID = bob.identityPublicKey()
    let stamp = Date(timeIntervalSince1970: 1_700_000_000)

    _ = persistence.attach(store, identitySeed: alice.exportSeed())
    persistence.saveCrypto(
      SessionPersistence.Snapshot(
        contacts: [],
        conversations: [:],
        ephemeralContactIDs: [],
        bluetoothChatIDs: [],
        myName: "",
        account: alice,
        sessions: [contactID: outbound.session],
        pendingInitiation: [:],
        lastInitiationIn: [:],
        fallbackRotatedAt: stamp))

    let reloaded = persistence.attach(store, identitySeed: alice.exportSeed())
    XCTAssertNotNil(reloaded.sessions[contactID])
    XCTAssertEqual(
      reloaded.fallbackRotatedAt?.timeIntervalSince1970, stamp.timeIntervalSince1970)
  }
}
