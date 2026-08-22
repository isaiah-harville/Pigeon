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

  private enum ExportFailure: Error {
    case injected
  }

  func testCorruptBulkStoreFailsInsteadOfStartingEmpty() throws {
    let url = FileManager.default.temporaryDirectory
      .appendingPathComponent("pigeon-corrupt-\(UUID().uuidString).store")
    defer { try? FileManager.default.removeItem(at: url) }
    try Data("not an encrypted store".utf8).write(to: url)

    let persistence = SessionPersistence()
    let store = EncryptedStore(key: SymmetricKey(size: .bits256), url: url)

    XCTAssertThrowsError(try persistence.attach(store, identitySeed: Data(repeating: 7, count: 32)))
  }

  func testWrongKeyFailsInsteadOfReplacingStoredIdentityState() throws {
    let url = FileManager.default.temporaryDirectory
      .appendingPathComponent("pigeon-wrong-key-\(UUID().uuidString).store")
    defer { try? FileManager.default.removeItem(at: url) }
    let original = EncryptedStore(key: SymmetricKey(size: .bits256), url: url)
    XCTAssertTrue(original.save(PersistedState(myName: "Existing account")))

    let persistence = SessionPersistence()
    let wrongKeyStore = EncryptedStore(key: SymmetricKey(size: .bits256), url: url)

    XCTAssertThrowsError(
      try persistence.attach(wrongKeyStore, identitySeed: Data(repeating: 9, count: 32)))
  }

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
    store.companion(suffix: ".transaction").wipe()
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
    _ = try persistence.attach(store, identitySeed: alice.exportSeed())
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
    let reloaded = try persistence.attach(store, identitySeed: alice.exportSeed())
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

    _ = try persistence.attach(store, identitySeed: alice.exportSeed())
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

    let reloaded = try persistence.attach(store, identitySeed: alice.exportSeed())
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

    _ = try persistence.attach(store, identitySeed: alice.exportSeed())
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

    let reloaded = try persistence.attach(store, identitySeed: alice.exportSeed())
    XCTAssertNotNil(reloaded.sessions[contactID])
    XCTAssertEqual(
      reloaded.fallbackRotatedAt?.timeIntervalSince1970, stamp.timeIntervalSince1970)
  }

  func testAccountExportFailureDoesNotReplaceLastGoodCryptoState() throws {
    let store = freshStore()
    let alice = try PigeonAccount.generate()
    let snapshot = SessionPersistence.Snapshot(
      contacts: [],
      conversations: [:],
      ephemeralContactIDs: [],
      bluetoothChatIDs: [],
      myName: "Alice",
      account: alice,
      sessions: [:],
      pendingInitiation: [:],
      lastInitiationIn: [:],
      fallbackRotatedAt: nil)

    let healthy = SessionPersistence()
    _ = try healthy.attach(store, identitySeed: alice.exportSeed())
    XCTAssertTrue(healthy.saveCrypto(snapshot))
    let cryptoStore = store.companion(suffix: ".crypto")
    let before = try XCTUnwrap(cryptoStore.load(PersistedCrypto.self))

    let failing = SessionPersistence(
      cryptoExporter: SessionCryptoExporter(
        exportAccount: { _ in throw ExportFailure.injected },
        exportSession: { try $0.exportPickle() }))
    _ = try failing.attach(store, identitySeed: alice.exportSeed())

    XCTAssertFalse(failing.saveCrypto(snapshot))
    let after = try XCTUnwrap(cryptoStore.load(PersistedCrypto.self))
    XCTAssertEqual(after.olmAccountPickle, before.olmAccountPickle)
    XCTAssertEqual(after.olmFallbackKey, before.olmFallbackKey)
  }

  func testBulkWriteFailureRecoversOneMatchingStateGeneration() throws {
    let url = FileManager.default.temporaryDirectory
      .appendingPathComponent("pigeon-transaction-\(UUID().uuidString).store")
    let key = SymmetricKey(size: .bits256)
    var failBulkWrite = false
    let io = EncryptedStoreIO(
      write: { data, destination, options in
        if failBulkWrite, destination == url { throw ExportFailure.injected }
        try data.write(to: destination, options: options)
      },
      remove: { try FileManager.default.removeItem(at: $0) })
    let faultingStore = EncryptedStore(key: key, url: url, io: io)
    defer {
      EncryptedStore(key: key, url: url).wipe()
      EncryptedStore(key: key, url: url).companion(suffix: ".crypto").wipe()
      EncryptedStore(key: key, url: url).companion(suffix: ".transaction").wipe()
    }

    let account = try PigeonAccount.generate()
    let persistence = SessionPersistence()
    _ = try persistence.attach(faultingStore, identitySeed: account.exportSeed())
    XCTAssertTrue(
      persistence.save(
        snapshot(account: account, name: "before", rotatedAt: nil)))

    let expectedStamp = Date(timeIntervalSince1970: 1_800_000_000)
    failBulkWrite = true
    XCTAssertFalse(
      persistence.save(
        snapshot(account: account, name: "after", rotatedAt: expectedStamp)))

    failBulkWrite = false
    let recovered = try SessionPersistence().attach(
      EncryptedStore(key: key, url: url), identitySeed: account.exportSeed())
    XCTAssertEqual(recovered.myName, "after")
    XCTAssertEqual(recovered.fallbackRotatedAt, expectedStamp)
    XCTAssertNil(
      try EncryptedStore(key: key, url: url).companion(suffix: ".transaction")
        .load(PersistedStateTransaction.self))
  }

  func testCryptoWriteFailureRecoversOneMatchingStateGeneration() throws {
    let url = FileManager.default.temporaryDirectory
      .appendingPathComponent("pigeon-crypto-transaction-\(UUID().uuidString).store")
    let key = SymmetricKey(size: .bits256)
    let cryptoURL = url.deletingLastPathComponent()
      .appendingPathComponent(url.lastPathComponent + ".crypto")
    var failCryptoWrite = false
    let io = EncryptedStoreIO(
      write: { data, destination, options in
        if failCryptoWrite, destination == cryptoURL { throw ExportFailure.injected }
        try data.write(to: destination, options: options)
      },
      remove: { try FileManager.default.removeItem(at: $0) })
    let faultingStore = EncryptedStore(key: key, url: url, io: io)
    defer { wipeStoreFamily(key: key, url: url) }

    let account = try PigeonAccount.generate()
    let peer = try PigeonAccount.generate()
    let prekey = try XCTUnwrap(peer.takeOneTimePrekeyBundles().first)
    let outbound = try account.establishOutbound(
      peerBundle: prekey, firstPlaintext: Data("first".utf8))
    let inbound = try peer.establishInbound(initiation: outbound.initiation)
    let contactID = peer.identityPublicKey()
    let beforeMarker = Data("before-marker".utf8)
    let afterMarker = Data("after-marker".utf8)
    let persistence = SessionPersistence()
    _ = try persistence.attach(faultingStore, identitySeed: account.exportSeed())
    XCTAssertTrue(
      persistence.save(
        SessionPersistence.Snapshot(
          contacts: [],
          conversations: [contactID: [ChatMessage(mine: true, text: "before")]],
          ephemeralContactIDs: [],
          bluetoothChatIDs: [],
          activeConversationIDs: [contactID],
          myName: "before",
          account: account,
          sessions: [contactID: outbound.session],
          pendingInitiation: [contactID: beforeMarker],
          lastInitiationIn: [contactID: beforeMarker],
          fallbackRotatedAt: nil)))

    let advance = try outbound.session.encrypt(plaintext: Data("advance".utf8))
    XCTAssertEqual(try inbound.session.decrypt(message: advance), Data("advance".utf8))

    let expectedStamp = Date(timeIntervalSince1970: 1_800_000_001)
    failCryptoWrite = true
    XCTAssertFalse(
      persistence.save(
        SessionPersistence.Snapshot(
          contacts: [],
          conversations: [contactID: [ChatMessage(mine: true, text: "after")]],
          ephemeralContactIDs: [],
          bluetoothChatIDs: [],
          activeConversationIDs: [contactID],
          myName: "after",
          account: account,
          sessions: [contactID: outbound.session],
          pendingInitiation: [contactID: afterMarker],
          lastInitiationIn: [contactID: afterMarker],
          fallbackRotatedAt: expectedStamp)))

    failCryptoWrite = false
    let recovered = try SessionPersistence().attach(
      EncryptedStore(key: key, url: url), identitySeed: account.exportSeed())
    XCTAssertEqual(recovered.myName, "after")
    XCTAssertEqual(recovered.fallbackRotatedAt, expectedStamp)
    XCTAssertEqual(recovered.conversations[contactID]?.map(\.text), ["after"])
    XCTAssertEqual(recovered.pendingInitiation[contactID], afterMarker)
    XCTAssertEqual(recovered.lastInitiationIn[contactID], afterMarker)
    let recoveredSession = try XCTUnwrap(recovered.sessions[contactID])
    let continued = try recoveredSession.encrypt(plaintext: Data("continued".utf8))
    XCTAssertEqual(try inbound.session.decrypt(message: continued), Data("continued".utf8))
  }

  func testTransactionCleanupFailureIsRecoveredBeforeNewWrites() throws {
    let url = FileManager.default.temporaryDirectory
      .appendingPathComponent("pigeon-cleanup-transaction-\(UUID().uuidString).store")
    let key = SymmetricKey(size: .bits256)
    let transactionURL = url.deletingLastPathComponent()
      .appendingPathComponent(url.lastPathComponent + ".transaction")
    var failTransactionRemoval = false
    let io = EncryptedStoreIO(
      write: { try $0.write(to: $1, options: $2) },
      remove: {
        if failTransactionRemoval, $0 == transactionURL { throw ExportFailure.injected }
        try FileManager.default.removeItem(at: $0)
      })
    let faultingStore = EncryptedStore(key: key, url: url, io: io)
    defer { wipeStoreFamily(key: key, url: url) }

    let account = try PigeonAccount.generate()
    let persistence = SessionPersistence()
    _ = try persistence.attach(faultingStore, identitySeed: account.exportSeed())
    XCTAssertTrue(
      persistence.save(
        snapshot(account: account, name: "before", rotatedAt: nil)))

    let expectedStamp = Date(timeIntervalSince1970: 1_800_000_002)
    failTransactionRemoval = true
    XCTAssertFalse(
      persistence.save(
        snapshot(account: account, name: "after", rotatedAt: expectedStamp)))
    XCTAssertNotNil(
      try faultingStore.companion(suffix: ".transaction")
        .load(PersistedStateTransaction.self))
    XCTAssertFalse(
      persistence.saveCrypto(
        snapshot(
          account: account, name: "must not supersede journal",
          rotatedAt: Date(timeIntervalSince1970: 1_800_000_003))))

    failTransactionRemoval = false
    let recovered = try SessionPersistence().attach(
      EncryptedStore(key: key, url: url), identitySeed: account.exportSeed())
    XCTAssertEqual(recovered.myName, "after")
    XCTAssertEqual(recovered.fallbackRotatedAt, expectedStamp)
    XCTAssertNil(
      try EncryptedStore(key: key, url: url).companion(suffix: ".transaction")
        .load(PersistedStateTransaction.self))
  }

  private func snapshot(
    account: PigeonAccount, name: String, rotatedAt: Date?
  ) -> SessionPersistence.Snapshot {
    SessionPersistence.Snapshot(
      contacts: [],
      conversations: [:],
      ephemeralContactIDs: [],
      bluetoothChatIDs: [],
      myName: name,
      account: account,
      sessions: [:],
      pendingInitiation: [:],
      lastInitiationIn: [:],
      fallbackRotatedAt: rotatedAt)
  }

  private func wipeStoreFamily(key: SymmetricKey, url: URL) {
    let store = EncryptedStore(key: key, url: url)
    store.wipe()
    store.companion(suffix: ".crypto").wipe()
    store.companion(suffix: ".transaction").wipe()
  }
}
