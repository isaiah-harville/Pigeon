//
//  SessionRelaunchDeliveryTests.swift
//  PigeonTests
//
//  Coordinator-level regression test for the relaunch-delivery bug: two real
//  SessionManagers talk over a fake store-and-forward bus, and one is terminated
//  and relaunched from its persisted store. Because Olm sessions now persist, the
//  relaunched device keeps decrypting messages deposited while it was gone — with
//  no fresh handshake — so the "responder sends to a terminated peer" direction
//  delivers instead of wedging. On the pre-fix code (sessions in memory only)
//  the relaunched device loses its session and this fails.
//

import CryptoKit
import PigeonFFI
import XCTest

@testable import Pigeon

/// A synchronous in-process bus that delivers ciphertext between devices and
/// queues for a device that's currently "terminated", flushing on reconnect —
/// the store-and-forward role the relay plays, modeled just enough to drive the
/// session layer. Keyed by identity so a relaunched device (same identity, new
/// transport) picks up what was queued for it.
@MainActor
final class TestBus {
  private var online: [Data: FakeTransport] = [:]
  private var queue: [Data: [Data]] = [:]

  func connect(_ identity: Data, _ transport: FakeTransport) {
    online[identity] = transport
    let pending = queue[identity] ?? []
    queue[identity] = []
    for bytes in pending { transport.deliver(bytes) }
    transport.onConnectivity?()
  }

  func disconnect(_ identity: Data) { online[identity] = nil }

  func send(from sender: Data, _ bytes: Data, to recipient: Data?) {
    if let recipient {
      if let transport = online[recipient] {
        transport.deliver(bytes)
      } else if recipient != sender {
        queue[recipient, default: []].append(bytes)  // store for a terminated peer
      }
    } else {
      for (identity, transport) in online where identity != sender { transport.deliver(bytes) }
    }
  }
}

/// A `Transport` that's just a port on the `TestBus`.
@MainActor
final class FakeTransport: Transport {
  let identity: Data
  let bus: TestBus
  var onMessage: ((Data, String) -> Void)?
  var onConnectivity: (() -> Void)?
  var status: TransportStatus { .idle }
  var connectedPeerCount: Int { 1 }
  var log: [String] = []

  init(identity: Data, bus: TestBus) {
    self.identity = identity
    self.bus = bus
  }

  func broadcast(_ message: Data, to recipient: Data?) {
    bus.send(from: identity, message, to: recipient)
  }

  func deliver(_ bytes: Data) { onMessage?(bytes, "test") }
}

/// In-memory identity key store so tests get a stable, controllable identity
/// (and a relaunched device keeps the same one) without touching the Keychain.
final class InMemoryKeyStore: KeyStore {
  private var data: Data?
  init(seed: Data?) { self.data = seed }
  func get() throws -> Data? { data }
  func set(_ data: Data, accessibility: KeychainAccessibility) throws { self.data = data }
  func setAccessibility(_ accessibility: KeychainAccessibility) throws {}
  func delete() throws { data = nil }
}

@MainActor
final class SessionRelaunchDeliveryTests: XCTestCase {

  /// Builds a device's SessionManager over the bus, unlocked against `storeFile`
  /// with the given key + identity seed, and connects it to the bus.
  private func launch(seed: Data, key: SymmetricKey, storeFile: String, bus: TestBus) throws
    -> SessionManager
  {
    let identity = try IdentityManager(store: InMemoryKeyStore(seed: seed))
    let transport = FakeTransport(identity: identity.publicKey.rawRepresentation, bus: bus)
    let manager = SessionManager(identity: identity, mesh: MeshService(transport: transport))
    let store = EncryptedStore(key: key, fileName: storeFile)
    manager.attachStore(store)
    bus.connect(identity.publicKey.rawRepresentation, transport)
    return manager
  }

  private func card(_ manager: SessionManager) throws -> (PigeonIdentityBundle, PigeonPrekeyBundle)
  {
    let account = try XCTUnwrap(manager.account)
    return (
      try PigeonIdentityBundle(decoding: account.identityBundle()),
      try PigeonPrekeyBundle(decoding: account.signedPrekeyBundle())
    )
  }

  private func newSeed() -> Data { Curve25519.Signing.PrivateKey().rawRepresentation }

  /// Two devices establish; the *initiator* is then terminated; the *responder*
  /// sends a message to it; the initiator relaunches and must receive it (and
  /// reply), all from its persisted session — no re-handshake.
  func testTerminatedPeerReceivesQueuedMessageAfterRelaunch() throws {
    let bus = TestBus()
    let seedA = newSeed()
    let seedB = newSeed()
    let keyA = SymmetricKey(size: .bits256)
    let keyB = SymmetricKey(size: .bits256)
    EncryptedStore(key: keyA, fileName: "itestA.store").wipe()
    EncryptedStore(key: keyA, fileName: "itestA.store").companion(suffix: ".crypto").wipe()
    EncryptedStore(key: keyB, fileName: "itestB.store").wipe()
    EncryptedStore(key: keyB, fileName: "itestB.store").companion(suffix: ".crypto").wipe()

    let a = try launch(seed: seedA, key: keyA, storeFile: "itestA.store", bus: bus)
    let b = try launch(seed: seedB, key: keyB, storeFile: "itestB.store", bus: bus)

    // Assign roles by the deterministic rule, then have the responder add the
    // initiator first so the initiator's initiation isn't dropped on arrival.
    let aIsInitiator = a.isInitiator(toward: b.myID)
    let initiator = aIsInitiator ? a : b
    let responder = aIsInitiator ? b : a
    let initiatorSeed = aIsInitiator ? seedA : seedB
    let initiatorKey = aIsInitiator ? keyA : keyB
    let initiatorStore = aIsInitiator ? "itestA.store" : "itestB.store"

    let (initiatorBundle, initiatorPrekey) = try card(initiator)
    let (responderBundle, responderPrekey) = try card(responder)
    responder.addContact(
      initiatorBundle, name: "I", relayURLs: [], prekeyBundle: initiatorPrekey,
      verifiedInPerson: true)
    initiator.addContact(
      responderBundle, name: "R", relayURLs: [], prekeyBundle: responderPrekey,
      verifiedInPerson: true)

    // Both ends established synchronously over the bus.
    XCTAssertTrue(initiator.establishedContactIDs.contains(responder.myID))
    XCTAssertTrue(responder.establishedContactIDs.contains(initiator.myID))

    // Terminate the initiator: it goes offline and its manager is discarded.
    let initiatorID = initiator.myID
    let responderID = responder.myID
    bus.disconnect(initiatorID)

    // The responder sends while the initiator is gone — the bus stores it.
    responder.send("hello while you were away", to: responderContact(responder, initiatorID))

    // Relaunch the initiator from its persisted store; the bus flushes the queue.
    let relaunched = try launch(
      seed: initiatorSeed, key: initiatorKey, storeFile: initiatorStore, bus: bus)

    // It decrypted the queued message with its *restored* session (no re-handshake).
    XCTAssertTrue(
      relaunched.establishedContactIDs.contains(responderID),
      "relaunched device should restore its session, not re-handshake")
    XCTAssertTrue(
      texts(relaunched, with: responderID).contains("hello while you were away"),
      "relaunched device must receive the message deposited while it was terminated")

    // And the responder's message is acked (no longer pending), and replies flow back.
    XCTAssertFalse(
      pendingExists(responder, with: initiatorID), "the delivered message should be acked")
    relaunched.send("got it, welcome back", to: responderContact(relaunched, responderID))
    XCTAssertTrue(texts(responder, with: initiatorID).contains("got it, welcome back"))
  }

  // MARK: - Small accessors over the manager's observable state

  private func responderContact(_ manager: SessionManager, _ id: Data) -> Contact {
    manager.contacts.first { $0.id == id }!
  }

  private func texts(_ manager: SessionManager, with id: Data) -> [String] {
    manager.conversationStore.messages(for: id).map(\.text)
  }

  private func pendingExists(_ manager: SessionManager, with id: Data) -> Bool {
    manager.conversationStore.messages(for: id).contains { $0.mine && $0.pending }
  }
}
