//
//  RehandshakeGateTests.swift
//  PigeonTests
//
//  re-handshakes that network input can trigger are rate-limited per
//  contact, so a spoofed/replayed `.rehandshakeRequest` flood can't force endless
//  session resets. Covers the pure gate policy and a coordinator-level burst.
//

import CryptoKit
import PigeonFFI
import XCTest

@testable import Pigeon

@MainActor
final class RehandshakeGateTests: XCTestCase {

  // MARK: - Pure policy

  private let alice = Data([0xAA])

  func testAllowsFirstRequestThenSuppressesWithinCooldown() {
    var gate = RehandshakeGate(cooldown: 30)
    let t0 = Date()
    XCTAssertTrue(gate.allow(alice, now: t0), "first request must be honored")
    XCTAssertFalse(gate.allow(alice, now: t0.addingTimeInterval(1)), "within cooldown: suppressed")
    XCTAssertFalse(gate.allow(alice, now: t0.addingTimeInterval(29.9)), "still within cooldown")
  }

  func testAllowsAgainOncePastCooldown() {
    var gate = RehandshakeGate(cooldown: 30)
    let t0 = Date()
    XCTAssertTrue(gate.allow(alice, now: t0))
    XCTAssertTrue(
      gate.allow(alice, now: t0.addingTimeInterval(30)), "past the window: honored again")
  }

  func testCooldownIsPerContact() {
    var gate = RehandshakeGate(cooldown: 30)
    let t0 = Date()
    let bob = Data([0xBB])
    XCTAssertTrue(gate.allow(alice, now: t0))
    XCTAssertTrue(gate.allow(bob, now: t0), "a different contact has its own budget")
  }

  func testClearLetsTheNextRequestThrough() {
    var gate = RehandshakeGate(cooldown: 30)
    let t0 = Date()
    XCTAssertTrue(gate.allow(alice, now: t0))
    gate.clear(alice)  // e.g. a user re-scans the QR card
    XCTAssertTrue(gate.allow(alice, now: t0.addingTimeInterval(1)), "clear supersedes the cooldown")
  }

  // MARK: - Coordinator-level spoofed flood

  /// Two devices establish; the initiator is then hit with a burst of spoofed
  /// `.rehandshakeRequest` envelopes (unauthenticated, empty payload — exactly
  /// what an attacker who can inject mesh packets can forge). It must honor at
  /// most one re-establishment for the burst, not one per packet.
  func testSpoofedRehandshakeFloodCausesAtMostOneReset() throws {
    let bus = TestBus()
    let keyA = SymmetricKey(size: .bits256)
    let keyB = SymmetricKey(size: .bits256)
    for file in ["rhgA.store", "rhgB.store"] {
      EncryptedStore(key: keyA, fileName: file).wipe()
      EncryptedStore(key: keyA, fileName: file).companion(suffix: ".crypto").wipe()
    }

    let a = try launch(seed: newSeed(), key: keyA, storeFile: "rhgA.store", bus: bus)
    let b = try launch(seed: newSeed(), key: keyB, storeFile: "rhgB.store", bus: bus)

    let aIsInitiator = a.isInitiator(toward: b.myID)
    let initiator = aIsInitiator ? a : b
    let responder = aIsInitiator ? b : a
    let (iBundle, iPrekey) = try card(initiator)
    let (rBundle, rPrekey) = try card(responder)
    responder.addContact(
      iBundle, name: "I", relayURLs: [], prekeyBundle: iPrekey, verifiedInPerson: true)
    initiator.addContact(
      rBundle, name: "R", relayURLs: [], prekeyBundle: rPrekey, verifiedInPerson: true)

    XCTAssertTrue(initiator.establishedContactIDs.contains(responder.myID))
    // The establishment ack clears the pending initiation, so the reset branch of
    // handleRehandshakeRequest is reachable (not the in-flight-resend branch).
    XCTAssertNil(initiator.pendingInitiation[responder.myID])

    // Forge a re-handshake request "from" the responder and replay it many times.
    let spoof = SessionEnvelope(
      type: .rehandshakeRequest, sender: responder.myID, recipient: initiator.myID,
      payload: Data()
    ).encoded()
    let before = reestablishCount(initiator, peer: responder.myID)
    for _ in 0..<50 { initiator.handleInbound(spoof, channel: .bluetooth) }
    let honored = reestablishCount(initiator, peer: responder.myID) - before

    XCTAssertLessThanOrEqual(
      honored, 1, "a 50-packet spoof flood must not drive more than one re-establishment")
  }

  // MARK: - Harness (TestBus/FakeTransport/InMemoryKeyStore from SessionRelaunchDeliveryTests)

  private func launch(seed: Data, key: SymmetricKey, storeFile: String, bus: TestBus) throws
    -> SessionManager
  {
    let identity = try IdentityManager(store: InMemoryKeyStore(seed: seed))
    let transport = FakeTransport(identity: identity.publicKey.rawRepresentation, bus: bus)
    let manager = SessionManager(identity: identity, mesh: MeshService(transport: transport))
    manager.attachStore(EncryptedStore(key: key, fileName: storeFile))
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

  /// How many times the initiator has logged honoring a re-establishment for a peer.
  private func reestablishCount(_ manager: SessionManager, peer: Data) -> Int {
    manager.log.filter { $0.contains("requested re-establishment") }.count
  }
}
