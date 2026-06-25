//
//  DeliveryStatusTests.swift
//  PigeonTests
//
//  an outbound message carries an honest Sent → Delivered status, only ever
//  claims `delivered` on the peer's end-to-end ack, and falls to a resendable
//  "Not delivered" when it couldn't be dispatched — never when it's merely
//  awaiting an ack from an offline-but-reachable peer. Covers the pure timeout
//  policy, the model's derivation/migration, the store transitions, and the
//  end-to-end happy path over the in-process bus.
//

import CryptoKit
import PigeonFFI
import XCTest

@testable import Pigeon

@MainActor
final class DeliveryStatusTests: XCTestCase {

  // MARK: - Pure timeout policy

  func testOnlyUndispatchedMessagesTimeOut() {
    let window: TimeInterval = 30
    // A still-sending message past the window has genuinely not reached a
    // transport: it may fail.
    XCTAssertTrue(DeliveryStatus.sending.timedOut(age: 31, window: window))
    XCTAssertFalse(DeliveryStatus.sending.timedOut(age: 29, window: window), "still within window")
    // A handed-off message is in store-and-forward; it must never time out, no
    // matter how long the ack takes.
    XCTAssertFalse(DeliveryStatus.sent.timedOut(age: 10_000, window: window))
    XCTAssertFalse(DeliveryStatus.delivered.timedOut(age: 10_000, window: window))
    XCTAssertFalse(DeliveryStatus.failed.timedOut(age: 10_000, window: window))
  }

  func testRetentionRetiresOnlyUnackedMessages() {
    let week: TimeInterval = 7 * 24 * 60 * 60
    // Any unacknowledged state past the retention horizon is retired from the
    // queue — the local safety valve against resending forever.
    XCTAssertTrue(DeliveryStatus.sending.expired(age: week + 1, retention: week))
    XCTAssertTrue(DeliveryStatus.sent.expired(age: week + 1, retention: week))
    XCTAssertTrue(DeliveryStatus.failed.expired(age: week + 1, retention: week))
    XCTAssertFalse(DeliveryStatus.sent.expired(age: week - 1, retention: week), "within window")
    // A proven or already-retired message never expires.
    XCTAssertFalse(DeliveryStatus.delivered.expired(age: week * 10, retention: week))
    XCTAssertFalse(DeliveryStatus.expired.expired(age: week * 10, retention: week), "terminal")
  }

  // MARK: - Model derivation & migration

  func testPendingIsDerivedFromDeliveryState() {
    XCTAssertTrue(message(.sending).pending)
    XCTAssertTrue(message(.sent).pending, "awaiting ack is still unacknowledged")
    XCTAssertTrue(message(.failed).pending, "a failed message must keep being resent")
    XCTAssertFalse(message(.delivered).pending)
    XCTAssertFalse(message(.expired).pending, "a retired message has left the resend queue")
    XCTAssertFalse(
      ChatMessage(mine: false, text: "in").pending, "received messages are never pending")
  }

  func testStatusSurvivesCodableRoundTrip() throws {
    for status in [DeliveryStatus.sending, .sent, .delivered, .failed, .expired] {
      let decoded = try roundTrip(message(status))
      XCTAssertEqual(decoded.delivery, status)
    }
  }

  func testLegacyPendingHistoryMigrates() throws {
    // Pre-status history stored a `pending` bool. An unacked one becomes `.sent`
    // (re-confirms or times out later); a settled one becomes `.delivered`.
    XCTAssertEqual(try decodeLegacy(mine: true, pending: true).delivery, .sent)
    XCTAssertEqual(try decodeLegacy(mine: true, pending: false).delivery, .delivered)
    XCTAssertNil(
      try decodeLegacy(mine: false, pending: false).delivery, "inbound carries no status")
  }

  // MARK: - Store transitions

  func testFailIfStillSendingOnlyTouchesSendingMessages() {
    let store = ConversationStore()
    let contact = Data([0x01])
    let sending = message(.sending)
    let sent = message(.sent)
    store.record(sending, for: contact, ephemeral: false)
    store.record(sent, for: contact, ephemeral: false)

    store.failIfStillSending(messageID: sending.id, contactID: contact)
    store.failIfStillSending(messageID: sent.id, contactID: contact)

    XCTAssertEqual(store.delivery(messageID: sending.id, contactID: contact), .failed)
    XCTAssertEqual(
      store.delivery(messageID: sent.id, contactID: contact), .sent, "dispatched: untouched")
  }

  func testDeliveredMessageDropsOutOfTheResendQueue() {
    let store = ConversationStore()
    let contact = Data([0x02])
    let msg = message(.sent)
    store.record(msg, for: contact, ephemeral: false)
    XCTAssertEqual(store.pending(for: contact).count, 1)

    store.setDelivery(.delivered, messageID: msg.id, contactID: contact)
    XCTAssertTrue(store.pending(for: contact).isEmpty, "an acked message is no longer resent")
  }

  // MARK: - Retention / queue expiry

  func testStaleUnackedMessagesExpireOutOfTheQueue() {
    let store = ConversationStore()
    let contact = Data([0x03])
    let week: TimeInterval = 7 * 24 * 60 * 60
    var old = message(.sent)
    old.date = Date().addingTimeInterval(-(week + 60))
    let fresh = message(.sent)
    store.record(old, for: contact, ephemeral: false)
    store.record(fresh, for: contact, ephemeral: false)

    XCTAssertTrue(store.expireStale(retention: week, now: Date()))

    XCTAssertEqual(store.delivery(messageID: old.id, contactID: contact), .expired)
    XCTAssertEqual(store.delivery(messageID: fresh.id, contactID: contact), .sent, "still fresh")
    XCTAssertEqual(
      store.pending(for: contact).map(\.id), [fresh.id], "the expired one left the queue")
  }

  func testDeliveredMessagesNeverExpire() {
    let store = ConversationStore()
    let contact = Data([0x04])
    var acked = message(.delivered)
    acked.date = Date().addingTimeInterval(-30 * 24 * 60 * 60)
    store.record(acked, for: contact, ephemeral: false)

    XCTAssertFalse(store.expireStale(retention: 7 * 24 * 60 * 60, now: Date()), "nothing to retire")
    XCTAssertEqual(store.delivery(messageID: acked.id, contactID: contact), .delivered)
  }

  func testExpiredMessageRevivesForResend() {
    let store = ConversationStore()
    let contact = Data([0x05])
    let week: TimeInterval = 7 * 24 * 60 * 60
    var old = message(.sent)
    old.date = Date().addingTimeInterval(-(week + 60))
    store.record(old, for: contact, ephemeral: false)
    _ = store.expireStale(retention: week, now: Date())
    XCTAssertTrue(store.pending(for: contact).isEmpty, "retired before resend")

    let revived = store.reviveExpired(contactID: contact)

    XCTAssertEqual(revived, [old.id])
    XCTAssertEqual(store.delivery(messageID: old.id, contactID: contact), .sending)
    XCTAssertEqual(store.pending(for: contact).count, 1, "revived back into the queue")
  }

  // MARK: - End-to-end happy path

  /// A message sent over a live session is acknowledged end-to-end, so it must
  /// land on `.delivered` — the only status we ever claim from proof.
  func testSentMessageBecomesDeliveredOnAck() throws {
    let bus = TestBus()
    let keyA = SymmetricKey(size: .bits256)
    let keyB = SymmetricKey(size: .bits256)
    for file in ["dsA.store", "dsB.store"] {
      EncryptedStore(key: keyA, fileName: file).wipe()
      EncryptedStore(key: keyA, fileName: file).companion(suffix: ".crypto").wipe()
    }

    let a = try launch(seed: newSeed(), key: keyA, storeFile: "dsA.store", bus: bus)
    let b = try launch(seed: newSeed(), key: keyB, storeFile: "dsB.store", bus: bus)

    let aIsInitiator = a.isInitiator(toward: b.myID)
    let initiator = aIsInitiator ? a : b
    let responder = aIsInitiator ? b : a
    let (iBundle, iPrekey) = try card(initiator)
    let (rBundle, rPrekey) = try card(responder)
    responder.addContact(
      iBundle, name: "I", relayURLs: [], prekeyBundle: iPrekey, verifiedInPerson: true)
    initiator.addContact(
      rBundle, name: "R", relayURLs: [], prekeyBundle: rPrekey, verifiedInPerson: true)
    let peer = try XCTUnwrap(initiator.contacts.first { $0.id == responder.myID })

    initiator.send("hello", to: peer)

    let mine = try XCTUnwrap(initiator.messages(with: peer).last { $0.mine && !$0.system })
    XCTAssertEqual(mine.delivery, .delivered, "the responder's ack proves delivery")
  }

  // MARK: - Helpers

  private func message(_ status: DeliveryStatus) -> ChatMessage {
    ChatMessage(mine: true, text: "m", delivery: status, system: false)
  }

  private func roundTrip(_ message: ChatMessage) throws -> ChatMessage {
    try JSONDecoder().decode(ChatMessage.self, from: JSONEncoder().encode(message))
  }

  /// Decodes a message from the pre-status on-disk shape (a `pending` bool, no
  /// `delivery` key) to exercise the migration path.
  private func decodeLegacy(mine: Bool, pending: Bool) throws -> ChatMessage {
    let json = """
      {"id":"\(UUID().uuidString)","mine":\(mine),"text":"x","pending":\(pending)}
      """
    return try JSONDecoder().decode(ChatMessage.self, from: Data(json.utf8))
  }

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
}
