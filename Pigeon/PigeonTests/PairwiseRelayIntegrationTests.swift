import CryptoKit
import Foundation
import PigeonFFI
import XCTest

@testable import Pigeon

@MainActor
final class PairwiseRelayIntegrationTests: XCTestCase {
  func testRelayFramesDeliverRequestAcceptanceAndOrdinaryMessage() throws {
    let bus = TestBus()
    let senderKey = SymmetricKey(size: .bits256)
    let recipientKey = SymmetricKey(size: .bits256)
    let senderFile = "relay-integration-sender-\(UUID().uuidString).store"
    let recipientFile = "relay-integration-recipient-\(UUID().uuidString).store"
    defer {
      wipe(senderKey, file: senderFile)
      wipe(recipientKey, file: recipientFile)
    }
    let (sender, senderTransport) = try launch(key: senderKey, file: senderFile, bus: bus)
    let (recipient, recipientTransport) = try launch(
      key: recipientKey, file: recipientFile, bus: bus)
    let relayURL = try XCTUnwrap(URL(string: "wss://relay.example/ws"))
    sender.relayURLs = [relayURL]
    recipient.relayURLs = [relayURL]
    sender.setMyName("Sender")
    recipient.setMyName("Recipient")

    let recipientCard = try XCTUnwrap(recipient.myCard)
    XCTAssertTrue(
      sender.addContact(
        recipientCard.bundle, name: recipientCard.name, relayURLs: recipientCard.relayURLs,
        prekeys: ContactPrekeyBundles(
          chat: recipientCard.prekeyBundle,
          control: recipientCard.pairwiseControlPrekeyBundle),
        admission: .outgoingRequest))
    let recipientOnSender = try XCTUnwrap(sender.contacts.first { $0.id == recipient.myID })

    sender.send("First contact", to: recipientOnSender)
    try deliverPending(from: sender, to: recipient, over: recipientTransport)

    let senderOnRecipient = try XCTUnwrap(recipient.contacts.first { $0.id == sender.myID })
    XCTAssertEqual(recipient.incomingMessageRequests.map(\.id), [sender.myID])
    XCTAssertEqual(recipient.messages(with: senderOnRecipient).last?.text, "First contact")

    try deliverPending(from: recipient, to: sender, over: senderTransport)
    let introduction = try XCTUnwrap(sender.messages(with: recipientOnSender).last)
    XCTAssertEqual(introduction.delivery, .delivered)

    recipient.acceptMessageRequest(from: senderOnRecipient)
    try deliverPending(from: recipient, to: sender, over: senderTransport)
    try deliverPending(from: sender, to: recipient, over: recipientTransport)
    XCTAssertEqual(
      sender.contacts.first { $0.id == recipient.myID }?.requestState,
      ContactRequestState.none)

    sender.send("After acceptance", to: recipientOnSender)
    try deliverPending(from: sender, to: recipient, over: recipientTransport)
    try deliverPending(from: recipient, to: sender, over: senderTransport)

    XCTAssertEqual(
      recipient.messages(with: senderOnRecipient).last { !$0.system }?.text,
      "After acceptance")
    XCTAssertEqual(
      sender.messages(with: recipientOnSender).last { $0.text == "After acceptance" }?.delivery,
      .delivered)
    XCTAssertTrue(bus.dispositions.isEmpty, "the local test bus stays disconnected")
  }

  func testContactRemovedAndReAddedReopensTheChat() throws {
    let bus = TestBus()
    let aliceKey = SymmetricKey(size: .bits256)
    let bobKey = SymmetricKey(size: .bits256)
    let aliceFile = "relay-re-add-alice-\(UUID().uuidString).store"
    let bobFile = "relay-re-add-bob-\(UUID().uuidString).store"
    defer {
      wipe(aliceKey, file: aliceFile)
      wipe(bobKey, file: bobFile)
    }
    let (alice, aliceTransport) = try launch(key: aliceKey, file: aliceFile, bus: bus)
    let (bob, bobTransport) = try launch(key: bobKey, file: bobFile, bus: bus)
    alice.setMyName("Alice")
    bob.setMyName("Bob")
    let bobOnAlice = try addInPerson(bob, to: alice)
    let aliceOnBob = try addInPerson(alice, to: bob)
    alice.send("Before", to: bobOnAlice)
    try deliverPending(from: alice, to: bob, over: bobTransport)
    bob.send("Reply", to: aliceOnBob)
    try deliverPending(from: bob, to: alice, over: aliceTransport)

    // Alice forgets Bob while Bob keeps his confirmed session with her.
    alice.removeContact(bobOnAlice)
    let bobAgain = try addInPerson(bob, to: alice)
    alice.send("Back again", to: bobAgain)
    try deliverPending(from: alice, to: bob, over: bobTransport)
    XCTAssertEqual(bob.messages(with: aliceOnBob).last { !$0.system }?.text, "Back again")

    bob.send("Welcome back", to: aliceOnBob)
    try deliverPending(from: bob, to: alice, over: aliceTransport)
    XCTAssertEqual(
      alice.messages(with: bobAgain).last { !$0.system }?.text, "Welcome back")
  }

  private func addInPerson(_ peer: SessionManager, to manager: SessionManager) throws -> Contact {
    let card = try XCTUnwrap(peer.myCard)
    XCTAssertTrue(
      manager.addContact(
        card.bundle, name: card.name, relayURLs: card.relayURLs,
        prekeys: ContactPrekeyBundles(
          chat: card.prekeyBundle, control: card.pairwiseControlPrekeyBundle),
        admission: .verifiedInPerson))
    return try XCTUnwrap(manager.contacts.first { $0.id == peer.myID })
  }

  private func launch(key: SymmetricKey, file: String, bus: TestBus) throws
    -> (SessionManager, FakeTransport)
  {
    let seed = Curve25519.Signing.PrivateKey().rawRepresentation
    let identity = try IdentityManager(store: InMemoryKeyStore(seed: seed))
    let transport = FakeTransport(identity: identity.publicKey.rawRepresentation, bus: bus)
    let manager = SessionManager(identity: identity, mesh: MeshService(transport: transport))
    try manager.attachStore(EncryptedStore(key: key, fileName: file))
    return (manager, transport)
  }

  private func deliverPending(
    from sender: SessionManager, to recipient: SessionManager, over transport: FakeTransport
  ) throws {
    let snapshot = try XCTUnwrap(sender.coreClient).stateSnapshot()
    let items = snapshot.pendingOutbound.filter {
      $0.kind == .pairwise && $0.destination == recipient.myID
    }
    XCTAssertFalse(items.isEmpty)
    for item in items {
      let frame = try PairwiseRelayProtocol.publish(
        sender: sender.myID, recipient: recipient.myID, payload: item.payload)
      let object = try XCTUnwrap(
        JSONSerialization.jsonObject(with: frame) as? [String: String])
      XCTAssertEqual(object["recipient"], recipient.myID.hexEncoded)
      let encoded = try XCTUnwrap(object["ciphertext"])
      let ciphertext = try XCTUnwrap(Data(base64Encoded: encoded))
      XCTAssertEqual(try MeshPacket(decoding: ciphertext).ttl, 1)
      XCTAssertEqual(transport.deliver(ciphertext), .consumed)
      XCTAssertTrue(sender.acknowledgeCoreOutbound(item.id))
    }
  }

  private func wipe(_ key: SymmetricKey, file: String) {
    let store = EncryptedStore(key: key, fileName: file)
    store.wipe()
    store.companion(suffix: ".crypto").wipe()
    store.companion(suffix: ".transaction").wipe()
    store.companion(suffix: CoreCheckpointStore.companionSuffix).wipe()
  }
}
