import CryptoKit
import Foundation
import PigeonFFI
import XCTest

@testable import Pigeon

@MainActor
final class TestBus {
  private var online: [Data: FakeTransport] = [:]
  private var queue: [Data: [Data]] = [:]
  private(set) var dispositions: [TransportMessageDisposition] = []

  func connect(_ identity: Data, _ transport: FakeTransport) {
    online[identity] = transport
    let pending = queue.removeValue(forKey: identity) ?? []
    for bytes in pending { dispositions.append(transport.deliver(bytes)) }
    transport.onConnectivity?()
  }

  func disconnect(_ identity: Data) { online[identity] = nil }

  func send(from sender: Data, _ bytes: Data, to recipient: Data?) {
    if let recipient {
      if let transport = online[recipient] {
        dispositions.append(transport.deliver(bytes))
      } else if recipient != sender {
        queue[recipient, default: []].append(bytes)
      }
    } else {
      for (identity, transport) in online where identity != sender {
        dispositions.append(transport.deliver(bytes))
      }
    }
  }
}

@MainActor
final class FakeTransport: Transport {
  let identity: Data
  let bus: TestBus
  var onMessage: ((Data, String) -> TransportMessageDisposition)?
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

  func deliver(_ bytes: Data) -> TransportMessageDisposition {
    onMessage?(bytes, "test") ?? .retryAfterRestart
  }
}

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
  func testTerminatedPeerReceivesQueuedCoreMessageAfterRelaunch() throws {
    let bus = TestBus()
    let senderSeed = Curve25519.Signing.PrivateKey().rawRepresentation
    let receiverSeed = Curve25519.Signing.PrivateKey().rawRepresentation
    let senderKey = SymmetricKey(size: .bits256)
    let receiverKey = SymmetricKey(size: .bits256)
    let senderFile = "core-relaunch-sender-\(UUID().uuidString).store"
    let receiverFile = "core-relaunch-receiver-\(UUID().uuidString).store"
    defer {
      wipe(senderKey, senderFile)
      wipe(receiverKey, receiverFile)
    }
    let sender = try launch(
      seed: senderSeed, key: senderKey, file: senderFile, bus: bus)
    var receiver: SessionManager? = try launch(
      seed: receiverSeed, key: receiverKey, file: receiverFile, bus: bus)
    try exchangeCards(sender, try XCTUnwrap(receiver))
    let receiverID = try XCTUnwrap(receiver).myID
    let receiverOnSender = try XCTUnwrap(sender.contacts.first { $0.id == receiverID })

    sender.send("before termination", to: receiverOnSender)
    XCTAssertEqual(
      try XCTUnwrap(receiver).messages(
        with: try XCTUnwrap(receiver?.contacts.first { $0.id == sender.myID })
      ).last?.text,
      "before termination")

    bus.disconnect(receiverID)
    receiver = nil
    sender.send("while terminated", to: receiverOnSender)

    let relaunched = try launch(
      seed: receiverSeed, key: receiverKey, file: receiverFile, bus: bus)
    let senderOnReceiver = try XCTUnwrap(
      relaunched.contacts.first { $0.id == sender.myID })
    XCTAssertEqual(relaunched.messages(with: senderOnReceiver).last?.text, "while terminated")
    XCTAssertTrue(bus.dispositions.allSatisfy { $0 == .consumed })
  }

  private func exchangeCards(_ first: SessionManager, _ second: SessionManager) throws {
    let firstCard = try XCTUnwrap(first.myCard)
    let secondCard = try XCTUnwrap(second.myCard)
    XCTAssertTrue(
      first.addContact(
        secondCard.bundle, name: "Second", relayURLs: [],
        prekeyBundle: secondCard.prekeyBundle, verifiedInPerson: true))
    XCTAssertTrue(
      second.addContact(
        firstCard.bundle, name: "First", relayURLs: [],
        prekeyBundle: firstCard.prekeyBundle, verifiedInPerson: true))
  }

  private func launch(
    seed: Data, key: SymmetricKey, file: String, bus: TestBus
  ) throws -> SessionManager {
    let identity = try IdentityManager(store: InMemoryKeyStore(seed: seed))
    let transport = FakeTransport(identity: identity.publicKey.rawRepresentation, bus: bus)
    let manager = SessionManager(identity: identity, mesh: MeshService(transport: transport))
    try manager.attachStore(EncryptedStore(key: key, fileName: file))
    bus.connect(identity.publicKey.rawRepresentation, transport)
    return manager
  }

  private func wipe(_ key: SymmetricKey, _ file: String) {
    let store = EncryptedStore(key: key, fileName: file)
    store.wipe()
    store.companion(suffix: ".crypto").wipe()
    store.companion(suffix: ".transaction").wipe()
    store.companion(suffix: CoreCheckpointStore.companionSuffix).wipe()
  }
}
