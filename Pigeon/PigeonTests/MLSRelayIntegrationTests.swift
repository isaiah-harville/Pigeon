import CryptoKit
import Foundation
import PigeonFFI
import XCTest

@testable import Pigeon

@MainActor
final class MLSRelayIntegrationTests: XCTestCase {
  private final class ScopedStoreFactory: IdentityKeyStoreFactory {
    private var stores: [String: InMemoryKeyStore] = [:]

    func makeStore(account: String) -> any KeyStore {
      if let store = stores[account] { return store }
      let store = InMemoryKeyStore(seed: nil)
      stores[account] = store
      return store
    }
  }

  func testRelayFramesDeliverEncryptedMLSMessageAfterGroupJoin() throws {
    let owner = try launch(seed: 71)
    let bob = try launch(seed: 72)
    let carol = try launch(seed: 73)
    defer {
      wipe(owner.store)
      wipe(bob.store)
      wipe(carol.store)
    }
    let relayURL = try XCTUnwrap(URL(string: "wss://relay.example/ws"))
    let coordinator = Curve25519.Signing.PrivateKey()
    for peer in [bob.manager, carol.manager] {
      try addContact(peer, to: owner.manager, relayURL: relayURL)
      try addContact(owner.manager, to: peer, relayURL: relayURL)
    }

    let created = try owner.manager.executeCore(
      PigeonCoreCommand(
        id: "create-mls-relay-group",
        body: .createGroup(
          PigeonCreateGroup(
            name: "Birds", memberIdentities: [bob.manager.myID, carol.manager.myID],
            relayURL: relayURL.absoluteString, meshEnabled: false,
            coordinatorPublicKey: coordinator.publicKey.rawRepresentation))))
    XCTAssertEqual(created.outbound.filter { $0.kind == .pairwise }.count, 2)
    for peer in [bob.manager, carol.manager] {
      let request = try XCTUnwrap(
        created.outbound.first {
          $0.kind == .pairwise && $0.destination == peer.myID
        })
      try peer.executeCore(
        PigeonCoreCommand(
          id: "join-request-\(peer.myID.hexEncoded)",
          body: .applyInbound(
            PigeonApplyInbound(
              kind: .pairwise, payload: request.payload,
              requestID: "join-request-\(peer.myID.hexEncoded)"))))
      let material = try XCTUnwrap(
        try peer.coreClient?.stateSnapshot().pendingOutbound.first {
          $0.kind == .pairwise && $0.destination == owner.manager.myID
        })
      XCTAssertEqual(
        owner.manager.consumePairwiseMessage(
          material.payload, requestID: "join-material-\(peer.myID.hexEncoded)"), .consumed)
    }

    let ownerSnapshot = try XCTUnwrap(owner.manager.coreClient).stateSnapshot()
    let submissionItem = try XCTUnwrap(
      ownerSnapshot.pendingOutbound.first {
        $0.kind == .groupCoordinator
      })
    guard case .coordinatorSubmission(let submission) = try submissionItem.relayAction() else {
      return XCTFail("Expected coordinator submission")
    }
    let receipt = try signedReceipt(for: submission, key: coordinator)
    XCTAssertTrue(
      owner.manager.consumeCoordinatorCandidate(
        receipt, candidate: submission.candidate, requestID: "initial-coordinator"))

    let welcomed = try XCTUnwrap(owner.manager.coreClient).stateSnapshot()
    for peer in [bob.manager, carol.manager] {
      let welcome = try XCTUnwrap(
        welcomed.pendingOutbound.first {
          $0.kind == .pairwise && $0.destination == peer.myID
            && $0.id
              != created.outbound.first {
                $0.kind == .pairwise && $0.destination == peer.myID
              }?.id
        })
      XCTAssertEqual(
        peer.consumePairwiseMessage(
          welcome.payload, requestID: "welcome-\(peer.myID.hexEncoded)"), .consumed)
      XCTAssertTrue(
        peer.consumeCoordinatorCandidate(
          receipt, candidate: submission.candidate,
          requestID: "initial-coordinator-\(peer.myID.hexEncoded)"))
    }

    let group = try XCTUnwrap(owner.manager.groups.first)
    let sent = try owner.manager.sendGroupMessage(
      "Hello over MLS relay", in: group, replyToMessageID: nil)
    let encrypted = try XCTUnwrap(sent.outbound.first { $0.kind == .groupMessage })
    guard case .append(let append) = try encrypted.relayAction() else {
      return XCTFail("Expected relay append")
    }
    let frame = try GroupRelayProtocol.action(.append(append))
    let object = try XCTUnwrap(JSONSerialization.jsonObject(with: frame) as? [String: String])
    XCTAssertEqual(object["type"], "append")
    let ciphertext = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(object["ciphertext"])))
    XCTAssertEqual(ciphertext, append.ciphertext)
    XCTAssertNil(ciphertext.range(of: Data("Hello over MLS relay".utf8)))

    XCTAssertEqual(
      bob.manager.consumeGroupRelayMessage(ciphertext, requestID: "relay-group-1"), .accepted)
    let received = try XCTUnwrap(
      bob.manager.groupConversations[group.groupID]?.messages.last {
        if case .message = $0.content { return true }
        return false
      })
    XCTAssertEqual(received.content, .message("Hello over MLS relay", replyToMessageID: nil))
    XCTAssertEqual(received.senderIdentity, owner.manager.myID)
    XCTAssertEqual(
      bob.manager.consumeGroupRelayMessage(ciphertext, requestID: "relay-group-1"), .accepted)
    XCTAssertEqual(
      bob.manager.groupConversations[group.groupID]?.messages.filter {
        if case .message = $0.content { return true }
        return false
      }.count, 1)
  }

  private func launch(seed: UInt8) throws -> (manager: SessionManager, store: EncryptedStore) {
    let identity = try IdentityManager(
      store: InMemoryKeyStore(seed: Data(repeating: seed, count: 32)))
    let manager = SessionManager(
      identity: identity,
      mesh: MeshService(
        transport: FakeTransport(
          identity: identity.publicKey.rawRepresentation, bus: TestBus())))
    let scopedStores = ScopedStoreFactory()
    manager.makeCoreIdentityProvider = {
      CoreIdentityProvider(rootIdentity: $0, storeFactory: scopedStores)
    }
    let file = "mls-relay-integration-\(UUID().uuidString).store"
    let store = EncryptedStore(key: SymmetricKey(size: .bits256), fileName: file)
    try manager.attachStore(store)
    return (manager, store)
  }

  private func addContact(_ peer: SessionManager, to manager: SessionManager, relayURL: URL)
    throws
  {
    let card = try XCTUnwrap(peer.myCard)
    XCTAssertTrue(
      manager.addContact(
        card.bundle, name: card.name, relayURLs: [relayURL],
        prekeys: ContactPrekeyBundles(
          chat: card.prekeyBundle, control: card.pairwiseControlPrekeyBundle),
        admission: .verifiedInPerson))
  }

  private func signedReceipt(
    for submission: PigeonGroupCoordinatorSubmission, key: Curve25519.Signing.PrivateKey
  ) throws -> PigeonCoordinatorReceipt {
    let entryHash = Data(SHA256.hash(data: submission.candidate))
    var transcript = Data("pigeon.relay.coordinator.receipt.v1".utf8)
    transcript.append(submission.coordinationID)
    var sequence = UInt64(1).bigEndian
    withUnsafeBytes(of: &sequence) { transcript.append(contentsOf: $0) }
    transcript.append(Data(repeating: 0, count: 32))
    var epoch = submission.claimedBaseEpoch.bigEndian
    withUnsafeBytes(of: &epoch) { transcript.append(contentsOf: $0) }
    transcript.append(entryHash)
    return PigeonCoordinatorReceipt(
      coordinationID: submission.coordinationID, sequence: 1,
      priorReceiptHash: Data(repeating: 0, count: 32),
      claimedBaseEpoch: submission.claimedBaseEpoch, entryHash: entryHash,
      signature: try key.signature(for: transcript))
  }

  private func wipe(_ store: EncryptedStore) {
    store.wipe()
    store.companion(suffix: ".crypto").wipe()
    store.companion(suffix: ".transaction").wipe()
    store.companion(suffix: CoreCheckpointStore.companionSuffix).wipe()
  }
}
