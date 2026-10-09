import CryptoKit
import PigeonFFI
import XCTest

@testable import Pigeon

@MainActor
final class PairwiseAdmissionProjectionTests: XCTestCase {
  func testCoreSnapshotReconcilesPairwiseRequestAdmission() throws {
    let identity = try IdentityManager(
      store: InMemoryKeyStore(seed: Data(repeating: 23, count: 32)))
    let manager = SessionManager(
      identity: identity,
      mesh: MeshService(transport: PairwiseAdmissionNoopTransport()))
    let bundle = try makeCorePeer(seedByte: 24).bundle
    manager.contacts = [Contact(bundle: bundle, displayName: "Peer")]

    manager.applyCoreSnapshot(
      snapshot(
        generation: 1, identity: bundle.identityKey,
        relationship: .outgoingRequest, introductionSent: true))

    XCTAssertEqual(manager.contacts[0].requestState, ContactRequestState.outgoing)
    XCTAssertTrue(manager.contacts[0].introductionSent)

    manager.applyCoreSnapshot(
      snapshot(
        generation: 2, identity: bundle.identityKey,
        relationship: .contact, introductionSent: false))

    XCTAssertEqual(manager.contacts[0].requestState, ContactRequestState.none)
    XCTAssertFalse(manager.contacts[0].introductionSent)
  }

  private func snapshot(
    generation: UInt64, identity: Data,
    relationship: PigeonPairwiseRelationship, introductionSent: Bool
  ) -> PigeonCoreSnapshot {
    PigeonCoreSnapshot(
      checkpointGeneration: generation,
      groups: [],
      pairwiseContacts: [
        PigeonPairwiseContactState(
          identity: identity, relationship: relationship,
          introductionReceived: false, introductionSent: introductionSent)
      ])
  }
}

@MainActor
private final class PairwiseAdmissionNoopTransport: Transport {
  let kind: TransportKind? = .relay
  var status: TransportStatus = .idle
  var connectedPeerCount = 0
  var log: [String] = []
  var onMessage: ((Data, String) -> TransportMessageDisposition)?
  var onConnectivity: (() -> Void)?

  func broadcast(_: Data, to _: Data?) {}
}
