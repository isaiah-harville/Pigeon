import Foundation
import PigeonFFI
import XCTest

@testable import Pigeon

final class PairwiseMeshBridgeTests: XCTestCase {
  func testFanoutWrapsOnlyPairwiseEffectsForLocalContacts() {
    let sender = Data(repeating: 1, count: 32)
    let local = Data(repeating: 2, count: 32)
    let remote = Data(repeating: 3, count: 32)
    let localItem = item(id: "local", destination: local)
    let remoteItem = item(id: "remote", destination: remote, localOnly: false)
    let groupItem = PigeonCoreOutboundItem(
      id: "group", kind: .groupMessage, relayURL: "wss://relay.example",
      destination: local, payload: Data([9]))
    var sentItemIDs: Set<String> = []

    let envelopes = PairwiseMeshBridge.outboundEnvelopes(
      items: [localItem, remoteItem, groupItem], sender: sender,
      sentItemIDs: &sentItemIDs)

    XCTAssertEqual(envelopes.count, 1)
    XCTAssertEqual(envelopes[0].type, .pairwise)
    XCTAssertEqual(envelopes[0].sender, sender)
    XCTAssertEqual(envelopes[0].recipient, local)
    XCTAssertEqual(envelopes[0].payload, localItem.payload)
    XCTAssertEqual(sentItemIDs, ["local"])
  }

  func testReconciliationAllowsOnlyNewPendingEffects() {
    let recipient = Data(repeating: 2, count: 32)
    var sentItemIDs: Set<String> = ["old", "pending"]

    let envelopes = PairwiseMeshBridge.outboundEnvelopes(
      items: [item(id: "pending", destination: recipient)],
      sender: Data(repeating: 1, count: 32), sentItemIDs: &sentItemIDs)

    XCTAssertTrue(envelopes.isEmpty)
    XCTAssertEqual(sentItemIDs, ["pending"])
  }

  private func item(
    id: String, destination: Data, localOnly: Bool = true
  ) -> PigeonCoreOutboundItem {
    PigeonCoreOutboundItem(
      id: id, kind: .pairwise, relayURL: "wss://relay.example",
      destination: destination, payload: Data([7, 8]), localOnly: localOnly)
  }
}
