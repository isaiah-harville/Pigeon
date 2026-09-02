import Foundation
import PigeonFFI
import XCTest

@testable import Pigeon

final class GroupMeshBridgeTests: XCTestCase {
  func testFanoutWrapsOnlyMeshEnabledGroupMessages() {
    let sender = Data(repeating: 1, count: 32)
    let group = groupState(meshEnabled: true, localIdentity: sender)
    let message = PigeonCoreOutboundItem(
      id: "message-1", kind: .groupMessage, relayURL: group.relayURL,
      destination: group.coordinationID, payload: Data("ciphertext".utf8))
    let coordinator = PigeonCoreOutboundItem(
      id: "coordinator-1", kind: .groupCoordinator, relayURL: group.relayURL,
      destination: group.coordinationID, payload: Data("candidate".utf8))
    var sentItemIDs: Set<String> = []

    let envelopes = GroupMeshBridge.outboundEnvelopes(
      groups: [group], items: [message, coordinator], sender: sender,
      sentItemIDs: &sentItemIDs)

    XCTAssertEqual(envelopes.count, 1)
    XCTAssertEqual(envelopes[0].type, .groupMls)
    XCTAssertEqual(envelopes[0].sender, sender)
    XCTAssertEqual(envelopes[0].recipient, group.groupID)
    XCTAssertEqual(envelopes[0].payload, message.payload)
    XCTAssertEqual(sentItemIDs, [message.id])
  }

  func testFanoutIsOffByDefaultAndDoesNotConsumeTheRelayEffect() {
    let sender = Data(repeating: 1, count: 32)
    let group = groupState(meshEnabled: false, localIdentity: sender)
    let message = PigeonCoreOutboundItem(
      id: "message-1", kind: .groupMessage, relayURL: group.relayURL,
      destination: group.coordinationID, payload: Data("ciphertext".utf8))
    var sentItemIDs: Set<String> = []

    let envelopes = GroupMeshBridge.outboundEnvelopes(
      groups: [group], items: [message], sender: sender, sentItemIDs: &sentItemIDs)

    XCTAssertTrue(envelopes.isEmpty)
    XCTAssertTrue(sentItemIDs.isEmpty)
  }

  func testInboundRequiresAnActiveMeshEnabledLocalMembership() {
    let localIdentity = Data(repeating: 1, count: 32)
    let enabled = groupState(meshEnabled: true, localIdentity: localIdentity)
    let disabled = groupState(meshEnabled: false, localIdentity: localIdentity)
    let envelope = SessionEnvelope(
      type: .groupMls, sender: Data(repeating: 2, count: 32),
      recipient: enabled.groupID, payload: Data("ciphertext".utf8))

    XCTAssertTrue(
      GroupMeshBridge.acceptsInbound(
        envelope, groups: [enabled], localIdentity: localIdentity))
    XCTAssertFalse(
      GroupMeshBridge.acceptsInbound(
        envelope, groups: [disabled], localIdentity: localIdentity))
    XCTAssertFalse(
      GroupMeshBridge.acceptsInbound(
        envelope, groups: [enabled], localIdentity: Data(repeating: 9, count: 32)))
  }

  private func groupState(meshEnabled: Bool, localIdentity: Data) -> PigeonGroupState {
    PigeonGroupState(
      groupID: Data(repeating: 3, count: 32), ownerIdentity: localIdentity,
      adminIdentities: [localIdentity],
      memberIdentities: [
        localIdentity, Data(repeating: 2, count: 32), Data(repeating: 4, count: 32),
      ], name: "Birds", relayURL: "https://relay.example",
      coordinationID: Data(repeating: 5, count: 32), meshEnabled: meshEnabled,
      epoch: 2, policyRevision: 1, dissolved: false,
      capabilityPublicKey: Data(repeating: 6, count: 32),
      coordinatorPublicKey: Data(repeating: 7, count: 32))
  }
}
