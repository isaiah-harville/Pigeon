import Foundation
import PigeonFFI
import XCTest

@testable import Pigeon

@MainActor
final class GroupRelayConnectionTests: XCTestCase {
  func testInitialFetchUsesDurableCoordinatorCursor() {
    let connection = GroupRelayConnection(group: group(coordinatorSequence: 7))

    connection.scheduleFetchesIfNeeded()

    XCTAssertEqual(connection.queue, [.fetchMessages, .fetchCoordinator(7)])
  }

  func testWakeSchedulesBothMessageAndCoordinatorFetches() {
    let connection = GroupRelayConnection(group: group(coordinatorSequence: 4))
    connection.fetchedAfterConnect = true
    connection.noteWake()

    connection.scheduleFetchesIfNeeded()

    XCTAssertEqual(connection.queue, [.fetchMessages, .fetchCoordinator(4)])
  }

  func testDurableCoordinatorFetchEffectCompletesUsingReceiptSequence() throws {
    let connection = GroupRelayConnection(group: group(coordinatorSequence: 12))
    let effect = GroupRelayEffect(
      id: "fetch-epochs",
      action: .coordinatorFetch(
        PigeonGroupCoordinatorFetch(
          coordinationID: connection.group.coordinationID,
          groupID: connection.group.groupID, fromEpoch: 3, throughEpoch: 9)))
    connection.awaiting = .effect(effect)
    let transport = GroupRelayTransport(signer: { _, _ in Data() })
    var delivered: [String] = []
    transport.onEffectDelivered = {
      delivered.append($0)
      return true
    }

    let data = try transport.data(for: .effect(effect), connection: connection)
    let wire = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    XCTAssertEqual(wire["after_sequence"] as? UInt64, 12)

    try transport.handle(.coordinatorCandidates([]), for: connection)
    XCTAssertNil(connection.awaiting)
    XCTAssertEqual(delivered, ["fetch-epochs"])
  }

  func testMessagePagesAdvanceAndContinueUntilEmpty() throws {
    let connection = GroupRelayConnection(group: group(coordinatorSequence: 0))
    connection.awaiting = .fetchMessages
    let transport = GroupRelayTransport(signer: { _, _ in Data() })
    transport.onMessage = { _, _ in .accepted }

    try transport.handle(
      .entries([.init(sequence: 5, ciphertext: Data([1]), timestamp: 1)]),
      for: connection)
    XCTAssertEqual(connection.queue, [.advance(5), .fetchMessages])
    connection.queue.removeFirst()
    connection.queue.removeFirst()
    connection.awaiting = .fetchMessages
    try transport.handle(.entries([]), for: connection)
    XCTAssertTrue(connection.queue.isEmpty)
  }

  func testTerminalRejectionAdvancesButTransientFailureRetries() throws {
    let first = GroupRelayConnection(group: group(coordinatorSequence: 0))
    first.awaiting = .fetchMessages
    let transport = GroupRelayTransport(signer: { _, _ in Data() })
    transport.onMessage = { _, _ in .rejected }
    try transport.handle(
      .entries([.init(sequence: 8, ciphertext: Data([0]), timestamp: 1)]),
      for: first)
    XCTAssertEqual(first.queue, [.advance(8), .fetchMessages])

    let second = GroupRelayConnection(group: group(coordinatorSequence: 0))
    second.awaiting = .fetchMessages
    transport.onMessage = { _, _ in .retry }
    XCTAssertThrowsError(
      try transport.handle(
        .entries([.init(sequence: 8, ciphertext: Data([0]), timestamp: 1)]),
        for: second))
    XCTAssertTrue(second.queue.isEmpty)
  }

  private func group(coordinatorSequence: UInt64) -> PigeonGroupState {
    PigeonGroupState(
      groupID: Data(repeating: 1, count: 32),
      ownerIdentity: Data(repeating: 2, count: 32),
      adminIdentities: [Data(repeating: 2, count: 32)],
      memberIdentities: [Data(repeating: 2, count: 32)],
      name: "Birds", relayURL: "wss://relay.example/group",
      coordinationID: Data(repeating: 3, count: 32), meshEnabled: false,
      epoch: 9, policyRevision: 9, dissolved: false,
      capabilityPublicKey: Data(repeating: 4, count: 32),
      capabilityID: Data(repeating: 5, count: 32),
      coordinatorPublicKey: Data(repeating: 6, count: 32),
      coordinatorSequence: coordinatorSequence)
  }
}
