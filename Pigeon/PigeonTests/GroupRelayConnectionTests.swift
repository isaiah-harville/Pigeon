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
