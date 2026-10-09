import XCTest

@testable import Pigeon

@MainActor
final class GroupAcknowledgementTests: XCTestCase {
  func testReceiptIntervalHasAFloorAndGrowsWithGroupSize() {
    XCTAssertEqual(SessionManager.groupAcknowledgementInterval(memberCount: 3), .seconds(2))
    XCTAssertEqual(SessionManager.groupAcknowledgementInterval(memberCount: 8), .seconds(4))
    XCTAssertEqual(
      SessionManager.groupAcknowledgementInterval(memberCount: SessionManager.maximumGroupMembers),
      .seconds(64))
  }
}
