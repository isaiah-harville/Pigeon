import XCTest

@testable import Pigeon

final class ChatInteractionTests: XCTestCase {
  func testTransportSwipeRequiresADominantHorizontalDrag() {
    XCTAssertTrue(ChatInteraction.shouldSwitchTransport(width: 72, height: -8))
    XCTAssertTrue(ChatInteraction.shouldSwitchTransport(width: -72, height: 8))
    XCTAssertFalse(ChatInteraction.shouldSwitchTransport(width: 0, height: -72))
    XCTAssertFalse(ChatInteraction.shouldSwitchTransport(width: 18, height: 0))
  }
}
