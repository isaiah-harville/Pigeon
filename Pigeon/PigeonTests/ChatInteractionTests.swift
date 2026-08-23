import XCTest

@testable import Pigeon

final class ChatInteractionTests: XCTestCase {
  func testTransportSwipeRequiresADominantHorizontalDrag() {
    XCTAssertTrue(ChatInteraction.shouldSwitchTransport(width: 72, height: -8))
    XCTAssertTrue(ChatInteraction.shouldSwitchTransport(width: -72, height: 8))
    XCTAssertFalse(ChatInteraction.shouldSwitchTransport(width: 0, height: -72))
    XCTAssertFalse(ChatInteraction.shouldSwitchTransport(width: 18, height: 0))
  }

  func testPendingMessageRequestCannotConfigureChat() {
    XCTAssertTrue(ChatInteraction.canConfigureChat(requestState: .none))
    XCTAssertFalse(ChatInteraction.canConfigureChat(requestState: .incoming))
    XCTAssertFalse(ChatInteraction.canConfigureChat(requestState: .outgoing))
  }
}
