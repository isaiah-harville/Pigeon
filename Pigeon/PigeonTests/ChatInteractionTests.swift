import XCTest

@testable import Pigeon

final class ChatInteractionTests: XCTestCase {
  func testUpwardComposerSwipeTogglesEphemeral() {
    XCTAssertTrue(ChatInteraction.shouldToggleEphemeral(width: 8, height: -72))
  }

  func testShortHorizontalAndDownwardDragsDoNotToggleEphemeral() {
    XCTAssertFalse(ChatInteraction.shouldToggleEphemeral(width: 4, height: -40))
    XCTAssertFalse(ChatInteraction.shouldToggleEphemeral(width: 80, height: -72))
    XCTAssertFalse(ChatInteraction.shouldToggleEphemeral(width: 0, height: 72))
  }

  func testSwipeEnablesDirectlyButRequiresConfirmationToDisable() {
    XCTAssertEqual(ChatInteraction.ephemeralSwipeAction(isEphemeral: false), .enable)
    XCTAssertEqual(ChatInteraction.ephemeralSwipeAction(isEphemeral: true), .confirmDisable)
  }
}
