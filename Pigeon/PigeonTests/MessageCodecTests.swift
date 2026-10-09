import XCTest

@testable import Pigeon

@MainActor
final class MessageCodecTests: XCTestCase {
  func testInboundReplySnippetIsClampedAndSingleLine() {
    let snippet = SessionManager.clampSnippet(
      "line one\nline two " + String(repeating: "x", count: 200))

    XCTAssertLessThanOrEqual(snippet.count, 80)
    XCTAssertFalse(snippet.contains("\n"))
  }

  func testScreenshotNoticesIdentifyWhoCapturedTheChat() {
    XCTAssertEqual(
      SessionManager.screenshotNotice(mine: true, contactName: "Sam"),
      "You reported a screenshot")
    XCTAssertEqual(
      SessionManager.screenshotNotice(mine: false, contactName: "Sam"),
      "Sam reported a screenshot")
  }
}
