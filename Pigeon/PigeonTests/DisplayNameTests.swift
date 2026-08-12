//
//  DisplayNameTests.swift
//  PigeonTests
//
//  Hygiene for names that arrive in an attacker-controlled contact card.
//

import XCTest

@testable import Pigeon

final class DisplayNameTests: XCTestCase {

  func testKeepsAnOrdinaryName() {
    XCTAssertEqual(DisplayName.sanitize("Ada Lovelace"), "Ada Lovelace")
  }

  func testTrimsAndCollapsesWhitespace() {
    XCTAssertEqual(DisplayName.sanitize("  Ada   Lovelace  "), "Ada Lovelace")
  }

  func testStripsLineBreaksSoOneNameStaysOneLine() {
    XCTAssertEqual(DisplayName.sanitize("Ada\nLovelace\r\nMk II"), "Ada Lovelace Mk II")
  }

  /// A right-to-left override can make one identity render as another; it must
  /// never survive into a list row or a notification.
  func testStripsBidirectionalOverrides() {
    let spoofed = "Ada\u{202E}ecilA"
    let sanitized = DisplayName.sanitize(spoofed)
    XCTAssertEqual(sanitized, "AdaecilA")
    XCTAssertFalse(sanitized.unicodeScalars.contains { $0.properties.generalCategory == .format })
  }

  func testClampsLength() {
    let long = String(repeating: "a", count: DisplayName.maxLength * 3)
    XCTAssertEqual(DisplayName.sanitize(long).count, DisplayName.maxLength)
  }

  func testNothingLegibleYieldsEmpty() {
    XCTAssertTrue(DisplayName.sanitize("\u{200B}\u{202E}\n \t").isEmpty)
  }
}
