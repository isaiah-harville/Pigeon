//
//  DiagnosticEventTests.swift
//  PigeonTests
//

import XCTest

@testable import Pigeon

final class DiagnosticEventTests: XCTestCase {

  func testEveryDiagnosticMessageIsFixedAndIdentifierFree() {
    for event in DiagnosticEvent.allCases {
      let message = event.message
      XCTAssertFalse(message.contains("://"))
      XCTAssertFalse(message.contains("@"))
      XCTAssertFalse(message.contains("\""))
      XCTAssertFalse(message.localizedCaseInsensitiveContains("ciphertext"))
      XCTAssertFalse(message.localizedCaseInsensitiveContains("plaintext"))
    }
  }
}
