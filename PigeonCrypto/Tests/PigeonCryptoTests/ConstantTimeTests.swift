//
//  ConstantTimeTests.swift
//  PigeonCryptoTests
//

import Foundation
import XCTest

@testable import PigeonCrypto

final class ConstantTimeTests: XCTestCase {

  func testEqualBuffersMatch() {
    let lhs = Data([0x01, 0x02, 0x03, 0x04])
    let rhs = Data([0x01, 0x02, 0x03, 0x04])
    XCTAssertTrue(ConstantTime.equals(lhs, rhs))
  }

  func testSingleBitDifferenceFails() {
    let original = Data(repeating: 0xAA, count: 32)
    var flipped = original
    flipped[16] ^= 0x01  // flip one bit deep in the buffer
    XCTAssertFalse(ConstantTime.equals(original, flipped))
  }

  func testFirstAndLastByteDifferencesFail() {
    let original = Data(repeating: 0x00, count: 8)
    var first = original
    first[0] = 0x01
    var last = original
    last[7] = 0x01
    XCTAssertFalse(ConstantTime.equals(original, first))
    XCTAssertFalse(ConstantTime.equals(original, last))
  }

  func testDifferentLengthsFail() {
    XCTAssertFalse(ConstantTime.equals(Data([0x01, 0x02]), Data([0x01, 0x02, 0x03])))
    XCTAssertFalse(ConstantTime.equals(Data(), Data([0x00])))
  }

  func testEmptyBuffersMatch() {
    XCTAssertTrue(ConstantTime.equals(Data(), Data()))
  }
}
