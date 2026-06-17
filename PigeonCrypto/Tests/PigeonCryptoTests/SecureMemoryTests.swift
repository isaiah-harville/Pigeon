//
//  SecureMemoryTests.swift
//  PigeonCryptoTests
//

import Foundation
import XCTest

@testable import PigeonCrypto

final class SecureMemoryTests: XCTestCase {

  func testZeroData() {
    var data = Data([0x01, 0x02, 0x03, 0x04, 0x05])
    SecureMemory.zero(&data)
    XCTAssertEqual(data, Data(repeating: 0, count: 5))  // wiped in place, length kept
  }

  func testZeroByteArray() {
    var bytes: [UInt8] = [9, 8, 7, 6, 5, 4]
    SecureMemory.zero(&bytes)
    XCTAssertEqual(bytes, [UInt8](repeating: 0, count: 6))
  }

  func testZeroEmptyIsNoOp() {
    var empty = Data()
    SecureMemory.zero(&empty)  // must not crash
    XCTAssertEqual(empty, Data())
  }
}
