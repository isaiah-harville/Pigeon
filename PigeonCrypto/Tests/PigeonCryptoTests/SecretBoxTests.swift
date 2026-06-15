//
//  SecretBoxTests.swift
//  PigeonCryptoTests
//

import CryptoKit
import Foundation
import XCTest

@testable import PigeonCrypto

final class SecretBoxTests: XCTestCase {

  private func key() -> SymmetricKey { SymmetricKey(size: .bits256) }

  func testRoundTrip() throws {
    let k = key()
    let plaintext = Data("conversation history".utf8)
    let box = try SecretBox.seal(plaintext, key: k)
    XCTAssertEqual(try SecretBox.open(box, key: k), plaintext)
    XCTAssertNotEqual(box, plaintext)
  }

  func testWrongKeyFails() throws {
    let box = try SecretBox.seal(Data("secret".utf8), key: key())
    XCTAssertThrowsError(try SecretBox.open(box, key: key())) {
      XCTAssertEqual($0 as? SecretBoxError, .openFailed)
    }
  }

  func testTamperFails() throws {
    let k = key()
    var box = try SecretBox.seal(Data("secret".utf8), key: k)
    box[box.index(before: box.endIndex)] ^= 0xFF
    XCTAssertThrowsError(try SecretBox.open(box, key: k)) {
      XCTAssertEqual($0 as? SecretBoxError, .openFailed)
    }
  }

  func testNoncesDifferPerSeal() throws {
    let k = key()
    let plaintext = Data("same".utf8)
    let a = try SecretBox.seal(plaintext, key: k)
    let b = try SecretBox.seal(plaintext, key: k)
    XCTAssertNotEqual(a, b)  // random nonce => distinct ciphertext
  }

  func testEmptyPlaintext() throws {
    let k = key()
    let box = try SecretBox.seal(Data(), key: k)
    XCTAssertEqual(try SecretBox.open(box, key: k), Data())
  }
}
