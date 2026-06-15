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
    let secretKey = key()
    let plaintext = Data("conversation history".utf8)
    let box = try SecretBox.seal(plaintext, key: secretKey)
    XCTAssertEqual(try SecretBox.open(box, key: secretKey), plaintext)
    XCTAssertNotEqual(box, plaintext)
  }

  func testWrongKeyFails() throws {
    let box = try SecretBox.seal(Data("secret".utf8), key: key())
    XCTAssertThrowsError(try SecretBox.open(box, key: key())) { error in
      XCTAssertEqual(error as? SecretBoxError, .openFailed)
    }
  }

  func testTamperFails() throws {
    let secretKey = key()
    var box = try SecretBox.seal(Data("secret".utf8), key: secretKey)
    box[box.index(before: box.endIndex)] ^= 0xFF
    XCTAssertThrowsError(try SecretBox.open(box, key: secretKey)) { error in
      XCTAssertEqual(error as? SecretBoxError, .openFailed)
    }
  }

  func testNoncesDifferPerSeal() throws {
    let secretKey = key()
    let plaintext = Data("same".utf8)
    let firstBox = try SecretBox.seal(plaintext, key: secretKey)
    let secondBox = try SecretBox.seal(plaintext, key: secretKey)
    XCTAssertNotEqual(firstBox, secondBox)  // random nonce => distinct ciphertext
  }

  func testEmptyPlaintext() throws {
    let secretKey = key()
    let box = try SecretBox.seal(Data(), key: secretKey)
    XCTAssertEqual(try SecretBox.open(box, key: secretKey), Data())
  }
}
