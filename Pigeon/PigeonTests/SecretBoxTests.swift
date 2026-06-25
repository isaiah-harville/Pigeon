//
//  SecretBoxTests.swift
//  PigeonTests
//
//  At-rest seal/open: round-trips, authentication (tamper detection), and the
//  wrong-key path. Ported from PigeonCrypto's suite when SecretBox moved into
//  the app during the pigeon-core cutover.
//

import CryptoKit
import XCTest

@testable import Pigeon

final class SecretBoxTests: XCTestCase {

  func testSealOpenRoundTrip() throws {
    let key = SymmetricKey(size: .bits256)
    let plaintext = Data("the on-disk store".utf8)
    let box = try SecretBox.seal(plaintext, key: key)
    XCTAssertNotEqual(box, plaintext)
    XCTAssertEqual(try SecretBox.open(box, key: key), plaintext)
  }

  func testWrongKeyFailsToOpen() throws {
    let box = try SecretBox.seal(Data("secret".utf8), key: SymmetricKey(size: .bits256))
    XCTAssertThrowsError(try SecretBox.open(box, key: SymmetricKey(size: .bits256))) { error in
      XCTAssertEqual(error as? SecretBoxError, .openFailed)
    }
  }

  func testTamperedCiphertextFailsToOpen() throws {
    let key = SymmetricKey(size: .bits256)
    var box = try SecretBox.seal(Data("secret".utf8), key: key)
    box[box.count - 1] ^= 0x01  // flip a tag bit
    XCTAssertThrowsError(try SecretBox.open(box, key: key)) { error in
      XCTAssertEqual(error as? SecretBoxError, .openFailed)
    }
  }

  func testFreshNoncePerSeal() throws {
    let key = SymmetricKey(size: .bits256)
    let plaintext = Data("same input".utf8)
    // Random nonce per seal => identical plaintext yields different ciphertext.
    XCTAssertNotEqual(
      try SecretBox.seal(plaintext, key: key),
      try SecretBox.seal(plaintext, key: key))
  }
}
