//
//  DoubleRatchetTests.swift
//  PigeonCryptoTests
//
//  Two-party simulations exercising the ratchet the way the mesh will:
//  in-order, out-of-order, dropped, and interleaved messages.
//

import CryptoKit
import Foundation
import XCTest

@testable import PigeonCrypto

final class DoubleRatchetTests: XCTestCase {

  /// Builds an Alice (initiator) / Bob (responder) pair sharing a secret.
  private func makePair(
    sharedSecret: Data = Data(repeating: 0x42, count: 32),
    maxSkip: Int = 1000
  ) throws
    -> (alice: DoubleRatchetSession, bob: DoubleRatchetSession)
  {
    let bobKeys = DHKeyPair()
    let alice = try DoubleRatchetSession.initiator(
      sharedSecret: sharedSecret,
      remotePublicKey: bobKeys.publicKey,
      maxSkip: maxSkip)
    let bob = DoubleRatchetSession.responder(
      sharedSecret: sharedSecret,
      selfKeyPair: bobKeys,
      maxSkip: maxSkip)
    return (alice, bob)
  }

  private func msg(_ string: String) -> Data { Data(string.utf8) }

  func testInOrderConversation() throws {
    let (alice, bob) = try makePair()

    let a1 = try alice.encrypt(msg("hello bob"))
    XCTAssertEqual(try bob.decrypt(a1), msg("hello bob"))

    let b1 = try bob.encrypt(msg("hi alice"))
    XCTAssertEqual(try alice.decrypt(b1), msg("hi alice"))

    let a2 = try alice.encrypt(msg("how are you"))
    XCTAssertEqual(try bob.decrypt(a2), msg("how are you"))

    let b2 = try bob.encrypt(msg("good, you?"))
    XCTAssertEqual(try alice.decrypt(b2), msg("good, you?"))
  }

  func testMultipleMessagesBeforeReply() throws {
    let (alice, bob) = try makePair()
    let plaintexts = (0..<5).map { msg("burst \($0)") }
    let sent = try plaintexts.map { plaintext in try alice.encrypt(plaintext) }
    for (index, message) in sent.enumerated() {
      XCTAssertEqual(try bob.decrypt(message), plaintexts[index])
    }
  }

  func testOutOfOrderWithinChain() throws {
    let (alice, bob) = try makePair()
    let m0 = try alice.encrypt(msg("zero"))
    let m1 = try alice.encrypt(msg("one"))
    let m2 = try alice.encrypt(msg("two"))

    // Delivered reordered: 2, 0, 1 — skipped keys must cover the gaps.
    XCTAssertEqual(try bob.decrypt(m2), msg("two"))
    XCTAssertEqual(try bob.decrypt(m0), msg("zero"))
    XCTAssertEqual(try bob.decrypt(m1), msg("one"))
  }

  func testDroppedThenLateDelivery() throws {
    let (alice, bob) = try makePair()
    let m0 = try alice.encrypt(msg("first"))
    let m1 = try alice.encrypt(msg("second"))

    // m0 is "lost" in the mesh; bob receives m1 first.
    XCTAssertEqual(try bob.decrypt(m1), msg("second"))
    // m0 finally arrives and is still decryptable via the stored skipped key.
    XCTAssertEqual(try bob.decrypt(m0), msg("first"))
  }

  func testFullDuplexRatcheting() throws {
    let (alice, bob) = try makePair()
    // Several DH ratchet steps as direction alternates.
    for i in 0..<8 {
      let aliceMessage = try alice.encrypt(msg("a\(i)"))
      XCTAssertEqual(try bob.decrypt(aliceMessage), msg("a\(i)"))
      let bobMessage = try bob.encrypt(msg("b\(i)"))
      XCTAssertEqual(try alice.decrypt(bobMessage), msg("b\(i)"))
    }
  }

  func testLateMessageFromPreviousChain() throws {
    let (alice, bob) = try makePair()
    // Alice sends two in chain #1; bob only gets the first.
    let old0 = try alice.encrypt(msg("old0"))
    let old1 = try alice.encrypt(msg("old1"))
    XCTAssertEqual(try bob.decrypt(old0), msg("old0"))

    // Bob replies (triggers a DH ratchet on alice's next receive),
    // and alice sends in a new chain.
    let bReply = try bob.encrypt(msg("reply"))
    XCTAssertEqual(try alice.decrypt(bReply), msg("reply"))
    let new0 = try alice.encrypt(msg("new0"))
    XCTAssertEqual(try bob.decrypt(new0), msg("new0"))

    // The straggler from the previous chain still decrypts.
    XCTAssertEqual(try bob.decrypt(old1), msg("old1"))
  }

  func testEachMessageUsesDistinctCiphertext() throws {
    let (alice, _) = try makePair()
    let c1 = try alice.encrypt(msg("same")).ciphertext
    let c2 = try alice.encrypt(msg("same")).ciphertext
    XCTAssertNotEqual(c1, c2)  // forward secrecy: identical plaintext, different keys
  }

  func testTamperedCiphertextRejected() throws {
    let (alice, bob) = try makePair()
    var message = try alice.encrypt(msg("secret"))
    var ciphertext = message.ciphertext
    ciphertext[ciphertext.startIndex] ^= 0x01
    message = RatchetMessage(header: message.header, ciphertext: ciphertext)
    XCTAssertThrowsError(try bob.decrypt(message)) { error in
      XCTAssertEqual(error as? RatchetError, .decryptionFailed)
    }
  }

  func testTamperedHeaderRejected() throws {
    let (alice, bob) = try makePair()
    let message = try alice.encrypt(msg("secret"))
    // Forge the message number; header is authenticated as AAD.
    let forged = RatchetHeader(
      dhPublic: message.header.dhPublic,
      previousChainLength: message.header.previousChainLength,
      messageNumber: message.header.messageNumber &+ 1)
    XCTAssertThrowsError(
      try bob.decrypt(RatchetMessage(header: forged, ciphertext: message.ciphertext)))
  }

  func testTooManySkippedMessagesRejected() throws {
    let (alice, bob) = try makePair(maxSkip: 5)
    var last: RatchetMessage?
    for i in 0..<10 { last = try alice.encrypt(msg("m\(i)")) }  // gap of 9 > maxSkip
    let lastMessage = try XCTUnwrap(last)
    XCTAssertThrowsError(try bob.decrypt(lastMessage)) { error in
      XCTAssertEqual(error as? RatchetError, .tooManySkippedMessages)
    }
  }

  func testHeaderEncodingRoundTrip() throws {
    let header = RatchetHeader(
      dhPublic: Data(repeating: 0xAB, count: 32),
      previousChainLength: 7,
      messageNumber: 65_537)
    let decoded = try RatchetHeader(decoding: header.encoded())
    XCTAssertEqual(decoded, header)
    XCTAssertEqual(header.encoded().count, 40)
  }
}
