//
//  SessionEnvelopeTests.swift
//  PigeonMeshTests
//

import Foundation
import XCTest

@testable import PigeonMesh

final class SessionEnvelopeTests: XCTestCase {

  private func id(_ byte: UInt8) -> Data { Data(repeating: byte, count: SessionEnvelope.idSize) }

  func testRoundTripHandshake() throws {
    let env = SessionEnvelope(
      type: .handshake, sender: id(0xA1), recipient: id(0xB2),
      payload: Data("e,ee,s,es".utf8))
    let decoded = try SessionEnvelope(decoding: env.encoded())
    XCTAssertEqual(decoded, env)
    XCTAssertEqual(decoded.type, .handshake)
  }

  func testRoundTripMessage() throws {
    let env = SessionEnvelope(
      type: .message, sender: id(0x11), recipient: id(0x22),
      payload: Data("ciphertext".utf8))
    let decoded = try SessionEnvelope(decoding: env.encoded())
    XCTAssertEqual(decoded.sender, id(0x11))
    XCTAssertEqual(decoded.recipient, id(0x22))
    XCTAssertEqual(decoded.payload, Data("ciphertext".utf8))
  }

  func testEmptyPayloadIsValid() throws {
    let env = SessionEnvelope(type: .handshake, sender: id(1), recipient: id(2), payload: Data())
    let decoded = try SessionEnvelope(decoding: env.encoded())
    XCTAssertEqual(decoded.payload, Data())
    XCTAssertEqual(env.encoded().count, SessionEnvelope.headerSize)
  }

  func testDecodeRejectsShort() {
    XCTAssertThrowsError(try SessionEnvelope(decoding: Data(repeating: 1, count: 10))) { error in
      XCTAssertEqual(error as? EnvelopeError, .malformedEnvelope)
    }
  }

  func testDecodeRejectsBadVersion() {
    var bytes = SessionEnvelope(type: .message, sender: id(1), recipient: id(2), payload: Data())
      .encoded()
    bytes[bytes.startIndex] = 0x09
    XCTAssertThrowsError(try SessionEnvelope(decoding: bytes)) { error in
      XCTAssertEqual(error as? EnvelopeError, .malformedEnvelope)
    }
  }

  func testDecodeRejectsBadType() {
    var bytes = SessionEnvelope(type: .message, sender: id(1), recipient: id(2), payload: Data())
      .encoded()
    bytes[bytes.startIndex + 1] = 0x07  // not a valid EnvelopeType
    XCTAssertThrowsError(try SessionEnvelope(decoding: bytes)) { error in
      XCTAssertEqual(error as? EnvelopeError, .malformedEnvelope)
    }
  }
}
