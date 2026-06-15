//
//  SecureSessionTests.swift
//  PigeonCryptoTests
//
//  End-to-end: handshake + ratchet through the public SecureSession API.
//

import XCTest
import Foundation
import CryptoKit
@testable import PigeonCrypto

final class SecureSessionTests: XCTestCase {

    /// Establishes a session pair by pumping the XX handshake to completion.
    private func establish() throws -> (alice: SecureSession, bob: SecureSession,
                                        aliceStatic: DHKeyPair, bobStatic: DHKeyPair) {
        let aliceStatic = DHKeyPair(), bobStatic = DHKeyPair()
        let alice = SecureSession.initiator(localStatic: aliceStatic)
        let bob = SecureSession.responder(localStatic: bobStatic)

        let m1 = try alice.writeHandshakeMessage()
        try bob.readHandshakeMessage(m1)
        let m2 = try bob.writeHandshakeMessage()
        try alice.readHandshakeMessage(m2)
        let m3 = try alice.writeHandshakeMessage()
        try bob.readHandshakeMessage(m3)

        return (alice, bob, aliceStatic, bobStatic)
    }

    private func msg(_ s: String) -> Data { Data(s.utf8) }

    func testEstablishesAndVerifiesPeerIdentity() throws {
        let (alice, bob, aliceStatic, bobStatic) = try establish()
        XCTAssertTrue(alice.isEstablished)
        XCTAssertTrue(bob.isEstablished)
        // Each side can confirm the peer's static key matches the QR identity.
        XCTAssertEqual(alice.remoteStaticKey, bobStatic.publicKey.rawRepresentation)
        XCTAssertEqual(bob.remoteStaticKey, aliceStatic.publicKey.rawRepresentation)
    }

    func testBidirectionalMessaging() throws {
        let (alice, bob, _, _) = try establish()

        let a1 = try alice.encrypt(msg("meet at the docks"))
        XCTAssertEqual(try bob.decrypt(a1), msg("meet at the docks"))

        let b1 = try bob.encrypt(msg("understood"))
        XCTAssertEqual(try alice.decrypt(b1), msg("understood"))

        // Multiple rounds, exercising DH ratchet steps through the public API.
        for i in 0..<5 {
            let a = try alice.encrypt(msg("a\(i)"))
            XCTAssertEqual(try bob.decrypt(a), msg("a\(i)"))
            let b = try bob.encrypt(msg("b\(i)"))
            XCTAssertEqual(try alice.decrypt(b), msg("b\(i)"))
        }
    }

    func testOutOfOrderDeliveryThroughSession() throws {
        let (alice, bob, _, _) = try establish()
        let w0 = try alice.encrypt(msg("0"))
        let w1 = try alice.encrypt(msg("1"))
        let w2 = try alice.encrypt(msg("2"))
        XCTAssertEqual(try bob.decrypt(w2), msg("2"))
        XCTAssertEqual(try bob.decrypt(w0), msg("0"))
        XCTAssertEqual(try bob.decrypt(w1), msg("1"))
    }

    func testEncryptBeforeEstablishedThrows() throws {
        let alice = SecureSession.initiator(localStatic: DHKeyPair())
        XCTAssertThrowsError(try alice.encrypt(msg("too soon"))) {
            XCTAssertEqual($0 as? SessionError, .notEstablished)
        }
    }

    func testMalformedWireRejected() throws {
        let (_, bob, _, _) = try establish()
        XCTAssertThrowsError(try bob.decrypt(Data([0x00, 0x01, 0x02]))) {
            XCTAssertEqual($0 as? SessionError, .malformedMessage)
        }
    }

    func testTwoSessionsAreIndependent() throws {
        let (alice, _, _, _) = try establish()
        let ct = try alice.encrypt(msg("hello"))
        // A different session's responder must not be able to read it.
        let (_, otherBob, _, _) = try establish()
        XCTAssertThrowsError(try otherBob.decrypt(ct))
    }
}
