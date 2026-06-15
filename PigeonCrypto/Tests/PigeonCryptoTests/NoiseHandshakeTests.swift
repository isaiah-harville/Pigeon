//
//  NoiseHandshakeTests.swift
//  PigeonCryptoTests
//
//  Exercises the Noise_XX handshake end to end between two parties.
//

import XCTest
import Foundation
import CryptoKit
@testable import PigeonCrypto

final class NoiseHandshakeTests: XCTestCase {

    /// Runs the full XX handshake and returns both completed results.
    private func runHandshake(initiatorStatic: DHKeyPair, responderStatic: DHKeyPair,
                              msg1: Data = Data(), msg2: Data = Data(), msg3: Data = Data())
        throws -> (NoiseHandshakeResult, NoiseHandshakeResult, payloads: [Data]) {
        let initiator = NoiseHandshakeState(initiator: true, staticKey: initiatorStatic)
        let responder = NoiseHandshakeState(initiator: false, staticKey: responderStatic)

        var received: [Data] = []
        let m1 = try initiator.writeMessage(payload: msg1)
        received.append(try responder.readMessage(m1))
        let m2 = try responder.writeMessage(payload: msg2)
        received.append(try initiator.readMessage(m2))
        let m3 = try initiator.writeMessage(payload: msg3)
        received.append(try responder.readMessage(m3))

        return (try initiator.finish(), try responder.finish(), received)
    }

    func testHandshakeCompletesAndAgreesOnKeys() throws {
        let iStatic = DHKeyPair(), rStatic = DHKeyPair()
        let (iRes, rRes, _) = try runHandshake(initiatorStatic: iStatic, responderStatic: rStatic)

        // Same transcript hash on both ends.
        XCTAssertEqual(iRes.handshakeHash, rRes.handshakeHash)

        // Each side learned the other's true static public key (mutual auth).
        XCTAssertEqual(iRes.remoteStaticKey, rStatic.publicKey.rawRepresentation)
        XCTAssertEqual(rRes.remoteStaticKey, iStatic.publicKey.rawRepresentation)
    }

    func testTransportMessagesBothDirections() throws {
        let (iRes, rRes, _) = try runHandshake(initiatorStatic: DHKeyPair(), responderStatic: DHKeyPair())

        // Initiator -> Responder
        let c1 = try iRes.send.encrypt(plaintext: Data("ping".utf8), ad: Data())
        XCTAssertEqual(try rRes.receive.decrypt(ciphertext: c1, ad: Data()), Data("ping".utf8))

        // Responder -> Initiator
        let c2 = try rRes.send.encrypt(plaintext: Data("pong".utf8), ad: Data())
        XCTAssertEqual(try iRes.receive.decrypt(ciphertext: c2, ad: Data()), Data("pong".utf8))

        // Counter advances: a second message uses a fresh nonce.
        let c3 = try iRes.send.encrypt(plaintext: Data("ping".utf8), ad: Data())
        XCTAssertNotEqual(c1, c3)
        XCTAssertEqual(try rRes.receive.decrypt(ciphertext: c3, ad: Data()), Data("ping".utf8))
    }

    func testHandshakeCarriesEncryptedPayloads() throws {
        // Message 2 and 3 payloads are encrypted; this is how the responder's
        // initial ratchet key will later be delivered.
        let secret2 = Data("responder-ratchet-key".utf8)
        let secret3 = Data("initiator-confirm".utf8)
        let (_, _, payloads) = try runHandshake(initiatorStatic: DHKeyPair(),
                                                responderStatic: DHKeyPair(),
                                                msg2: secret2, msg3: secret3)
        XCTAssertEqual(payloads[0], Data())     // msg1 payload (empty)
        XCTAssertEqual(payloads[1], secret2)    // responder -> initiator
        XCTAssertEqual(payloads[2], secret3)    // initiator -> responder
    }

    func testTamperedHandshakeMessageRejected() throws {
        let initiator = NoiseHandshakeState(initiator: true, staticKey: DHKeyPair())
        let responder = NoiseHandshakeState(initiator: false, staticKey: DHKeyPair())

        let m1 = try initiator.writeMessage()
        _ = try responder.readMessage(m1)
        var m2 = try responder.writeMessage()
        m2[m2.count - 1] ^= 0xFF // corrupt the responder's encrypted static/payload

        XCTAssertThrowsError(try initiator.readMessage(m2)) {
            XCTAssertEqual($0 as? NoiseError, .decryptionFailed)
        }
    }

    func testOutOfOrderWritesRejected() throws {
        let responder = NoiseHandshakeState(initiator: false, staticKey: DHKeyPair())
        // Responder must read message 1 before it may write.
        XCTAssertThrowsError(try responder.writeMessage()) {
            XCTAssertEqual($0 as? NoiseError, .notYourTurn)
        }
    }

    func testIndependentSessionsDiffer() throws {
        let (a, _, _) = try runHandshake(initiatorStatic: DHKeyPair(), responderStatic: DHKeyPair())
        let (b, _, _) = try runHandshake(initiatorStatic: DHKeyPair(), responderStatic: DHKeyPair())
        // Fresh ephemerals => different transcript hashes per session.
        XCTAssertNotEqual(a.handshakeHash, b.handshakeHash)
    }
}
