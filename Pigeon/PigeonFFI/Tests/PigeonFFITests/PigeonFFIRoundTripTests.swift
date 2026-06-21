//
//  PigeonFFIRoundTripTests.swift
//  PigeonFFITests
//
//  Proves the Rust pigeon-core crate is reachable through the UniFFI/XCFramework
//  bridge end-to-end from Swift. This is the Swift counterpart of pigeon-core's
//  `tests/pairwise.rs` (and the Rust-side FFI tests); it asserts observable
//  behaviour across the FFI seam — async first contact, the identity binding,
//  out-of-order traffic, replay rejection, and account persistence.
//

import Foundation
import SwiftProtobuf
import XCTest

@testable import PigeonFFI

final class PigeonFFIRoundTripTests: XCTestCase {

  /// Alice opens a session to Bob from a one-time prekey bundle and sends a
  /// first message; Bob establishes the matching inbound session and recovers
  /// it. Returns both accounts and the two sessions (after one reply each way).
  private func convergedPair() throws -> (
    alice: PigeonAccount, bob: PigeonAccount,
    aliceSession: PigeonSession, bobSession: PigeonSession
  ) {
    let alice = try PigeonAccount.generate()
    let bob = try PigeonAccount.generate()

    let bundle = try XCTUnwrap(bob.takeOneTimePrekeyBundles().first)
    let outbound = try alice.establishOutbound(
      peerBundle: bundle, firstPlaintext: Data("hello bob".utf8))

    let inbound = try bob.establishInbound(initiation: outbound.initiation)
    XCTAssertEqual(inbound.plaintext, Data("hello bob".utf8))

    // A reply settles the ratchet so both ends are fully converged.
    let reply = try inbound.session.encrypt(plaintext: Data("hi alice".utf8))
    XCTAssertEqual(try outbound.session.decrypt(message: reply), Data("hi alice".utf8))

    return (alice, bob, outbound.session, inbound.session)
  }

  func testFirstContactRecoversPlaintextAndVerifiedPeer() throws {
    let pair = try convergedPair()
    // Each session records the peer's verified Ed25519 identity for the
    // safety-number check — the channel is authenticated to that identity.
    XCTAssertEqual(pair.aliceSession.remoteIdentityKey(), pair.bob.identityPublicKey())
    XCTAssertEqual(pair.bobSession.remoteIdentityKey(), pair.alice.identityPublicKey())
  }

  func testFallbackPrekeyPathWorksWithoutOneTimeKeys() throws {
    let alice = try PigeonAccount.generate()
    let bob = try PigeonAccount.generate()

    let outbound = try alice.establishOutbound(
      peerBundle: bob.signedPrekeyBundle(), firstPlaintext: Data("async hi".utf8))
    let inbound = try bob.establishInbound(initiation: outbound.initiation)
    XCTAssertEqual(inbound.plaintext, Data("async hi".utf8))
  }

  func testOutOfOrderTrafficDecrypts() throws {
    let pair = try convergedPair()
    let plaintexts = ["m0", "m1", "m2", "m3", "m4"].map { Data($0.utf8) }
    let messages = try plaintexts.map { try pair.bobSession.encrypt(plaintext: $0) }

    for i in [2, 0, 4, 1, 3] {
      XCTAssertEqual(try pair.aliceSession.decrypt(message: messages[i]), plaintexts[i])
    }
  }

  func testReplayingACiphertextFails() throws {
    let pair = try convergedPair()
    let message = try pair.bobSession.encrypt(plaintext: Data("only once".utf8))
    XCTAssertEqual(try pair.aliceSession.decrypt(message: message), Data("only once".utf8))
    XCTAssertThrowsError(try pair.aliceSession.decrypt(message: message))
  }

  func testParseVerifiesAndRejectsTamperedBundles() throws {
    let account = try PigeonAccount.generate()

    let identity = try parseIdentityBundle(encoded: account.identityBundle())
    XCTAssertEqual(identity.identityKey, account.identityPublicKey())

    var tampered = try Pigeon_Wire_V1_IdentityBundle(serializedBytes: account.identityBundle())
    tampered.bindingSignature[0] ^= 0x01
    XCTAssertThrowsError(try parseIdentityBundle(encoded: try tampered.serializedData())) { error in
      XCTAssertEqual(error as? PigeonError, .InvalidSignature)
    }
  }

  func testAccountPersistenceRoundTrip() throws {
    let bob = try PigeonAccount.generate()
    let identityBefore = bob.identityPublicKey()

    let reloaded = try PigeonAccount.import(
      seed: bob.exportSeed(),
      olmPickle: bob.exportOlmPickle(),
      fallbackKey: bob.exportFallbackKey())
    XCTAssertEqual(reloaded.identityPublicKey(), identityBefore)
  }
}
