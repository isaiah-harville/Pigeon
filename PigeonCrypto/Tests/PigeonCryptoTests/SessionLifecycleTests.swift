//
//  SessionLifecycleTests.swift
//  PigeonCryptoTests
//
//  Session lifecycle the way the app drives it: re-handshake after a peer
//  restart, stray handshakes on an established session, store-and-forward retry
//  catch-up (the relay resends the same pending message until it lands), and the
//  idempotency limits of async first contact. These model the recovery paths in
//  the app's SessionManager, which has no unit tests of its own.
//

import CryptoKit
import Foundation
import XCTest

@testable import PigeonCrypto

final class SessionLifecycleTests: XCTestCase {

  private func msg(_ string: String) -> Data { Data(string.utf8) }

  /// Pumps the XX handshake between a fresh initiator/responder pair to completion.
  private func handshake(
    aliceStatic: DHKeyPair, bobStatic: DHKeyPair
  ) throws -> (alice: SecureSession, bob: SecureSession) {
    let alice = SecureSession.initiator(localStatic: aliceStatic)
    let bob = SecureSession.responder(localStatic: bobStatic)
    let m1 = try alice.writeHandshakeMessage()
    try bob.readHandshakeMessage(m1)
    let m2 = try bob.writeHandshakeMessage()
    try alice.readHandshakeMessage(m2)
    let m3 = try alice.writeHandshakeMessage()
    try bob.readHandshakeMessage(m3)
    return (alice, bob)
  }

  // MARK: - Re-handshake / restart recovery

  /// After a peer "restarts" (loses its session), the app resets and re-runs the
  /// handshake between the *same* identities. A second handshake must produce a
  /// fresh working session whose identity binding is unchanged — otherwise
  /// reconnection would silently break trust.
  func testReHandshakeAfterPeerRestartRecovers() throws {
    let aliceStatic = DHKeyPair()
    let bobStatic = DHKeyPair()

    let (alice1, bob1) = try handshake(aliceStatic: aliceStatic, bobStatic: bobStatic)
    let before = try alice1.encrypt(msg("before restart"))
    XCTAssertEqual(try bob1.decrypt(before), msg("before restart"))

    // Bob restarts and loses bob1; the app rebuilds both ends and re-handshakes.
    let (alice2, bob2) = try handshake(aliceStatic: aliceStatic, bobStatic: bobStatic)
    XCTAssertEqual(try bob2.decrypt(try alice2.encrypt(msg("after restart"))), msg("after restart"))
    XCTAssertEqual(try alice2.decrypt(try bob2.encrypt(msg("ack"))), msg("ack"))

    // The binding the app checks against the contact's QR identity is stable.
    XCTAssertEqual(alice2.remoteStaticKey, bobStatic.publicKey.rawRepresentation)
    XCTAssertEqual(bob2.remoteStaticKey, aliceStatic.publicKey.rawRepresentation)

    // The old session's keys do not leak into the new one.
    XCTAssertThrowsError(try bob2.decrypt(try alice1.encrypt(msg("stale"))))
  }

  /// A handshake message arriving on an already-established session (a delayed
  /// retransmit, or a peer that didn't realize we finished) must be rejected
  /// rather than resetting the live ratchet. This is what lets SessionManager
  /// safely ignore duplicate handshakes instead of churning the session.
  func testHandshakeOnEstablishedSessionIsRejected() throws {
    let (alice, bob) = try handshake(aliceStatic: DHKeyPair(), bobStatic: DHKeyPair())
    XCTAssertTrue(alice.isEstablished)

    XCTAssertThrowsError(try alice.writeHandshakeMessage()) { error in
      XCTAssertEqual(error as? SessionError, .alreadyEstablished)
    }
    let stray = try SecureSession.initiator(localStatic: DHKeyPair()).writeHandshakeMessage()
    XCTAssertThrowsError(try bob.readHandshakeMessage(stray)) { error in
      XCTAssertEqual(error as? SessionError, .alreadyEstablished)
    }

    // The session still works after shrugging off the stray handshake.
    XCTAssertEqual(try bob.decrypt(try alice.encrypt(msg("intact"))), msg("intact"))
  }

  // MARK: - Store-and-forward retry

  /// The relay holds a sender's pending messages and the 3s retry loop keeps
  /// (re)sending them while the peer is offline. When the peer finally drains the
  /// mailbox in order, a backlog larger than `maxSkip` must still decrypt, since
  /// each in-order message skips nothing.
  func testStoreAndForwardInOrderCatchUpBeyondMaxSkip() throws {
    let (alice, bob) = try handshake(aliceStatic: DHKeyPair(), bobStatic: DHKeyPair())

    // Alice sends a long backlog while Bob is offline (default maxSkip is 1000).
    let count = 1200
    let backlog = try (0..<count).map { try alice.encrypt(msg("queued \($0)")) }
    for (index, wire) in backlog.enumerated() {
      XCTAssertEqual(try bob.decrypt(wire), msg("queued \(index)"))
    }
  }

  /// If the relay evicts the backlog and the peer receives only a far-future
  /// message (a gap beyond `maxSkip`), decryption is refused rather than skipping
  /// unbounded keys. The app treats this failure as a cue to re-handshake, which
  /// rebuilds the chain from zero — so the message is not lost, just retried.
  func testSingleLateMessageBeyondMaxSkipIsRejected() throws {
    let (alice, bob) = try handshake(aliceStatic: DHKeyPair(), bobStatic: DHKeyPair())

    var last = Data()
    for index in 0...1001 { last = try alice.encrypt(msg("m\(index)")) }  // gap 1001 > maxSkip
    XCTAssertThrowsError(try bob.decrypt(last)) { error in
      XCTAssertEqual(error as? RatchetError, .tooManySkippedMessages)
    }
  }

  /// SessionManager re-encrypts a pending message on every retry tick (so each
  /// transmission is independently decryptable over a lossy/duplicating relay),
  /// and dedupes by message id on receipt. Any single attempt that lands must
  /// decrypt, and late-arriving earlier attempts must remain decryptable too.
  func testRetriedMessageIsIndependentlyDecryptable() throws {
    let (alice, bob) = try handshake(aliceStatic: DHKeyPair(), bobStatic: DHKeyPair())

    // Three retry attempts at the *same* logical message.
    let attempt1 = try alice.encrypt(msg("ping"))
    let attempt2 = try alice.encrypt(msg("ping"))
    let attempt3 = try alice.encrypt(msg("ping"))
    XCTAssertNotEqual(attempt1, attempt2)
    XCTAssertNotEqual(attempt2, attempt3)

    // Only the latest attempt reaches Bob first; it decrypts.
    XCTAssertEqual(try bob.decrypt(attempt3), msg("ping"))
    // The earlier attempts arrive late and still decrypt via stored skipped keys.
    XCTAssertEqual(try bob.decrypt(attempt1), msg("ping"))
    XCTAssertEqual(try bob.decrypt(attempt2), msg("ping"))
  }

  // MARK: - Async first contact (X3DH) idempotency

  private struct Party {
    let signing: Curve25519.Signing.PrivateKey
    let staticKey: DHKeyPair
    let identity: IdentityBundle
  }

  private func makeParty() throws -> Party {
    let signing = Curve25519.Signing.PrivateKey()
    let staticKey = DHKeyPair()
    let staticPublic = staticKey.publicKey.rawRepresentation
    let identity = IdentityBundle(
      identityKey: signing.publicKey.rawRepresentation,
      staticKey: staticPublic,
      signature: Data(try signing.signature(for: staticPublic)))
    return Party(signing: signing, staticKey: staticKey, identity: identity)
  }

  /// Once an X3DH session has advanced (the peer replied, stepping the ratchet),
  /// re-running `respond` on the same initiation header rebuilds a *fresh* ratchet
  /// that has lost the advanced state and can no longer decrypt later messages.
  /// This is exactly why SessionManager must ignore a duplicate initiation header
  /// (`lastX3DHIn`) rather than rebuilding the session on every retransmit.
  func testX3DHReRespondAfterAdvanceLosesState() throws {
    let alice = try makeParty()
    let bob = try makeParty()
    let spk = DHKeyPair()
    let bundle = try X3DHPrekeyBundle.create(
      identitySigningKey: bob.signing,
      staticKey: bob.staticKey,
      signedPrekeyID: 1,
      signedPrekey: spk)

    let initiation = try X3DH.initiate(
      localStatic: alice.staticKey, localIdentity: alice.identity, bundle: bundle)
    let header = try X3DHInitiation(decoding: initiation.header.encoded())
    let bobSession = try X3DH.respond(
      localStatic: bob.staticKey, signedPrekey: spk, oneTimePrekey: nil, header: header)

    // First message lands, then Bob replies — that reply steps Alice's ratchet,
    // so her next message is in a new chain only the advanced Bob session knows.
    XCTAssertEqual(try bobSession.decrypt(try initiation.session.encrypt(msg("hi"))), msg("hi"))
    XCTAssertEqual(try initiation.session.decrypt(try bobSession.encrypt(msg("hey"))), msg("hey"))
    let advanced = try initiation.session.encrypt(msg("still there?"))

    // Rebuilding from the same header (what a naive duplicate-init handler would
    // do) yields a stale session that cannot read the advanced-chain message.
    let rebuilt = try X3DH.respond(
      localStatic: bob.staticKey, signedPrekey: spk, oneTimePrekey: nil, header: header)
    XCTAssertThrowsError(try rebuilt.decrypt(advanced))

    // The genuine, advanced session still decrypts it.
    XCTAssertEqual(try bobSession.decrypt(advanced), msg("still there?"))
  }
}
