//
//  X3DHTests.swift
//  PigeonCryptoTests
//
//  Asynchronous first contact: prekey bundle authenticity, the X3DH agreement,
//  and the replay/exhaustion behavior of one-time prekeys.
//

import CryptoKit
import Foundation
import XCTest

@testable import PigeonCrypto

final class X3DHTests: XCTestCase {

  /// A party's long-term material: identity signing key + Noise static key,
  /// plus the matching public identity bundle.
  private struct Party {
    let signing: Curve25519.Signing.PrivateKey
    let staticKey: DHKeyPair
    let identity: IdentityBundle
  }

  private func makeParty() throws -> Party {
    let signing = Curve25519.Signing.PrivateKey()
    let staticKey = DHKeyPair()
    let staticPublic = staticKey.publicKey.rawRepresentation
    let sig = try signing.signature(for: staticPublic)
    let identity = IdentityBundle(
      identityKey: signing.publicKey.rawRepresentation,
      staticKey: staticPublic,
      signature: Data(sig))
    return Party(signing: signing, staticKey: staticKey, identity: identity)
  }

  /// Bob's published bundle plus the private prekeys he must retain to respond.
  private func makeBundle(
    for bob: Party, withOneTime: Bool
  ) throws -> (bundle: X3DHPrekeyBundle, spk: DHKeyPair, otk: DHKeyPair?) {
    let spk = DHKeyPair()
    let otk = withOneTime ? DHKeyPair() : nil
    let bundle = try X3DHPrekeyBundle.create(
      identitySigningKey: bob.signing,
      staticKey: bob.staticKey,
      signedPrekeyID: 7,
      signedPrekey: spk,
      oneTimePrekeyID: withOneTime ? 42 : nil,
      oneTimePrekey: otk)
    return (bundle, spk, otk)
  }

  private func msg(_ s: String) -> Data { Data(s.utf8) }

  // MARK: - End to end

  func testAsyncFirstContactWithOneTimePrekey() throws {
    let alice = try makeParty()
    let bob = try makeParty()
    let (bundle, spk, otk) = try makeBundle(for: bob, withOneTime: true)

    // Alice (Bob offline): derive session and encrypt the first message.
    let initiation = try X3DH.initiate(
      localStatic: alice.staticKey, localIdentity: alice.identity, bundle: bundle)
    let wireHeader = initiation.header.encoded()
    let firstCiphertext = try initiation.session.encrypt(msg("hello bob"))

    // Bob comes online, parses the header, looks up his private prekeys, responds.
    let header = try X3DHInitiation(decoding: wireHeader)
    XCTAssertEqual(header.signedPrekeyID, 7)
    XCTAssertEqual(header.oneTimePrekeyID, 42)
    let bobSession = try X3DH.respond(
      localStatic: bob.staticKey, signedPrekey: spk, oneTimePrekey: otk, header: header)

    let decoded = try bobSession.decrypt(roundTrip(firstCiphertext))
    XCTAssertEqual(decoded, msg("hello bob"))

    // Bob's identity (from the header) matches the real Alice for safety-number UX.
    XCTAssertEqual(header.initiatorIdentity, alice.identity)

    // The ratchet now runs normally in both directions.
    let reply = try bobSession.encrypt(msg("hi alice"))
    XCTAssertEqual(try initiation.session.decrypt(roundTrip(reply)), msg("hi alice"))
    let second = try initiation.session.encrypt(msg("how are you"))
    XCTAssertEqual(try bobSession.decrypt(roundTrip(second)), msg("how are you"))
  }

  func testAsyncFirstContactWithoutOneTimePrekey() throws {
    let alice = try makeParty()
    let bob = try makeParty()
    let (bundle, spk, _) = try makeBundle(for: bob, withOneTime: false)

    let initiation = try X3DH.initiate(
      localStatic: alice.staticKey, localIdentity: alice.identity, bundle: bundle)
    XCTAssertNil(initiation.header.oneTimePrekeyID)
    let first = try initiation.session.encrypt(msg("no otk path"))

    let header = try X3DHInitiation(decoding: initiation.header.encoded())
    let bobSession = try X3DH.respond(
      localStatic: bob.staticKey, signedPrekey: spk, oneTimePrekey: nil, header: header)
    XCTAssertEqual(try bobSession.decrypt(roundTrip(first)), msg("no otk path"))
  }

  // MARK: - Bundle authenticity

  func testValidBundleRoundTrips() throws {
    let bob = try makeParty()
    let (bundle, _, _) = try makeBundle(for: bob, withOneTime: true)
    XCTAssertTrue(bundle.isValid())
    let decoded = try X3DHPrekeyBundle(decoding: bundle.encoded())
    XCTAssertEqual(decoded, bundle)
    XCTAssertTrue(decoded.isValid())

    let (noOTK, _, _) = try makeBundle(for: bob, withOneTime: false)
    XCTAssertEqual(try X3DHPrekeyBundle(decoding: noOTK.encoded()), noOTK)
  }

  func testTamperedSignedPrekeyRejected() throws {
    let bob = try makeParty()
    let (bundle, _, _) = try makeBundle(for: bob, withOneTime: true)
    // Swap in a different signed prekey the signature does not cover.
    let forged = X3DHPrekeyBundle(
      identity: bundle.identity,
      signedPrekeyID: bundle.signedPrekeyID,
      signedPrekey: DHKeyPair().publicKey.rawRepresentation,
      signedPrekeySignature: bundle.signedPrekeySignature,
      oneTimePrekeyID: bundle.oneTimePrekeyID,
      oneTimePrekey: bundle.oneTimePrekey,
      oneTimePrekeySignature: bundle.oneTimePrekeySignature)
    XCTAssertFalse(forged.isValid())

    let alice = try makeParty()
    XCTAssertThrowsError(
      try X3DH.initiate(
        localStatic: alice.staticKey, localIdentity: alice.identity, bundle: forged))
  }

  func testTamperedOneTimePrekeyRejected() throws {
    let bob = try makeParty()
    let (bundle, _, _) = try makeBundle(for: bob, withOneTime: true)
    let forged = X3DHPrekeyBundle(
      identity: bundle.identity,
      signedPrekeyID: bundle.signedPrekeyID,
      signedPrekey: bundle.signedPrekey,
      signedPrekeySignature: bundle.signedPrekeySignature,
      oneTimePrekeyID: bundle.oneTimePrekeyID,
      oneTimePrekey: DHKeyPair().publicKey.rawRepresentation,
      oneTimePrekeySignature: bundle.oneTimePrekeySignature)
    XCTAssertFalse(forged.isValid())
  }

  func testBundleSignedByWrongIdentityRejected() throws {
    let bob = try makeParty()
    let attacker = try makeParty()
    // Attacker signs a prekey but advertises Bob's identity key.
    let spk = DHKeyPair()
    let spkPublic = spk.publicKey.rawRepresentation
    let spkSig = try attacker.signing.signature(
      for: X3DHPrekeyBundle.prekeyMessage(id: 1, key: spkPublic))
    let forged = X3DHPrekeyBundle(
      identity: bob.identity,
      signedPrekeyID: 1,
      signedPrekey: spkPublic,
      signedPrekeySignature: Data(spkSig))
    XCTAssertFalse(forged.isValid())
  }

  // MARK: - Replay & exhaustion

  func testReplayAfterOneTimePrekeyConsumedIsRejected() throws {
    let alice = try makeParty()
    let bob = try makeParty()
    let (bundle, spk, otk) = try makeBundle(for: bob, withOneTime: true)

    let initiation = try X3DH.initiate(
      localStatic: alice.staticKey, localIdentity: alice.identity, bundle: bundle)
    let header = try X3DHInitiation(decoding: initiation.header.encoded())

    // First delivery succeeds and Bob deletes the one-time prekey.
    _ = try X3DH.respond(
      localStatic: bob.staticKey, signedPrekey: spk, oneTimePrekey: otk, header: header)

    // A replay of the same header now finds the one-time prekey gone: Bob can no
    // longer supply it, so the agreement is refused rather than silently
    // re-derived. This is the X3DH replay defense.
    XCTAssertThrowsError(
      try X3DH.respond(
        localStatic: bob.staticKey, signedPrekey: spk, oneTimePrekey: nil, header: header)
    ) { error in
      XCTAssertEqual(error as? X3DHError, .prekeyMismatch)
    }
  }

  func testOneTimePrekeyPresenceMustMatchHeader() throws {
    let alice = try makeParty()
    let bob = try makeParty()
    let (bundle, spk, _) = try makeBundle(for: bob, withOneTime: false)

    let initiation = try X3DH.initiate(
      localStatic: alice.staticKey, localIdentity: alice.identity, bundle: bundle)
    let header = try X3DHInitiation(decoding: initiation.header.encoded())

    // Header used no one-time prekey, but the responder offers one: refused.
    XCTAssertThrowsError(
      try X3DH.respond(
        localStatic: bob.staticKey, signedPrekey: spk, oneTimePrekey: DHKeyPair(), header: header)
    ) { error in
      XCTAssertEqual(error as? X3DHError, .prekeyMismatch)
    }
  }

  func testWrongSignedPrekeyFailsToDecrypt() throws {
    let alice = try makeParty()
    let bob = try makeParty()
    let (bundle, _, otk) = try makeBundle(for: bob, withOneTime: true)

    let initiation = try X3DH.initiate(
      localStatic: alice.staticKey, localIdentity: alice.identity, bundle: bundle)
    let first = try initiation.session.encrypt(msg("secret"))
    let header = try X3DHInitiation(decoding: initiation.header.encoded())

    // Bob uses the wrong signed-prekey private half -> different shared secret.
    let bobSession = try X3DH.respond(
      localStatic: bob.staticKey, signedPrekey: DHKeyPair(), oneTimePrekey: otk, header: header)
    XCTAssertThrowsError(try bobSession.decrypt(roundTrip(first)))
  }

  // MARK: - Malformed input

  func testMalformedBundleAndInitiationThrow() throws {
    XCTAssertThrowsError(try X3DHPrekeyBundle(decoding: Data([0x00, 0x01])))
    XCTAssertThrowsError(try X3DHInitiation(decoding: Data()))
    let bob = try makeParty()
    let (bundle, _, _) = try makeBundle(for: bob, withOneTime: true)
    // Trailing garbage is rejected.
    XCTAssertThrowsError(try X3DHPrekeyBundle(decoding: bundle.encoded() + Data([0xFF])))
  }

  // MARK: - Helpers

  /// Serializes a ratchet message to wire bytes and back, exercising the same
  /// encoding the transport uses between the two ends.
  private func roundTrip(_ message: RatchetMessage) throws -> RatchetMessage {
    let wire = message.header.encoded() + message.ciphertext
    let header = try RatchetHeader(decoding: wire.prefix(40))
    return RatchetMessage(header: header, ciphertext: Data(wire.dropFirst(40)))
  }
}
