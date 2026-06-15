//
//  IdentityBundleTests.swift
//  PigeonCryptoTests
//

import CryptoKit
import Foundation
import XCTest

@testable import PigeonCrypto

final class IdentityBundleTests: XCTestCase {

  /// Builds a valid bundle: a static key signed by an identity key.
  private func makeBundle() throws -> (
    bundle: IdentityBundle,
    identity: Curve25519.Signing.PrivateKey,
    staticKey: DHKeyPair
  ) {
    let identity = Curve25519.Signing.PrivateKey()
    let staticKey = DHKeyPair()
    let staticPub = staticKey.publicKey.rawRepresentation
    let signature = try identity.signature(for: staticPub)
    let bundle = IdentityBundle(
      identityKey: identity.publicKey.rawRepresentation,
      staticKey: staticPub,
      signature: signature)
    return (bundle, identity, staticKey)
  }

  func testValidBundleVerifies() throws {
    XCTAssertTrue(try makeBundle().bundle.isValid())
  }

  func testTamperedStaticKeyFailsVerification() throws {
    let (bundle, _, _) = try makeBundle()
    var badStatic = bundle.staticKey
    badStatic[badStatic.startIndex] ^= 0xFF
    let forged = IdentityBundle(
      identityKey: bundle.identityKey,
      staticKey: badStatic,
      signature: bundle.signature)
    XCTAssertFalse(forged.isValid())
  }

  func testWrongIdentityKeyFailsVerification() throws {
    let (bundle, _, _) = try makeBundle()
    let otherIdentity = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation
    let forged = IdentityBundle(
      identityKey: otherIdentity,
      staticKey: bundle.staticKey,
      signature: bundle.signature)
    XCTAssertFalse(forged.isValid())
  }

  func testCorruptSignatureFailsVerification() throws {
    let (bundle, _, _) = try makeBundle()
    var badSig = bundle.signature
    badSig[badSig.startIndex] ^= 0xFF
    let forged = IdentityBundle(
      identityKey: bundle.identityKey,
      staticKey: bundle.staticKey,
      signature: badSig)
    XCTAssertFalse(forged.isValid())
  }

  func testEncodingRoundTrip() throws {
    let (bundle, _, _) = try makeBundle()
    let decoded = try IdentityBundle(decoding: bundle.encoded())
    XCTAssertEqual(decoded, bundle)
    XCTAssertEqual(bundle.encoded().count, IdentityBundle.size)
    XCTAssertTrue(decoded.isValid())
  }

  func testDecodeRejectsWrongLength() {
    XCTAssertThrowsError(try IdentityBundle(decoding: Data(repeating: 0, count: 100))) { error in
      XCTAssertEqual(error as? IdentityError, .malformedBundle)
    }
  }
}
