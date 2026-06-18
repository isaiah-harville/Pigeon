//
//  ContactCardTests.swift
//  PigeonTests
//
//  The QR card wire format: round-trips, a minimal (no-relay) card, and the
//  security-critical rule that advertised relay URLs are honoured only when
//  signed by the card's own identity key.
//

import CryptoKit
import PigeonCrypto
import XCTest

@testable import Pigeon

@MainActor
final class ContactCardTests: XCTestCase {

  /// A fresh identity key plus a valid, signed identity bundle bound to it.
  private func makeIdentity() -> (idKey: Curve25519.Signing.PrivateKey, bundle: IdentityBundle) {
    let idKey = Curve25519.Signing.PrivateKey()
    let staticKey = Curve25519.KeyAgreement.PrivateKey()
    let staticPub = staticKey.publicKey.rawRepresentation
    let signature = try! idKey.signature(for: staticPub)
    let bundle = IdentityBundle(
      identityKey: idKey.publicKey.rawRepresentation, staticKey: staticPub, signature: signature)
    XCTAssertTrue(bundle.isValid())
    return (idKey, bundle)
  }

  func testMinimalCardRoundTrip() {
    let (_, bundle) = makeIdentity()
    let card = ContactCard(
      name: "Alice", bundle: bundle, relayURLs: [], relaySignature: Data(), prekeyBundle: nil)
    let decoded = ContactCard(scanned: card.encoded())
    XCTAssertEqual(decoded?.name, "Alice")
    XCTAssertEqual(decoded?.bundle, bundle)
    XCTAssertEqual(decoded?.relayURLs, [])
  }

  func testSignedRelayURLsAreHonoured() {
    let (idKey, bundle) = makeIdentity()
    let urls = [URL(string: "wss://a.example/ws")!, URL(string: "wss://b.example/ws")!]
    let signature = try! idKey.signature(for: ContactCard.relayPayload(urls))
    let card = ContactCard(
      name: "Bob", bundle: bundle, relayURLs: urls, relaySignature: signature, prekeyBundle: nil)

    let decoded = ContactCard(scanned: card.encoded())
    XCTAssertEqual(decoded?.name, "Bob")
    XCTAssertEqual(decoded?.relayURLs, urls)
  }

  func testUnsignedRelayURLsAreDropped() {
    // Built with an empty relay signature: a scanner must not honour the URLs.
    let (_, bundle) = makeIdentity()
    let urls = [URL(string: "wss://a.example/ws")!]
    let card = ContactCard(
      name: "Bob", bundle: bundle, relayURLs: urls, relaySignature: Data(), prekeyBundle: nil)

    let decoded = ContactCard(scanned: card.encoded())
    XCTAssertEqual(decoded?.relayURLs, [])
  }

  func testRelayURLsSignedByAnotherIdentityAreDropped() {
    let (_, bundle) = makeIdentity()
    let (attackerKey, _) = makeIdentity()
    let urls = [URL(string: "wss://evil.example/ws")!]
    // Signed by a *different* identity than the card's bundle — must be rejected.
    let forged = try! attackerKey.signature(for: ContactCard.relayPayload(urls))
    let card = ContactCard(
      name: "Bob", bundle: bundle, relayURLs: urls, relaySignature: forged, prekeyBundle: nil)

    let decoded = ContactCard(scanned: card.encoded())
    XCTAssertEqual(decoded?.relayURLs, [])
  }

  func testGarbageIsNotACard() {
    XCTAssertNil(ContactCard(scanned: "not base64 @@@"))
    XCTAssertNil(ContactCard(scanned: Data([1, 2, 3]).base64EncodedString()))  // too short
  }
}
