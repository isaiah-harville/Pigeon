//
//  ContactCardTests.swift
//  PigeonTests
//
//  The QR card wire format: round-trips, a minimal (no-relay) card, and the
//  security-critical rule that advertised relay URLs are honoured only when
//  signed by the card's own identity key.
//

import CryptoKit
import PigeonCore
import XCTest

@testable import Pigeon

@MainActor
final class ContactCardTests: XCTestCase {

  /// A fresh identity plus its valid, signed identity bundle. Built from a real
  /// `PigeonAccount`, which also exercises the byte-stability invariant the relay
  /// signature relies on: the Ed25519 seed reproduces the same public key in
  /// CryptoKit here and in `ed25519-dalek` inside pigeon-core, so `idKey` signs
  /// what the card later verifies against `bundle.identityKey`.
  private func makeIdentity() throws -> (
    idKey: Curve25519.Signing.PrivateKey, bundle: PigeonIdentityBundle
  ) {
    let account = try PigeonAccount.generate()
    let idKey = try Curve25519.Signing.PrivateKey(rawRepresentation: account.exportSeed())
    let bundle = try PigeonIdentityBundle(decoding: account.identityBundle())
    XCTAssertEqual(idKey.publicKey.rawRepresentation, bundle.identityKey)
    return (idKey, bundle)
  }

  func testMinimalCardRoundTrip() throws {
    let (_, bundle) = try makeIdentity()
    let card = ContactCard(
      name: "Alice", bundle: bundle, relayURLs: [], relaySignature: Data(), prekeyBundle: nil)
    let decoded = ContactCard(scanned: card.encoded())
    XCTAssertEqual(decoded?.name, "Alice")
    XCTAssertEqual(decoded?.bundle, bundle)
    XCTAssertEqual(decoded?.relayURLs, [])
  }

  func testSignedRelayURLsAreHonoured() throws {
    let (idKey, bundle) = try makeIdentity()
    let urls = [URL(string: "wss://a.example/ws")!, URL(string: "wss://b.example/ws")!]
    let signature = try idKey.signature(for: ContactCard.relayPayload(urls))
    let card = ContactCard(
      name: "Bob", bundle: bundle, relayURLs: urls, relaySignature: signature, prekeyBundle: nil)

    let decoded = ContactCard(scanned: card.encoded())
    XCTAssertEqual(decoded?.name, "Bob")
    XCTAssertEqual(decoded?.relayURLs, urls)
  }

  func testUnsignedRelayURLsAreDropped() throws {
    // Built with an empty relay signature: a scanner must not honour the URLs.
    let (_, bundle) = try makeIdentity()
    let urls = [URL(string: "wss://a.example/ws")!]
    let card = ContactCard(
      name: "Bob", bundle: bundle, relayURLs: urls, relaySignature: Data(), prekeyBundle: nil)

    let decoded = ContactCard(scanned: card.encoded())
    XCTAssertEqual(decoded?.relayURLs, [])
  }

  func testRelayURLsSignedByAnotherIdentityAreDropped() throws {
    let (_, bundle) = try makeIdentity()
    let (attackerKey, _) = try makeIdentity()
    let urls = [URL(string: "wss://evil.example/ws")!]
    // Signed by a *different* identity than the card's bundle — must be rejected.
    let forged = try attackerKey.signature(for: ContactCard.relayPayload(urls))
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
