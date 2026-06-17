//
//  RelayRoutingTests.swift
//  PigeonTests
//
//  Pure routing/decision logic of the relay client: addressed per-recipient
//  delivery, federation relay selection, the connection-set union, and
//  robustness to malformed server frames.
//

import XCTest

@testable import Pigeon

@MainActor
final class RelayRoutingTests: XCTestCase {

  private func url(_ s: String) -> URL { URL(string: s)! }

  // MARK: - Addressed delivery + federation selection

  func testDeliveryPrefersRecipientAdvertisedRelays() {
    let advertised = [url("wss://theirs.example/ws")]
    let mine = [url("wss://mine.example/ws")]
    // Federation: deposit on the recipient's relays, not ours.
    XCTAssertEqual(
      RelayTransport.deliveryTargets(advertised: advertised, myRelays: mine), advertised)
  }

  func testDeliveryFallsBackToOwnRelaysWhenRecipientAdvertisesNone() {
    let mine = [url("wss://mine.example/ws")]
    XCTAssertEqual(RelayTransport.deliveryTargets(advertised: [], myRelays: mine), mine)
  }

  func testDeliveryTargetsNothingWhenNoRelaysKnown() {
    XCTAssertTrue(RelayTransport.deliveryTargets(advertised: [], myRelays: []).isEmpty)
  }

  // MARK: - Per-conversation preferred relay (#18)

  func testPreferredRelayIsOrderedFirstWithOthersAsFallback() {
    let a = url("wss://a.example/ws")
    let b = url("wss://b.example/ws")
    let c = url("wss://c.example/ws")
    // Preferred relay leads; the rest follow in order so a dead preferred
    // falls through to them.
    XCTAssertEqual(
      RelayTransport.deliveryTargets(preferred: b, advertised: [a, b, c], myRelays: []),
      [b, a, c])
  }

  func testPreferredNotAdvertisedIsIgnored() {
    let a = url("wss://a.example/ws")
    let stray = url("wss://stray.example/ws")
    // A preference the recipient doesn't advertise can't be honored — fall back
    // to their advertised relays unchanged.
    XCTAssertEqual(
      RelayTransport.deliveryTargets(preferred: stray, advertised: [a], myRelays: []),
      [a])
  }

  func testPreferredIgnoredWhenAdvertisesNoneFallsBackToOwn() {
    let mine = [url("wss://mine.example/ws")]
    let stray = url("wss://stray.example/ws")
    XCTAssertEqual(
      RelayTransport.deliveryTargets(preferred: stray, advertised: [], myRelays: mine),
      mine)
  }

  func testNilPreferredMatchesPlainDelivery() {
    let a = url("wss://a.example/ws")
    let b = url("wss://b.example/ws")
    XCTAssertEqual(
      RelayTransport.deliveryTargets(preferred: nil, advertised: [a, b], myRelays: []),
      [a, b])
  }

  // MARK: - Connection set (reconfigure union)

  func testWantedConnectionsUnionsAndDeduplicatesPreservingOrder() {
    let mine = [url("wss://a.example/ws"), url("wss://b.example/ws")]
    let contacts = [url("wss://b.example/ws"), url("wss://c.example/ws")]
    XCTAssertEqual(
      RelayTransport.wantedConnections(myRelays: mine, contactRelays: contacts),
      [url("wss://a.example/ws"), url("wss://b.example/ws"), url("wss://c.example/ws")])
  }

  func testWantedConnectionsEmptyWhenNothingConfigured() {
    XCTAssertTrue(RelayTransport.wantedConnections(myRelays: [], contactRelays: []).isEmpty)
  }

  // MARK: - Malformed / failure-path response handling

  func testClassifyValidEnvelope() {
    let ciphertext = Data([1, 2, 3, 4])
    let frame = RelayTransport.classifyInbound([
      "type": "envelope", "id": "abc", "ciphertext": ciphertext.base64EncodedString(),
    ])
    XCTAssertEqual(frame, .envelope(.init(id: "abc", ciphertext: ciphertext)))
  }

  func testClassifyEnvelopeMissingFieldsIsIgnored() {
    XCTAssertEqual(RelayTransport.classifyInbound(["type": "envelope", "id": "abc"]), .ignored)
    XCTAssertEqual(
      RelayTransport.classifyInbound(["type": "envelope", "ciphertext": "AQID"]), .ignored)
  }

  func testClassifyEnvelopeWithNonBase64CiphertextIsIgnored() {
    let frame = RelayTransport.classifyInbound([
      "type": "envelope", "id": "abc", "ciphertext": "not base64!!",
    ])
    XCTAssertEqual(frame, .ignored)
  }

  func testClassifyErrorAndUnknownTypes() {
    XCTAssertEqual(
      RelayTransport.classifyInbound(["type": "error", "message": "boom"]), .error("boom"))
    XCTAssertEqual(RelayTransport.classifyInbound(["type": "error"]), .error("error"))
    XCTAssertEqual(RelayTransport.classifyInbound(["type": "wat"]), .ignored)
    XCTAssertEqual(RelayTransport.classifyInbound([:]), .ignored)
  }

  // MARK: - Ack gating default

  func testCanConsumeDefaultsToTrue() {
    let relay = RelayTransport(mailboxHex: "00", sign: { _ in nil })
    XCTAssertTrue(relay.canConsume())
  }
}
