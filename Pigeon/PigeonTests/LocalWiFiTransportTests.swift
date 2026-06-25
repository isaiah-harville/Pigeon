//
//  LocalWiFiTransportTests.swift
//  PigeonTests
//
//  #34: the local Wi-Fi transport drops in alongside BLE and the relay. Covers
//  the pure, side-effect-free pieces — the link classification a received message
//  is tagged with, the local/all link sets the session sends over, and the
//  deterministic invite tie-break that keeps a pair from forming two sessions —
//  without standing up the live Multipeer stack (which would prompt for local
//  network access).
//

import XCTest

@testable import Pigeon

@MainActor
final class LocalWiFiTransportTests: XCTestCase {

  // MARK: - Channel classification

  func testWifiSenderIdClassifiesAsLocalWiFi() {
    XCTAssertEqual(TransportChannel(peerID: "wifi:P-1A2B3C4D"), .localWiFi)
  }

  func testOtherSenderIdsStillClassifyCorrectly() {
    XCTAssertEqual(
      TransportChannel(peerID: "relay:relay.example.com"), .relay(host: "relay.example.com"))
    // A raw BLE peer UUID has no known prefix and falls back to Bluetooth.
    XCTAssertEqual(TransportChannel(peerID: "5B1C0D0D-2A7B-44E8-9C92"), .bluetooth)
  }

  // MARK: - Link sets

  func testLocalLinkSetIsBluetoothPlusWiFi() {
    XCTAssertEqual(TransportKind.local, [.bluetooth, .localWiFi])
    XCTAssertFalse(TransportKind.local.contains(.relay), "local mode never uses the relay")
  }

  func testAllIncludesEveryLink() {
    XCTAssertEqual(TransportKind.all, [.bluetooth, .localWiFi, .relay])
  }

  // MARK: - Invite tie-break

  func testExactlyOneSideInvites() {
    let a = "P-aaaa1111"
    let b = "P-bbbb2222"
    // Both devices see both names and must reach opposite decisions, so exactly
    // one session is created for the pair.
    XCTAssertNotEqual(
      LocalWiFiTransport.shouldInvite(myName: a, peerName: b),
      LocalWiFiTransport.shouldInvite(myName: b, peerName: a))
  }

  func testEqualNamesNeitherInvites() {
    // Random per-launch names make this astronomically unlikely; if it happens,
    // neither invites rather than both — no duplicate session.
    XCTAssertFalse(LocalWiFiTransport.shouldInvite(myName: "P-same", peerName: "P-same"))
  }

  // MARK: - Service type

  func testServiceTypeIsValidBonjour() {
    let type = LocalWiFiTransport.serviceType
    XCTAssertLessThanOrEqual(type.count, 15, "Bonjour service types are limited to 15 characters")
    XCTAssertEqual(type, type.lowercased())
    XCTAssertTrue(type.allSatisfy { $0.isLowercase || $0.isNumber || $0 == "-" })
  }
}
