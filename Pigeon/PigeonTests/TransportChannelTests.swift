//
//  TransportChannelTests.swift
//  PigeonTests
//
//  Classification of the transport-scoped sender id into the channel the UI
//  shows. The id is locally observed, never read from the wire.
//

import XCTest

@testable import Pigeon

final class TransportChannelTests: XCTestCase {

  func testRelayPeerIDParsesHost() {
    XCTAssertEqual(
      TransportChannel(peerID: "relay:relay.example.com"),
      .relay(host: "relay.example.com"))
  }

  func testRelayPeerIDWithEmptyHost() {
    XCTAssertEqual(TransportChannel(peerID: "relay:"), .relay(host: ""))
  }

  func testRelayHostMayContainColons() {
    // host(_:) can yield "host:port"; the prefix split must keep the remainder.
    XCTAssertEqual(
      TransportChannel(peerID: "relay:192.0.2.1:8443"),
      .relay(host: "192.0.2.1:8443"))
  }

  func testBluetoothPeerIDIsBluetooth() {
    // BLE reports a raw peer UUID, which has no "relay:" prefix.
    XCTAssertEqual(
      TransportChannel(peerID: "8E1F2C3D-0000-1111-2222-333344445555"),
      .bluetooth)
  }

  func testEmptyPeerIDIsBluetooth() {
    XCTAssertEqual(TransportChannel(peerID: ""), .bluetooth)
  }

  func testRoundTripsThroughCodable() throws {
    for channel in [TransportChannel.bluetooth, .relay(host: "r.example")] {
      let data = try JSONEncoder().encode(channel)
      XCTAssertEqual(try JSONDecoder().decode(TransportChannel.self, from: data), channel)
    }
  }
}
