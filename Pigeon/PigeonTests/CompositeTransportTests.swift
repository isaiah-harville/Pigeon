//
//  CompositeTransportTests.swift
//  PigeonTests
//
//  The channel filter that lets the session force a message onto a specific
//  link (relay-only when a chat is switched off Bluetooth — #24).
//

import Foundation
import XCTest

@testable import Pigeon

@MainActor
final class CompositeTransportTests: XCTestCase {

  /// A single-link transport that records what it was asked to broadcast. It
  /// relies on the default `broadcast(_:to:over:)` filter from the protocol.
  private final class FakeTransport: Transport {
    let kind: TransportKind?
    var status: TransportStatus = .idle
    var connectedPeerCount = 0
    var log: [String] = []
    var onMessage: ((Data, String) -> Void)?
    private(set) var sent: [Data] = []

    init(kind: TransportKind?) { self.kind = kind }
    func broadcast(_ message: Data, to _: Data?) { sent.append(message) }
  }

  func testAllFilterReachesEveryLink() {
    let ble = FakeTransport(kind: .bluetooth)
    let relay = FakeTransport(kind: .relay)
    let composite = CompositeTransport([ble, relay])

    composite.broadcast(Data([0x01]), to: nil, over: TransportKind.all)

    XCTAssertEqual(ble.sent, [Data([0x01])])
    XCTAssertEqual(relay.sent, [Data([0x01])])
  }

  func testRelayOnlyFilterSkipsBluetooth() {
    let ble = FakeTransport(kind: .bluetooth)
    let relay = FakeTransport(kind: .relay)
    let composite = CompositeTransport([ble, relay])

    composite.broadcast(Data([0x02]), to: nil, over: [.relay])

    XCTAssertTrue(ble.sent.isEmpty)
    XCTAssertEqual(relay.sent, [Data([0x02])])
  }

  func testBluetoothOnlyFilterSkipsRelay() {
    let ble = FakeTransport(kind: .bluetooth)
    let relay = FakeTransport(kind: .relay)
    let composite = CompositeTransport([ble, relay])

    composite.broadcast(Data([0x03]), to: nil, over: [.bluetooth])

    XCTAssertEqual(ble.sent, [Data([0x03])])
    XCTAssertTrue(relay.sent.isEmpty)
  }

  func testUnfilteredConvenienceReachesEveryLink() {
    let ble = FakeTransport(kind: .bluetooth)
    let relay = FakeTransport(kind: .relay)
    let composite = CompositeTransport([ble, relay])

    composite.broadcast(Data([0x04]), to: nil)

    XCTAssertEqual(ble.sent, [Data([0x04])])
    XCTAssertEqual(relay.sent, [Data([0x04])])
  }
}
