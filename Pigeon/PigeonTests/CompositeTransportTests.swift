//
//  CompositeTransportTests.swift
//  PigeonTests
//
//  The channel filter that lets the session force a message onto a specific
//  link (relay-only when a chat is switched off Bluetooth).
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
    var onMessage: ((Data, String) -> TransportMessageDisposition)?
    var onConnectivity: (() -> Void)?
    private(set) var sent: [Data] = []
    private(set) var refreshCount = 0
    private(set) var enabledValues: [Bool] = []

    init(kind: TransportKind?) { self.kind = kind }
    func broadcast(_ message: Data, to _: Data?) { sent.append(message) }
    func refreshConnections() { refreshCount += 1 }
    func setEnabled(_ enabled: Bool) { enabledValues.append(enabled) }
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

  func testRefreshReachesEveryLink() {
    let ble = FakeTransport(kind: .bluetooth)
    let relay = FakeTransport(kind: .relay)
    let composite = CompositeTransport([ble, relay])

    composite.refreshConnections()

    XCTAssertEqual(ble.refreshCount, 1)
    XCTAssertEqual(relay.refreshCount, 1)
  }

  /// Event-driven delivery: a child link coming up must surface to the
  /// composite's consumer, so the session layer can flush pending work without
  /// polling. Either link firing should reach the single handler.
  func testConnectivityFromAnyLinkReachesConsumer() {
    let ble = FakeTransport(kind: .bluetooth)
    let relay = FakeTransport(kind: .relay)
    let composite = CompositeTransport([ble, relay])

    var fired = 0
    composite.onConnectivity = { fired += 1 }

    ble.onConnectivity?()
    relay.onConnectivity?()

    XCTAssertEqual(fired, 2)
  }

  func testDisabledCompositeStopsNetworkActivityUntilReenabled() {
    let ble = FakeTransport(kind: .bluetooth)
    let relay = FakeTransport(kind: .relay)
    let composite = CompositeTransport([ble, relay])
    var received = 0
    var connectivityEvents = 0
    composite.onMessage = { _, _ in
      received += 1
      return .consumed
    }
    composite.onConnectivity = { connectivityEvents += 1 }

    composite.setEnabled(false)
    composite.broadcast(Data([0x05]), to: nil)
    composite.refreshConnections()
    let disabledDisposition = ble.onMessage?(Data([0x06]), "peer")
    ble.onConnectivity?()

    XCTAssertEqual(ble.enabledValues, [false])
    XCTAssertEqual(relay.enabledValues, [false])
    XCTAssertTrue(ble.sent.isEmpty)
    XCTAssertTrue(relay.sent.isEmpty)
    XCTAssertEqual(ble.refreshCount, 0)
    XCTAssertEqual(relay.refreshCount, 0)
    XCTAssertEqual(disabledDisposition, .retryAfterRestart)
    XCTAssertEqual(received, 0)
    XCTAssertEqual(connectivityEvents, 0)

    composite.setEnabled(true)
    composite.broadcast(Data([0x07]), to: nil)
    composite.refreshConnections()
    let enabledDisposition = relay.onMessage?(Data([0x08]), "relay:example")
    relay.onConnectivity?()

    XCTAssertEqual(ble.enabledValues, [false, true])
    XCTAssertEqual(relay.enabledValues, [false, true])
    XCTAssertEqual(ble.sent, [Data([0x07])])
    XCTAssertEqual(relay.sent, [Data([0x07])])
    XCTAssertEqual(ble.refreshCount, 1)
    XCTAssertEqual(relay.refreshCount, 1)
    XCTAssertEqual(enabledDisposition, .consumed)
    XCTAssertEqual(received, 1)
    XCTAssertEqual(connectivityEvents, 1)
  }
}
