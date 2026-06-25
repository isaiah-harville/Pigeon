//
//  BluetoothFragmentBudgetTests.swift
//  PigeonTests
//
//  #30: BLE fragment payload follows the negotiated ATT MTU per connection
//  instead of a fixed conservative size. Covers the pure clamp policy — header
//  subtraction, the safe floor on small/absent MTUs, and the defensive ceiling —
//  without standing up CoreBluetooth.
//

import XCTest

@testable import Pigeon

@MainActor
final class BluetoothFragmentBudgetTests: XCTestCase {

  func testNoLivePathFallsBackToTheFloor() {
    XCTAssertEqual(
      PeerTransport.fragmentPayloadBudget(smallestNegotiatedLength: nil),
      BluetoothConstants.maxFragmentPayload)
  }

  func testSmallMtuIsClampedUpToTheFloor() {
    // A 23-byte ATT MTU (20 usable) must not shrink fragments below today's safe
    // floor — the floor is what every link is already known to carry.
    XCTAssertEqual(
      PeerTransport.fragmentPayloadBudget(smallestNegotiatedLength: 23),
      BluetoothConstants.maxFragmentPayload)
  }

  func testNegotiatedMtuRaisesThePayloadByTheHeader() {
    // A typical iOS notify length of 185 yields 185 − 7 header = 178 usable bytes,
    // above the 150 floor and below the ceiling.
    let budget = PeerTransport.fragmentPayloadBudget(smallestNegotiatedLength: 185)
    XCTAssertEqual(budget, 185 - BluetoothConstants.fragmentHeaderSize)
    XCTAssertGreaterThan(budget, BluetoothConstants.maxFragmentPayload)
  }

  func testGenerousMtuIsCappedAtTheCeiling() {
    // A 512-byte length would give 505 usable; the defensive ceiling bounds it.
    XCTAssertEqual(
      PeerTransport.fragmentPayloadBudget(smallestNegotiatedLength: 512),
      BluetoothConstants.maxFragmentPayloadCeiling)
  }

  func testRealisticMtuFragmentsFitTheNegotiatedLength() {
    // For any MTU iOS actually negotiates (comfortably above the floor), the whole
    // encoded fragment — payload + header — must fit the negotiated value length so
    // every target can receive it in one write/notification.
    for length in [185, 247, 400, 512, 1000] {
      let budget = PeerTransport.fragmentPayloadBudget(smallestNegotiatedLength: length)
      XCTAssertLessThanOrEqual(budget + BluetoothConstants.fragmentHeaderSize, length)
      XCTAssertGreaterThanOrEqual(budget, BluetoothConstants.maxFragmentPayload)
    }
  }
}
