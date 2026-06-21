//
//  LockedInboxTests.swift
//  PigeonTests
//
//  The locked-receipt buffer: coalesced notification, ordered drain, and the
//  flood bound that keeps a deposit storm from exhausting memory while locked.
//

import Foundation
import XCTest

@testable import Pigeon

final class LockedInboxTests: XCTestCase {

  private func entry(_ byte: UInt8) -> Data { Data([byte]) }

  func testNotifiesOnlyOnFirstBufferUntilReset() {
    var inbox = LockedInbox()
    XCTAssertTrue(inbox.buffer(entry(1), channel: .bluetooth), "first deposit should notify")
    XCTAssertFalse(inbox.buffer(entry(2), channel: .bluetooth), "subsequent deposits coalesce")
    XCTAssertFalse(inbox.buffer(entry(3), channel: .bluetooth))

    inbox.reset()
    XCTAssertTrue(inbox.buffer(entry(4), channel: .bluetooth), "reset re-arms the notification")
  }

  func testDrainReturnsBufferedInOrderAndClears() {
    var inbox = LockedInbox()
    _ = inbox.buffer(entry(1), channel: .bluetooth)
    _ = inbox.buffer(entry(2), channel: .relay(host: "relay.example"))

    let drained = inbox.drain()
    XCTAssertEqual(drained.map(\.data), [entry(1), entry(2)])
    XCTAssertEqual(drained.map(\.channel), [.bluetooth, .relay(host: "relay.example")])
    XCTAssertTrue(inbox.isEmpty)
    XCTAssertTrue(inbox.drain().isEmpty, "draining again yields nothing")
  }

  func testFloodIsBoundedToTheMostRecentEntries() {
    var inbox = LockedInbox()
    // Deposit well past the bound; the oldest must be dropped, newest kept.
    for index in 0..<600 { _ = inbox.buffer(Data([UInt8(index % 256)]), channel: .bluetooth) }

    let drained = inbox.drain()
    XCTAssertEqual(drained.count, 256, "buffer is capped at the flood bound")
    // The final deposit (index 599 -> 599 % 256 = 87) must survive as the last entry.
    XCTAssertEqual(drained.last?.data, Data([87]))
  }
}
