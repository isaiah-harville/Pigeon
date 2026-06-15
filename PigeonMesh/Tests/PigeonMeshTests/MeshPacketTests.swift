//
//  MeshPacketTests.swift
//  PigeonMeshTests
//

import Foundation
import XCTest

@testable import PigeonMesh

final class MeshPacketTests: XCTestCase {

  private func packet(ttl: UInt8 = 8, payload: Data = Data("hi".utf8)) -> MeshPacket {
    MeshPacket(packetID: MeshPacket.randomID(), ttl: ttl, payload: payload)
  }

  // MARK: - Packet encoding

  func testPacketRoundTrip() throws {
    let packet = packet(ttl: 5, payload: Data("carrier".utf8))
    let decoded = try MeshPacket(decoding: packet.encoded())
    XCTAssertEqual(decoded, packet)
    XCTAssertEqual(packet.encoded().count, MeshPacket.headerSize + 7)
  }

  func testRandomIDsAreUniqueAndSized() {
    let firstID = MeshPacket.randomID()
    let secondID = MeshPacket.randomID()
    XCTAssertEqual(firstID.count, MeshPacket.idSize)
    XCTAssertNotEqual(firstID, secondID)
  }

  func testDecodeRejectsShortOrBadVersion() {
    XCTAssertThrowsError(try MeshPacket(decoding: Data([1, 2, 3])))
    var bytes = packet().encoded()
    bytes[bytes.startIndex] = 0x09
    XCTAssertThrowsError(try MeshPacket(decoding: bytes)) { error in
      XCTAssertEqual(error as? MeshError, .malformedPacket)
    }
  }

  func testRelayDecrementsTTL() {
    let relayed = packet(ttl: 3).relayed()
    XCTAssertEqual(relayed?.ttl, 2)
  }

  func testRelayStopsAtHopLimit() {
    XCTAssertNil(packet(ttl: 1).relayed())
    XCTAssertNil(packet(ttl: 0).relayed())
  }

  // MARK: - SeenCache

  func testSeenCacheDetectsDuplicates() {
    let cache = SeenCache()
    let id = MeshPacket.randomID()
    XCTAssertTrue(cache.insert(id))  // first time
    XCTAssertFalse(cache.insert(id))  // duplicate
    XCTAssertTrue(cache.contains(id))
  }

  func testSeenCacheEvictsOldest() {
    let cache = SeenCache(capacity: 2)
    let firstID = MeshPacket.randomID()
    let secondID = MeshPacket.randomID()
    let thirdID = MeshPacket.randomID()
    cache.insert(firstID)
    cache.insert(secondID)
    cache.insert(thirdID)  // evicts firstID
    XCTAssertFalse(cache.contains(firstID))
    XCTAssertTrue(cache.contains(secondID))
    XCTAssertTrue(cache.contains(thirdID))
  }

  // MARK: - Router

  func testOriginateProducesDeliverableUniquePackets() {
    let router = MeshRouter(defaultTTL: 8)
    let packet = router.originate(Data("msg".utf8))
    XCTAssertEqual(packet.ttl, 8)
    XCTAssertEqual(packet.payload, Data("msg".utf8))
  }

  func testIngestDeliversOnceThenDedupes() {
    let router = MeshRouter()
    let packet = packet(ttl: 8, payload: Data("once".utf8))

    let first = router.ingest(packet)
    XCTAssertEqual(first.deliver, Data("once".utf8))
    XCTAssertEqual(first.relay?.ttl, 7)

    // The same packet arriving again over another path is dropped.
    let second = router.ingest(packet)
    XCTAssertNil(second.deliver)
    XCTAssertNil(second.relay)
  }

  func testIngestDuplicateAcrossPathsIsTheDuplicateFix() {
    // Models exactly the observed bug: one logical message, two BLE paths.
    let router = MeshRouter()
    let originator = MeshRouter()
    let packet = originator.originate(Data("hello from A".utf8))

    let viaPathOne = router.ingest(packet)
    let viaPathTwo = router.ingest(packet)  // same packetID, different transport source

    XCTAssertEqual(viaPathOne.deliver, Data("hello from A".utf8))
    XCTAssertNil(viaPathTwo.deliver)  // delivered exactly once
  }

  func testOriginatorIgnoresItsOwnEcho() {
    let router = MeshRouter()
    let packet = router.originate(Data("echo".utf8))
    // If our own packet floods back to us, we must not deliver it to ourselves.
    XCTAssertNil(router.ingest(packet).deliver)
  }

  func testIngestAtTTL1DeliversButDoesNotRelay() {
    let router = MeshRouter()
    let packet = packet(ttl: 1, payload: Data("last hop".utf8))
    let result = router.ingest(packet)
    XCTAssertEqual(result.deliver, Data("last hop".utf8))
    XCTAssertNil(result.relay)
  }
}
