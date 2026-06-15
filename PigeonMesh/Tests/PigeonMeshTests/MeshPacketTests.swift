//
//  MeshPacketTests.swift
//  PigeonMeshTests
//

import XCTest
import Foundation
@testable import PigeonMesh

final class MeshPacketTests: XCTestCase {

    private func packet(ttl: UInt8 = 8, payload: Data = Data("hi".utf8)) -> MeshPacket {
        MeshPacket(packetID: MeshPacket.randomID(), ttl: ttl, payload: payload)
    }

    // MARK: - Packet encoding

    func testPacketRoundTrip() throws {
        let p = packet(ttl: 5, payload: Data("carrier".utf8))
        let decoded = try MeshPacket(decoding: p.encoded())
        XCTAssertEqual(decoded, p)
        XCTAssertEqual(p.encoded().count, MeshPacket.headerSize + 7)
    }

    func testRandomIDsAreUniqueAndSized() {
        let a = MeshPacket.randomID()
        let b = MeshPacket.randomID()
        XCTAssertEqual(a.count, MeshPacket.idSize)
        XCTAssertNotEqual(a, b)
    }

    func testDecodeRejectsShortOrBadVersion() {
        XCTAssertThrowsError(try MeshPacket(decoding: Data([1, 2, 3])))
        var bytes = packet().encoded()
        bytes[bytes.startIndex] = 0x09
        XCTAssertThrowsError(try MeshPacket(decoding: bytes)) {
            XCTAssertEqual($0 as? MeshError, .malformedPacket)
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
        XCTAssertTrue(cache.insert(id))   // first time
        XCTAssertFalse(cache.insert(id))  // duplicate
        XCTAssertTrue(cache.contains(id))
    }

    func testSeenCacheEvictsOldest() {
        let cache = SeenCache(capacity: 2)
        let a = MeshPacket.randomID(), b = MeshPacket.randomID(), c = MeshPacket.randomID()
        cache.insert(a)
        cache.insert(b)
        cache.insert(c)             // evicts a
        XCTAssertFalse(cache.contains(a))
        XCTAssertTrue(cache.contains(b))
        XCTAssertTrue(cache.contains(c))
    }

    // MARK: - Router

    func testOriginateProducesDeliverableUniquePackets() {
        let router = MeshRouter(defaultTTL: 8)
        let p = router.originate(Data("msg".utf8))
        XCTAssertEqual(p.ttl, 8)
        XCTAssertEqual(p.payload, Data("msg".utf8))
    }

    func testIngestDeliversOnceThenDedupes() {
        let router = MeshRouter()
        let p = packet(ttl: 8, payload: Data("once".utf8))

        let first = router.ingest(p)
        XCTAssertEqual(first.deliver, Data("once".utf8))
        XCTAssertEqual(first.relay?.ttl, 7)

        // The same packet arriving again over another path is dropped.
        let second = router.ingest(p)
        XCTAssertNil(second.deliver)
        XCTAssertNil(second.relay)
    }

    func testIngestDuplicateAcrossPathsIsTheDuplicateFix() {
        // Models exactly the observed bug: one logical message, two BLE paths.
        let router = MeshRouter()
        let originator = MeshRouter()
        let p = originator.originate(Data("hello from A".utf8))

        let viaPathOne = router.ingest(p)
        let viaPathTwo = router.ingest(p) // same packetID, different transport source

        XCTAssertEqual(viaPathOne.deliver, Data("hello from A".utf8))
        XCTAssertNil(viaPathTwo.deliver) // delivered exactly once
    }

    func testOriginatorIgnoresItsOwnEcho() {
        let router = MeshRouter()
        let p = router.originate(Data("echo".utf8))
        // If our own packet floods back to us, we must not deliver it to ourselves.
        XCTAssertNil(router.ingest(p).deliver)
    }

    func testIngestAtTTL1DeliversButDoesNotRelay() {
        let router = MeshRouter()
        let p = packet(ttl: 1, payload: Data("last hop".utf8))
        let r = router.ingest(p)
        XCTAssertEqual(r.deliver, Data("last hop".utf8))
        XCTAssertNil(r.relay)
    }
}
