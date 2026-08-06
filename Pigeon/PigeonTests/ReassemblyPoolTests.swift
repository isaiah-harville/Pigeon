//
//  ReassemblyPoolTests.swift
//  PigeonTests
//
//  The bound on how many BLE sources we track reassembly state for.
//

import XCTest

@testable import Pigeon

final class ReassemblyPoolTests: XCTestCase {

  func testReusesTheSameReassemblerForOneSource() {
    var pool = ReassemblyPool()
    let source = UUID()
    let first = pool.reassembler(for: source)
    let second = pool.reassembler(for: source)
    XCTAssertTrue(first === second)
    XCTAssertEqual(pool.count, 1)
  }

  func testTrackedSourcesAreCappedAtTheBound() {
    var pool = ReassemblyPool()
    for _ in 0..<(ReassemblyPool.maxSources * 3) {
      _ = pool.reassembler(for: UUID())
    }
    XCTAssertEqual(pool.count, ReassemblyPool.maxSources)
  }

  func testEvictsTheLeastRecentlyUsedSource() {
    var pool = ReassemblyPool()
    let oldest = UUID()
    let kept = UUID()
    _ = pool.reassembler(for: oldest)
    _ = pool.reassembler(for: kept)
    // Fill to the bound, touching `kept` so `oldest` is the stale one.
    for _ in 0..<(ReassemblyPool.maxSources - 2) {
      _ = pool.reassembler(for: UUID())
    }
    _ = pool.reassembler(for: kept)
    _ = pool.reassembler(for: UUID())  // one over the bound

    XCTAssertFalse(pool.tracks(oldest))
    XCTAssertTrue(pool.tracks(kept))
  }

  func testDropForgetsASource() {
    var pool = ReassemblyPool()
    let source = UUID()
    _ = pool.reassembler(for: source)
    pool.drop(source)
    XCTAssertFalse(pool.tracks(source))
    XCTAssertEqual(pool.count, 0)
  }
}
