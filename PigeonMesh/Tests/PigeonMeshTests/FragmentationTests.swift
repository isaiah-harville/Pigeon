//
//  FragmentationTests.swift
//  PigeonMeshTests
//

import Foundation
import XCTest

@testable import PigeonMesh

final class FragmentationTests: XCTestCase {

  private func randomData(_ count: Int) -> Data {
    Data((0..<count).map { _ in UInt8.random(in: 0...255) })
  }

  // MARK: - Fragment encoding

  func testFragmentRoundTrip() throws {
    let fragment = Fragment(messageID: 0xBEEF, index: 3, count: 10, payload: randomData(50))
    let decoded = try Fragment(decoding: fragment.encoded())
    XCTAssertEqual(decoded, fragment)
    XCTAssertEqual(fragment.encoded().count, Fragment.headerSize + 50)
  }

  func testDecodeRejectsShortData() {
    XCTAssertThrowsError(try Fragment(decoding: Data([1, 2, 3]))) { error in
      XCTAssertEqual(error as? FragmentationError, .malformedFragment)
    }
  }

  func testDecodeRejectsBadVersion() {
    var bytes = Fragment(messageID: 1, index: 0, count: 1, payload: Data()).encoded()
    bytes[bytes.startIndex] = 0xFF
    XCTAssertThrowsError(try Fragment(decoding: bytes)) { error in
      XCTAssertEqual(error as? FragmentationError, .malformedFragment)
    }
  }

  func testDecodeRejectsIndexBeyondCount() {
    // index 5, count 3 -> inconsistent
    var bytes = Data([Fragment.version])
    bytes.append(contentsOf: [0x00, 0x01])  // messageID
    bytes.append(contentsOf: [0x00, 0x05])  // index
    bytes.append(contentsOf: [0x00, 0x03])  // count
    XCTAssertThrowsError(try Fragment(decoding: bytes)) { error in
      XCTAssertEqual(error as? FragmentationError, .inconsistentFragment)
    }
  }

  // MARK: - Fragment + reassemble

  func testSingleFragmentMessage() throws {
    var fragmenter = Fragmenter()
    let reassembler = Reassembler()
    let message = randomData(30)
    let frags = try fragmenter.fragment(message, maxPayloadPerFragment: 100)
    XCTAssertEqual(frags.count, 1)
    XCTAssertEqual(try reassembler.ingest(frags[0]), message)
  }

  func testEmptyMessageIsDeliverable() throws {
    var fragmenter = Fragmenter()
    let reassembler = Reassembler()
    let frags = try fragmenter.fragment(Data(), maxPayloadPerFragment: 100)
    XCTAssertEqual(frags.count, 1)
    XCTAssertEqual(try reassembler.ingest(frags[0]), Data())
  }

  func testMultiFragmentInOrder() throws {
    var fragmenter = Fragmenter()
    let reassembler = Reassembler()
    let message = randomData(1000)
    let frags = try fragmenter.fragment(message, maxPayloadPerFragment: 180)
    XCTAssertEqual(frags.count, 6)  // ceil(1000/180)

    var result: Data?
    for fragment in frags { result = try reassembler.ingest(fragment) }
    XCTAssertEqual(result, message)
  }

  func testMultiFragmentOutOfOrder() throws {
    var fragmenter = Fragmenter()
    let reassembler = Reassembler()
    let message = randomData(900)
    let frags = try fragmenter.fragment(message, maxPayloadPerFragment: 100).shuffled()

    var result: Data?
    for fragment in frags {
      if let reassembled = try reassembler.ingest(fragment) { result = reassembled }
    }
    XCTAssertEqual(result, message)
  }

  func testDuplicateFragmentsTolerated() throws {
    var fragmenter = Fragmenter()
    let reassembler = Reassembler()
    let message = randomData(500)
    let frags = try fragmenter.fragment(message, maxPayloadPerFragment: 100)

    var result: Data?
    // Deliver every fragment twice; completion should fire exactly once and be correct.
    for fragment in frags + frags {
      if let reassembled = try reassembler.ingest(fragment) { result = reassembled }
    }
    XCTAssertEqual(result, message)
  }

  func testInterleavedMessages() throws {
    var fragmenter = Fragmenter()
    let reassembler = Reassembler()
    let firstMessage = randomData(400)
    let secondMessage = randomData(350)
    let firstFragments = try fragmenter.fragment(firstMessage, maxPayloadPerFragment: 100)
    let secondFragments = try fragmenter.fragment(secondMessage, maxPayloadPerFragment: 100)

    // Interleave the two messages' fragments.
    var reassembledMessages: [Data] = []
    let interleaved =
      zip(firstFragments, secondFragments).flatMap { first, second in [first, second] }
      + firstFragments.dropFirst(secondFragments.count)
      + secondFragments.dropFirst(firstFragments.count)
    for fragment in interleaved {
      if let reassembled = try reassembler.ingest(fragment) {
        reassembledMessages.append(reassembled)
      }
    }
    XCTAssertTrue(reassembledMessages.contains(firstMessage))
    XCTAssertTrue(reassembledMessages.contains(secondMessage))
  }

  func testEachMessageGetsDistinctID() throws {
    var fragmenter = Fragmenter()
    let firstFragment = try fragmenter.fragment(randomData(10), maxPayloadPerFragment: 100)[0]
    let secondFragment = try fragmenter.fragment(randomData(10), maxPayloadPerFragment: 100)[0]
    XCTAssertNotEqual(firstFragment.messageID, secondFragment.messageID)
  }

  // MARK: - Bounds

  func testOversizeMessageRejected() throws {
    let reassembler = Reassembler(maxMessageBytes: 200)
    // Two fragments of 150 bytes each = 300 > 200.
    let id: UInt16 = 7
    _ = try reassembler.ingest(
      Fragment(messageID: id, index: 0, count: 2, payload: randomData(150)))
    XCTAssertThrowsError(
      try reassembler.ingest(Fragment(messageID: id, index: 1, count: 2, payload: randomData(150)))
    ) { error in
      XCTAssertEqual(error as? FragmentationError, .messageTooLarge)
    }
  }

  func testConcurrentPendingBounded() throws {
    let reassembler = Reassembler(maxConcurrentMessages: 4)
    // Open 10 distinct incomplete messages; only the cap should remain buffered.
    for id in 0..<10 {
      _ = try reassembler.ingest(
        Fragment(messageID: UInt16(id), index: 0, count: 2, payload: Data([0x01])))
    }
    XCTAssertLessThanOrEqual(reassembler.pendingCount, 4)
  }

  func testReusedMessageIDResetsState() throws {
    let reassembler = Reassembler()
    // First message id=1 starts (count 3), only one fragment arrives.
    _ = try reassembler.ingest(Fragment(messageID: 1, index: 0, count: 3, payload: Data([0xAA])))
    // id=1 reused with a different count: treated as a new message.
    let firstResult = try reassembler.ingest(
      Fragment(messageID: 1, index: 0, count: 2, payload: Data([0xBB])))
    XCTAssertNil(firstResult)
    let secondResult = try reassembler.ingest(
      Fragment(messageID: 1, index: 1, count: 2, payload: Data([0xCC])))
    XCTAssertEqual(secondResult, Data([0xBB, 0xCC]))
  }
}
