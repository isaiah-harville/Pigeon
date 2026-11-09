//
//  PairwiseInboundFailureTests.swift
//  PigeonTests
//

import PigeonFFI
import XCTest

@testable import Pigeon

final class PairwiseInboundFailureTests: XCTestCase {
  func testMessagesThatCanNeverDecryptAreReleasedFromTheRelay() {
    let permanent: [PigeonError] = [
      .InvalidKey, .InvalidSignature, .MalformedBundle, .NotAPreKeyMessage,
      .SessionCreation, .Decryption, .ResourceLimit, .UnsupportedVersion,
    ]
    for error in permanent {
      XCTAssertEqual(
        TransportMessageDisposition(pairwiseFailure: error), .consumed, "\(error)")
    }
  }

  func testFailuresOfThisDeviceKeepTheRelayCopyForRetry() {
    let transient: [PigeonError] = [
      .Entropy, .Encryption, .Serialization, .Persistence, .Identity, .GroupPolicy, .Mls,
    ]
    for error in transient {
      XCTAssertEqual(
        TransportMessageDisposition(pairwiseFailure: error), .retryAfterRestart, "\(error)")
    }
  }

  func testPlatformFailuresKeepTheRelayCopyForRetry() {
    XCTAssertEqual(
      TransportMessageDisposition(pairwiseFailure: PlatformError.Unavailable),
      .retryAfterRestart)
    XCTAssertEqual(
      TransportMessageDisposition(pairwiseFailure: CocoaError(.fileWriteUnknown)),
      .retryAfterRestart)
  }
}
