//
//  SafetyNumberTests.swift
//  PigeonTests
//
//  The in-person verification string: order-independent, deterministic, and the
//  expected human-readable shape.
//

import CryptoKit
import XCTest

@testable import Pigeon

@MainActor
final class SafetyNumberTests: XCTestCase {

  private func identity() -> IdentityPublicKey {
    IdentityPublicKey(signingKey: Curve25519.Signing.PrivateKey().publicKey)
  }

  func testOrderIndependent() {
    let a = identity()
    let b = identity()
    XCTAssertEqual(
      SafetyNumber.compute(local: a, remote: b),
      SafetyNumber.compute(local: b, remote: a))
  }

  func testDeterministic() {
    let a = identity()
    let b = identity()
    XCTAssertEqual(
      SafetyNumber.compute(local: a, remote: b),
      SafetyNumber.compute(local: a, remote: b))
  }

  func testDistinctPairsDiffer() {
    let a = identity()
    XCTAssertNotEqual(
      SafetyNumber.compute(local: a, remote: identity()),
      SafetyNumber.compute(local: a, remote: identity()))
  }

  func testFormatIs60DigitsIn12GroupsOf5() {
    let number = SafetyNumber.compute(local: identity(), remote: identity())
    let groups = number.split(separator: " ")
    XCTAssertEqual(groups.count, 12)
    XCTAssertTrue(groups.allSatisfy { $0.count == 5 && $0.allSatisfy(\.isNumber) })
    XCTAssertEqual(number.filter(\.isNumber).count, 60)
  }
}
