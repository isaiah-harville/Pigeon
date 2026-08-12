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

  /// Pins the derivation to its written spec: 5200 rounds of
  /// `SHA-512(current ‖ context ‖ key)` seeded with `context ‖ key`, under the
  /// versioned domain-separation string. Independently reimplemented here, so
  /// changing the context, the seed, or the round count fails loudly — every
  /// safety number changes with it and contacts must re-compare in person.
  func testDerivationMatchesTheDomainSeparatedSpec() {
    let a = identity()
    let b = identity()
    let (first, second) =
      a.rawRepresentation.lexicographicallyPrecedes(b.rawRepresentation)
      ? (a.rawRepresentation, b.rawRepresentation) : (b.rawRepresentation, a.rawRepresentation)
    let expected = digits(reference(first)) + digits(reference(second))
    let actual = SafetyNumber.compute(local: a, remote: b).filter(\.isNumber)
    XCTAssertEqual(actual, expected)
  }

  /// The spec, reimplemented independently of the production code.
  private func reference(_ key: Data) -> Data {
    let context = Data("Pigeon.SafetyNumber.v1".utf8)
    var current = context + key
    for _ in 0..<5200 {
      current = Data(SHA512.hash(data: current + context + key))
    }
    return current
  }

  /// 30 decimal digits: six 5-byte big-endian chunks, each mod 100000.
  private func digits(_ digest: Data) -> String {
    stride(from: 0, to: 30, by: 5)
      .map { offset in
        let chunk = digest[offset..<(offset + 5)].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        return String(format: "%05d", chunk % 100_000)
      }
      .joined()
  }

  func testFormatIs60DigitsIn12GroupsOf5() {
    let number = SafetyNumber.compute(local: identity(), remote: identity())
    let groups = number.split(separator: " ")
    XCTAssertEqual(groups.count, 12)
    XCTAssertTrue(groups.allSatisfy { $0.count == 5 && $0.allSatisfy(\.isNumber) })
    XCTAssertEqual(number.filter(\.isNumber).count, 60)
  }
}
