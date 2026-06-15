//
//  SafetyNumber.swift
//  Pigeon
//
//  Derives a human-comparable verification string for a pair of identities.
//

import CryptoKit
import Foundation

/// A 60-digit value (12 groups of 5) that two users compare in person — by
/// reading aloud or scanning a QR — to confirm no man-in-the-middle sits
/// between them. It is a deterministic function of both public keys and is
/// identical on both devices regardless of who computes it.
///
/// Design notes:
/// - Order-independent: the two keys are sorted before hashing, so Alice and
///   Bob derive the same number without coordinating who is "first".
/// - Iterated hashing (`iterations`) makes brute-forcing a colliding key pair
///   expensive, mirroring the approach used by Signal's safety numbers.
enum SafetyNumber {

  /// Number of hash iterations. Higher = more grinding cost for an attacker
  /// trying to fabricate a key whose safety number collides with a target.
  private static let iterations = 5200

  /// Computes the safety number for the local and remote identities.
  static func compute(local: IdentityPublicKey, remote: IdentityPublicKey) -> String {
    let a = local.rawRepresentation
    let b = remote.rawRepresentation

    // Sort so the result is independent of argument order.
    let (first, second) = lexicographicallyOrdered(a, b)

    let digestA = iteratedDigest(of: first)
    let digestB = iteratedDigest(of: second)

    // 30 digits from each side -> 60 total, grouped into 5-digit chunks.
    let digits = encodeDigits(digestA, count: 30) + encodeDigits(digestB, count: 30)
    return group(digits, by: 5)
  }

  private static func lexicographicallyOrdered(_ x: Data, _ y: Data) -> (Data, Data) {
    for (bx, by) in zip(x, y) where bx != by {
      return bx < by ? (x, y) : (y, x)
    }
    return x.count <= y.count ? (x, y) : (y, x)
  }

  private static func iteratedDigest(of key: Data) -> Data {
    var current = key
    for _ in 0..<iterations {
      // Re-mixing the original key each round binds every iteration to it.
      var input = current
      input.append(key)
      current = Data(SHA512.hash(data: input))
    }
    return current
  }

  /// Turns digest bytes into a fixed-length decimal string by reading
  /// 5-byte chunks as big-endian integers mod 100000 (5 digits each).
  private static func encodeDigits(_ digest: Data, count: Int) -> String {
    var out = ""
    var index = digest.startIndex
    while out.count < count {
      var chunk: UInt64 = 0
      for _ in 0..<5 {
        let byte = digest[index]
        chunk = (chunk << 8) | UInt64(byte)
        index = digest.index(after: index)
        if index == digest.endIndex { index = digest.startIndex }
      }
      out += String(format: "%05d", chunk % 100_000)
    }
    return String(out.prefix(count))
  }

  private static func group(_ digits: String, by size: Int) -> String {
    stride(from: 0, to: digits.count, by: size).map { offset -> String in
      let start = digits.index(digits.startIndex, offsetBy: offset)
      let end = digits.index(start, offsetBy: size, limitedBy: digits.endIndex) ?? digits.endIndex
      return String(digits[start..<end])
    }.joined(separator: " ")
  }
}
