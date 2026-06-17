//
//  ConstantTime.swift
//  PigeonCrypto
//
//  Constant-time equality for security-sensitive byte comparisons.
//
//  Most of Pigeon's secret comparisons never reach this file: AEAD tag
//  verification happens inside CryptoKit (`AES.GCM.open` / `ChaChaPoly.open`),
//  which is already constant-time. This helper exists for the few authentication
//  decisions we make in our own code over byte buffers — notably the binding
//  check that ties a Noise handshake's static key to a verified identity — so
//  their running time does not depend on *how many* leading bytes match.
//
//  Note: the length check short-circuits, so the *lengths* of the inputs are not
//  hidden. That is intentional and safe here — the values compared are
//  fixed-length keys/tags whose sizes are public.
//

import Foundation

public enum ConstantTime {

  /// Compares two byte buffers in time that depends only on their length, not on
  /// their contents. Returns `false` immediately for mismatched lengths (which
  /// are not secret); for equal lengths it inspects every byte before returning.
  public static func equals(_ lhs: Data, _ rhs: Data) -> Bool {
    guard lhs.count == rhs.count else { return false }
    var difference: UInt8 = 0
    lhs.withUnsafeBytes { (left: UnsafeRawBufferPointer) in
      rhs.withUnsafeBytes { (right: UnsafeRawBufferPointer) in
        for i in 0..<left.count {
          difference |= left[i] ^ right[i]
        }
      }
    }
    return difference == 0
  }
}
