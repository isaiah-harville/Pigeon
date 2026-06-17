//
//  SecureMemory.swift
//  PigeonCrypto
//
//  Best-effort wiping of secret bytes from memory once they are no longer
//  needed, to shorten the window in which key material could be recovered from
//  a memory dump or scrape.
//
//  Limitations (important, and why this is "best-effort"):
//  - Swift `Data`/`[UInt8]` are value types with copy-on-write. We can only zero
//    a buffer when the caller holds the *sole* reference; if another copy shares
//    the storage, `withUnsafeMutableBytes` triggers a copy and we wipe the copy,
//    not the original. Callers must therefore drop other references *before*
//    zeroing (e.g. reassign a stored property, then zero the leftover local).
//  - The Swift runtime and OS may still have made transient copies we cannot
//    reach (argument passing, reallocation, swap).
//  - The reliably-zeroed containers are CryptoKit's own (`SymmetricKey`,
//    `SharedSecret`, the Curve25519 private keys): they wipe their storage on
//    deallocation. Prefer those for long-lived secrets; use this helper for the
//    raw `Data` byte buffers the Double Ratchet/Noise layers unavoidably handle.
//
//  We use `memset_s` where available (the C11 Annex K function specifically
//  designed not to be optimized away) and fall back to `memset` elsewhere.
//

import Foundation

#if canImport(Darwin)
  import Darwin
#elseif canImport(Glibc)
  import Glibc
#endif

public enum SecureMemory {

  /// Overwrites `data`'s bytes with zeros in place. No-op if empty. Only
  /// effective when `data` uniquely owns its storage (see file note).
  public static func zero(_ data: inout Data) {
    guard !data.isEmpty else { return }
    data.withUnsafeMutableBytes { raw in
      guard let base = raw.baseAddress else { return }
      wipe(base, raw.count)
    }
  }

  /// Overwrites `bytes` with zeros in place. No-op if empty.
  public static func zero(_ bytes: inout [UInt8]) {
    guard !bytes.isEmpty else { return }
    bytes.withUnsafeMutableBytes { raw in
      guard let base = raw.baseAddress else { return }
      wipe(base, raw.count)
    }
  }

  private static func wipe(_ base: UnsafeMutableRawPointer, _ count: Int) {
    #if canImport(Darwin)
      memset_s(base, count, 0, count)
    #else
      memset(base, 0, count)
    #endif
  }
}
