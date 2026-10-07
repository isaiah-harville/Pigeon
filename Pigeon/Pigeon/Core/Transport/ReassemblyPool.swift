//
//  ReassemblyPool.swift
//  Pigeon
//
//  Per-source fragment reassemblers for the BLE transport, with a bound on
//  retained payload across all sources.
//
//  Each `Reassembler` is bounded to 64 messages and 256 KiB per message. The
//  pool also caps source count and total retained fragment payload at 4 MiB.
//

import Foundation
import PigeonFFI

/// A bounded, least-recently-used pool of per-source reassemblers.
struct ReassemblyPool {

  /// Upper bound on concurrently tracked sources. Comfortably above the number
  /// of simultaneous BLE links CoreBluetooth maintains.
  static let maxSources = 16
  static let maxPendingBytes: UInt64 = 4 * 1024 * 1024

  private var reassemblers: [UUID: Reassembler] = [:]
  /// Sources in least-recently-used order (oldest first).
  private var order: [UUID] = []

  /// Number of sources currently tracked.
  var count: Int { reassemblers.count }
  var pendingBytes: UInt64 { reassemblers.values.reduce(0) { $0 + $1.pendingBytes() } }

  mutating func ingest(_ fragment: Fragment, from source: UUID) throws -> Data? {
    let message = try reassembler(for: source).ingest(fragment)
    while pendingBytes > Self.maxPendingBytes, let oldest = order.first {
      drop(oldest)
    }
    return message
  }

  /// Returns this source's reassembler, creating one if needed and retiring the
  /// least-recently-used source once the bound is reached. Retiring one only
  /// drops its partial fragments; a live peer's next message starts fresh.
  mutating func reassembler(for source: UUID) -> Reassembler {
    order.removeAll { $0 == source }
    order.append(source)
    if let existing = reassemblers[source] { return existing }
    let made = Reassembler()
    reassemblers[source] = made
    while order.count > Self.maxSources {
      reassemblers[order.removeFirst()] = nil
    }
    return made
  }

  /// Forgets a source's partial fragments (on disconnect or unsubscribe).
  mutating func drop(_ source: UUID) {
    reassemblers[source] = nil
    order.removeAll { $0 == source }
  }

  /// Whether a source is currently tracked (for tests).
  func tracks(_ source: UUID) -> Bool {
    reassemblers[source] != nil
  }
}
