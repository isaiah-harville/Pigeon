//
//  ReassemblyPool.swift
//  Pigeon
//
//  Per-source fragment reassemblers for the BLE transport, with a bound on how
//  many sources are tracked at once.
//
//  Each `Reassembler` is itself bounded (64 in-flight messages, 256 KiB each),
//  but the number of *sources* was not: a peer that churns identifiers — or
//  centrals that write to us and never unsubscribe — could otherwise accumulate
//  reassemblers without limit. Extracted from PeerTransport so the bound is one
//  small, testable unit.
//

import Foundation
import PigeonFFI

/// A bounded, least-recently-used pool of per-source reassemblers.
struct ReassemblyPool {

  /// Upper bound on concurrently tracked sources. Comfortably above the number
  /// of simultaneous BLE links CoreBluetooth maintains.
  static let maxSources = 16

  private var reassemblers: [UUID: Reassembler] = [:]
  /// Sources in least-recently-used order (oldest first).
  private var order: [UUID] = []

  /// Number of sources currently tracked.
  var count: Int { reassemblers.count }

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
