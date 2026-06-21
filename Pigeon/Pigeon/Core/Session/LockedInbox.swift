//
//  LockedInbox.swift
//  Pigeon
//
//  Holds session envelopes that arrive while the vault is locked (we can't
//  decrypt or persist yet) until the user unlocks. Extracted from SessionManager
//  so the buffering, bound, and coalesced-notification policy live in one small,
//  testable unit instead of the coordinator.
//

import Foundation

/// In-memory-only buffer for envelopes received while locked. Never written to
/// disk; the relay also retains its copies (we don't ack while locked), so
/// nothing is lost if we're killed before unlock. Bounded to blunt flooding, and
/// it tracks the once-per-locked-session "you have messages" notification so a
/// flood of deposits can't spam the user.
struct LockedInbox {

  /// One buffered envelope: the opaque bytes and the link it arrived on.
  typealias Entry = (data: Data, channel: TransportChannel)

  /// Upper bound on envelopes buffered while locked (memory only).
  private static let maxBuffered = 256

  private var entries: [Entry] = []
  private var notified = false

  var isEmpty: Bool { entries.isEmpty }

  /// Buffers an envelope, dropping the oldest past the bound. Returns `true` the
  /// first time it's called this locked session, signalling the caller to fire
  /// the (coalesced) "unlock to read" notification exactly once.
  mutating func buffer(_ data: Data, channel: TransportChannel) -> Bool {
    entries.append((data, channel))
    if entries.count > Self.maxBuffered {
      entries.removeFirst(entries.count - Self.maxBuffered)
    }
    guard !notified else { return false }
    notified = true
    return true
  }

  /// Returns everything buffered and clears the buffer, for replay after unlock.
  mutating func drain() -> [Entry] {
    defer { entries.removeAll() }
    return entries
  }

  /// Re-arms the coalesced notification (call on unlock, once the buffer has been
  /// drained), so the next locked session notifies again.
  mutating func reset() {
    notified = false
  }
}
