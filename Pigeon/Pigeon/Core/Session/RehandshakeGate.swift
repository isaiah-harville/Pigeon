//
//  RehandshakeGate.swift
//  Pigeon
//
//  Rate-limits reactive re-handshakes per contact (#33).
//
//  A `.rehandshakeRequest` envelope is an unauthenticated, empty-payload control
//  message, and an undecryptable `.message` is just as cheap to forge. Either one
//  drives the session layer to tear down and re-establish the session. The
//  identity/static binding keeps a spoofer from reading or forging content, but
//  nothing stops an attacker who can inject mesh packets from replaying these to
//  force endless session resets — a denial-of-service that wedges a conversation
//  in perpetual re-establishment.
//
//  This gate is the single choke point for every re-handshake the *network* can
//  trigger: it honors at most one per contact per cooldown window and silently
//  drops the rest, so a flood costs one reset per window instead of one per
//  packet. User-initiated resets (re-scanning a QR card, manual recovery) bypass
//  it entirely — they call `resetSession` directly and are never rate-limited.
//
//  Pure value type so the policy is unit-tested without the session machinery.
//

import Foundation

struct RehandshakeGate {

  /// Minimum spacing between honored re-handshakes for one contact. Re-establishment
  /// completes well within this, so a genuine desync still recovers promptly while
  /// a spoofed flood is throttled to one teardown per window.
  let cooldown: TimeInterval

  /// Last time a re-handshake was honored for each contact. In-memory only: the
  /// DoS is a live-traffic concern, and an attacker can't relaunch the victim's
  /// app to clear it, so there's nothing to persist.
  private var lastHonored: [Data: Date] = [:]

  init(cooldown: TimeInterval) { self.cooldown = cooldown }

  /// The default cooldown used in production (`SessionManager`). Re-establishment
  /// completes well within 30s, so a genuine desync still recovers promptly.
  static let defaultCooldown: TimeInterval = 30

  /// Whether a network-triggered re-handshake for `contactID` may proceed now.
  /// Returns `true` and records the moment when none has been honored within the
  /// cooldown window; returns `false` to suppress flood/replay-driven churn.
  mutating func allow(_ contactID: Data, now: Date) -> Bool {
    if let last = lastHonored[contactID], now.timeIntervalSince(last) < cooldown {
      return false
    }
    lastHonored[contactID] = now
    return true
  }

  /// Forgets a contact's cooldown so the next request is honored immediately.
  /// Used when a user-initiated reset supersedes the throttle (e.g. a fresh QR
  /// scan), keeping the map from growing across removed contacts.
  mutating func clear(_ contactID: Data) { lastHonored[contactID] = nil }
}
