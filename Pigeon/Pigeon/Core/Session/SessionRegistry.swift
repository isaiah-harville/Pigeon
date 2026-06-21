//
//  SessionRegistry.swift
//  Pigeon
//
//  The per-contact Olm session state of the coordinator: the live sessions, the
//  set of contacts with a fully established + verified session, and the two
//  initiation payloads that drive async-first establishment. Extracted from
//  SessionManager so this state is owned by one focused, observable type.
//
//  Storage only — the establishment, binding, and ratchet *logic* stays in
//  SessionManager's messaging code (which still reaches this state through the
//  coordinator's facade), so the crypto paths are untouched by the extraction.
//

import Foundation
import PigeonCore

/// Owns the live messaging-session state. `@Observable` so views observing
/// establishment (e.g. the chat's lock indicator) refresh as sessions stand up.
@MainActor
@Observable
final class SessionRegistry {

  /// One Olm session per contact (identity id → session).
  var sessions: [Data: PigeonSession] = [:]
  /// Identity ids of contacts with a fully established, verified session.
  var established: Set<Data> = []
  /// The initiation payload (`identity ‖ first Olm pre-key message`) we sent per
  /// contact, retained so it can be resent until the peer drains it. Cleared once
  /// the peer acks (proof it stood up the session).
  var pendingInitiation: [Data: Data] = [:]
  /// The last initiation payload we processed as responder, to ignore retransmits
  /// (re-running `establishInbound` would build a second session); a *different*
  /// payload signals a genuine peer restart and triggers a rebuild.
  var lastInitiationIn: [Data: Data] = [:]

  /// Clears all per-contact session state, so the next establishment starts a
  /// fresh handshake (manual recovery, a re-scan, or a detected desync).
  func reset(_ id: Data) {
    sessions[id] = nil
    pendingInitiation[id] = nil
    lastInitiationIn[id] = nil
    established.remove(id)
  }
}
