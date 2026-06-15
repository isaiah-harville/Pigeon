//
//  Transport.swift
//  Pigeon
//
//  The link-layer abstraction the mesh runs over. BLE (`PeerTransport`) is the
//  only implementation today, but `MeshService` depends on this protocol rather
//  than CoreBluetooth so future transports (Multipeer, LoRa, data mules, relays)
//  can drop in without touching mesh, session, or crypto code.
//
//  A transport is a "dumb pipe": it moves opaque byte messages between nearby
//  peers and knows nothing about encryption, mesh envelopes, or identity.
//  Everything it carries is already ciphertext by the time it gets here.
//

import Foundation

/// Link state surfaced to the UI. The vocabulary is intentionally small and
/// shared across transports; a transport maps its own state onto the nearest
/// case (e.g. a radio that is off reports `.poweredOff`).
enum TransportStatus: String {
  case idle = "Idle"
  case unauthorized = "Bluetooth not authorized"
  case poweredOff = "Bluetooth is off"
  case scanning = "Scanning for peers…"
}

/// A peer-to-peer byte pipe. Implementations handle their own discovery,
/// connection management, and fragmentation; callers see only whole messages.
///
/// Main-actor isolated: the mesh and UI observe transport state on the main
/// actor, and existing implementations deliver their callbacks there.
@MainActor
protocol Transport: AnyObject {
  /// Human-readable link state for the UI.
  var status: TransportStatus { get }

  /// Number of peers currently connected.
  var connectedPeerCount: Int { get }

  /// Recent activity, newest last — diagnostic only.
  var log: [String] { get }

  /// Invoked with each fully reassembled inbound message and an opaque,
  /// transport-scoped identifier for its immediate sender. The mesh layer does
  /// not trust this id for routing or security; it only deduplicates and relays
  /// authenticated envelopes.
  var onMessage: ((_ message: Data, _ peerID: String) -> Void)? { get set }

  /// Broadcasts an opaque message to every connected peer.
  func broadcast(_ message: Data)
}
