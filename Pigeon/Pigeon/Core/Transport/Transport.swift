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

/// Which link a message travelled over, surfaced to the UI so users can see
/// whether a message went by local Bluetooth or over an internet relay (and
/// which relay). This is *locally observed* — derived from which transport
/// delivered the bytes — never read from the wire, so it adds no unauthenticated
/// routing metadata and keeps the relay zero-knowledge.
enum TransportChannel: Codable, Equatable, Hashable {
  case bluetooth
  case relay(host: String)

  /// Classifies the opaque, transport-scoped sender id from `onMessage`. The
  /// relay tags its deliveries `"relay:<host>"`; BLE reports a raw peer UUID.
  init(peerID: String) {
    let prefix = "relay:"
    if peerID.hasPrefix(prefix) {
      self = .relay(host: String(peerID.dropFirst(prefix.count)))
    } else {
      self = .bluetooth
    }
  }
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

  /// Sends an opaque message. `recipient` is the intended destination's identity
  /// key when known (a direct, originated message), or `nil` for address-less
  /// flooding (e.g. relaying someone else's packet onward). It is only a
  /// delivery hint: flood transports like BLE ignore it and broadcast to all
  /// peers, while a point-to-point transport (the relay) uses it to address the
  /// recipient's mailbox and skips `nil` (it does not flood the internet).
  func broadcast(_ message: Data, to recipient: Data?)
}
