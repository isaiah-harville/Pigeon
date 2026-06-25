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
  case localWiFi
  case relay(host: String)

  /// Classifies the opaque, transport-scoped sender id from `onMessage`. The
  /// relay tags its deliveries `"relay:<host>"` and local Wi-Fi `"wifi:<name>"`;
  /// BLE reports a raw peer UUID, so anything else is Bluetooth.
  init(peerID: String) {
    let relayPrefix = "relay:"
    let wifiPrefix = "wifi:"
    if peerID.hasPrefix(relayPrefix) {
      self = .relay(host: String(peerID.dropFirst(relayPrefix.count)))
    } else if peerID.hasPrefix(wifiPrefix) {
      self = .localWiFi
    } else {
      self = .bluetooth
    }
  }
}

/// Identifies which kind of link a concrete transport is, so callers can
/// restrict a send to a subset of links (e.g. force a message over the relay
/// when the user switches an in-range chat to the internet).
enum TransportKind: CaseIterable {
  case bluetooth
  case localWiFi
  case relay

  /// Every link — the unrestricted set, used as the "send everywhere" default.
  static var all: Set<TransportKind> { Set(allCases) }

  /// The local (no-internet) links: Bluetooth mesh and same-network Wi-Fi. A chat
  /// in local mode floods both, and the mesh dedup absorbs the overlap.
  static var local: Set<TransportKind> { [.bluetooth, .localWiFi] }
}

/// A peer-to-peer byte pipe. Implementations handle their own discovery,
/// connection management, and fragmentation; callers see only whole messages.
///
/// Main-actor isolated: the mesh and UI observe transport state on the main
/// actor, and existing implementations deliver their callbacks there.
@MainActor
protocol Transport: AnyObject {

  /// The link this transport drives, or `nil` for an aggregate (e.g.
  /// `CompositeTransport`) that owns several. Used to honor a channel filter.
  var kind: TransportKind? { get }
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

  /// Fired when this transport's reachability *improves* — a peer connects and
  /// its channel is ready, or a relay authenticates — so the session layer can
  /// (re)drive establishment and flush pending messages on the event instead of
  /// polling on a timer. Coarse and best-effort: it may fire more than
  /// once per real change, so consumers must be idempotent. Never fired for a
  /// drop (nothing to send when a link goes away).
  var onConnectivity: (() -> Void)? { get set }

  /// Sends an opaque message. `recipient` is the intended destination's identity
  /// key when known (a direct, originated message), or `nil` for address-less
  /// flooding (e.g. relaying someone else's packet onward). It is only a
  /// delivery hint: flood transports like BLE ignore it and broadcast to all
  /// peers, while a point-to-point transport (the relay) uses it to address the
  /// recipient's mailbox and skips `nil` (it does not flood the internet).
  func broadcast(_ message: Data, to recipient: Data?)

  /// Sends restricted to `channels` (pass `TransportKind.all` for every link).
  /// Lets the session force a message onto a specific link, e.g. relay-only when
  /// a chat is switched off Bluetooth.
  func broadcast(_ message: Data, to recipient: Data?, over channels: Set<TransportKind>)

  /// User-initiated recovery nudge. Transports should restart discovery or
  /// reconnect their sockets without changing app/session state.
  func refreshConnections()
}

extension Transport {
  var kind: TransportKind? { nil }

  /// Default filtering for a single-link transport: send when the filter
  /// includes this transport's kind, otherwise stay silent. `CompositeTransport`
  /// overrides this to fan the filter out to its children.
  func broadcast(_ message: Data, to recipient: Data?, over channels: Set<TransportKind>) {
    if let kind, !channels.contains(kind) { return }
    broadcast(message, to: recipient)
  }

  func refreshConnections() {}
}
