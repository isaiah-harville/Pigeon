//
//  LocalWiFiTransport.swift
//  Pigeon
//
//  A same-network local transport built on Multipeer Connectivity (#34). It runs
//  alongside BLE and the relay as another `Transport`: a "dumb pipe" that moves
//  opaque, already-end-to-end-encrypted mesh bytes between nearby devices over
//  Wi-Fi / peer-to-peer Wi-Fi, with no knowledge of encryption, identity, or mesh
//  envelopes. Multipeer gives reliable, arbitrarily-sized sessions, so — unlike
//  BLE — no fragmentation is needed here; whole mesh packets go over the wire.
//
//  Trust model: like BLE, this is an open local link. We accept any nearby Pigeon
//  peer and carry its bytes; confidentiality, authentication, and ordering are
//  enforced above by the Olm session and identity binding, never by this layer.
//  The mesh dedup layer absorbs a message that also arrives over BLE or the relay.
//  Defence in depth: the Multipeer session itself is encrypted (`.required`) and
//  we advertise a random per-launch name with no discovery metadata, so the local
//  network sees neither the device's name nor readable content.
//

import Foundation
import MultipeerConnectivity

/// The local-Wi-Fi implementation of `Transport`. Advertises and browses for
/// peers on the local network and exchanges opaque messages over an encrypted
/// Multipeer session. Main-actor isolated like the other transports; the
/// Multipeer delegate callbacks arrive off-main and hop back on.
@MainActor
final class LocalWiFiTransport: NSObject, Transport {

  /// Bonjour service type shared by all Pigeon devices (≤ 15 chars, lowercase /
  /// digits / hyphen). Must match the `NSBonjourServices` Info.plist entries.
  static let serviceType = "pigeon-mesh"

  let kind: TransportKind? = .localWiFi
  private(set) var status: TransportStatus = .idle
  private(set) var connectedPeerCount = 0
  private(set) var log: [String] = []

  var onMessage: ((_ message: Data, _ peerID: String) -> Void)?
  var onConnectivity: (() -> Void)?

  /// Our advertised name: random per launch, so the local network learns no
  /// device name. Also the deterministic tie-break value for who invites.
  private let localName: String

  // Apple's Multipeer objects are internally thread-safe for the calls we make
  // (send/invite/start/stop) and we only ever hand them Sendable values, so we
  // reach them from the off-main delegate callbacks via `nonisolated(unsafe)`.
  // Mutable app state (counts, log, status) stays on the main actor.
  nonisolated(unsafe) private let session: MCSession
  nonisolated(unsafe) private let advertiser: MCNearbyServiceAdvertiser
  nonisolated(unsafe) private let browser: MCNearbyServiceBrowser

  override init() {
    localName = "P-" + UUID().uuidString.prefix(8)
    let peerID = MCPeerID(displayName: localName)
    session = MCSession(peer: peerID, securityIdentity: nil, encryptionPreference: .required)
    advertiser = MCNearbyServiceAdvertiser(
      peer: peerID, discoveryInfo: nil, serviceType: Self.serviceType)
    browser = MCNearbyServiceBrowser(peer: peerID, serviceType: Self.serviceType)
    super.init()
    session.delegate = self
    advertiser.delegate = self
    browser.delegate = self
    advertiser.startAdvertisingPeer()
    browser.startBrowsingForPeers()
    status = .scanning
    note("Wi-Fi advertising/browsing as \(localName)")
  }

  deinit {
    advertiser.stopAdvertisingPeer()
    browser.stopBrowsingForPeers()
    session.disconnect()
  }

  /// Sends to every connected local peer. Wi-Fi is a flood/local link like BLE,
  /// so the `recipient` hint is ignored — the mesh addresses and deduplicates
  /// above this layer.
  func broadcast(_ message: Data, to _: Data?) {
    let peers = session.connectedPeers
    guard !peers.isEmpty else { return }
    do {
      try session.send(message, toPeers: peers, with: .reliable)
      note("Wi-Fi sent \(message.count)B to \(peers.count) peer(s)")
    } catch {
      note("Wi-Fi send failed: \(error.localizedDescription)")
    }
  }

  func refreshConnections() {
    browser.stopBrowsingForPeers()
    browser.startBrowsingForPeers()
    advertiser.startAdvertisingPeer()
    status = .scanning
    note("Wi-Fi refresh requested")
  }

  /// Deterministic tie-break so exactly one side of a pair sends the invitation
  /// (both devices see both random names, so the comparison agrees), avoiding two
  /// redundant sessions for the same pair. Pure, so it is unit-tested.
  nonisolated static func shouldInvite(myName: String, peerName: String) -> Bool {
    myName < peerName
  }

  private func note(_ message: String) {
    log.append(message)
    if log.count > 200 { log.removeFirst(log.count - 200) }
  }

  /// Delivers a reassembled inbound message on the main actor, tagging the sender
  /// id with a `wifi:` prefix so `TransportChannel` classifies the link.
  private func deliver(_ data: Data, from name: String) {
    note("Wi-Fi received \(data.count)B from \(name)")
    onMessage?(data, "wifi:\(name)")
  }

  private func handleStateChange(connectedCount: Int, peer: String, connected: Bool) {
    connectedPeerCount = connectedCount
    if connected {
      note("Wi-Fi connected: \(peer)")
      onConnectivity?()  // a usable local link came up — flush pending work (#82)
    } else {
      note("Wi-Fi link to \(peer) ended")
    }
  }
}

// MARK: - MCSessionDelegate

extension LocalWiFiTransport: MCSessionDelegate {
  nonisolated func session(
    _ session: MCSession, peer peerID: MCPeerID, didChange state: MCSessionState
  ) {
    let count = session.connectedPeers.count
    let name = peerID.displayName
    let connected = state == .connected
    let settled = state != .connecting
    Task { @MainActor in
      if settled { self.handleStateChange(connectedCount: count, peer: name, connected: connected) }
    }
  }

  nonisolated func session(_: MCSession, didReceive data: Data, fromPeer peerID: MCPeerID) {
    let name = peerID.displayName
    Task { @MainActor in self.deliver(data, from: name) }
  }

  // Pigeon only uses the reliable data path; streams and resources are unused.
  nonisolated func session(
    _: MCSession, didReceive _: InputStream, withName _: String, fromPeer _: MCPeerID
  ) {}
  nonisolated func session(
    _: MCSession, didStartReceivingResourceWithName _: String, fromPeer _: MCPeerID,
    with _: Progress
  ) {}
  nonisolated func session(
    _: MCSession, didFinishReceivingResourceWithName _: String, fromPeer _: MCPeerID,
    at _: URL?, withError _: Error?
  ) {}
}

// MARK: - MCNearbyServiceAdvertiserDelegate

extension LocalWiFiTransport: MCNearbyServiceAdvertiserDelegate {
  nonisolated func advertiser(
    _: MCNearbyServiceAdvertiser, didReceiveInvitationFromPeer _: MCPeerID,
    withContext _: Data?, invitationHandler: @escaping (Bool, MCSession?) -> Void
  ) {
    // Accept any nearby Pigeon peer: the open local-link model (same as BLE).
    invitationHandler(true, session)
  }
}

// MARK: - MCNearbyServiceBrowserDelegate

extension LocalWiFiTransport: MCNearbyServiceBrowserDelegate {
  // The `[String: String]?` discovery info is imposed by the delegate protocol.
  // swiftlint:disable discouraged_optional_collection
  nonisolated func browser(
    _ browser: MCNearbyServiceBrowser, foundPeer peerID: MCPeerID,
    withDiscoveryInfo _: [String: String]?
  ) {
    // swiftlint:enable discouraged_optional_collection
    guard Self.shouldInvite(myName: localName, peerName: peerID.displayName) else { return }
    browser.invitePeer(peerID, to: session, withContext: nil, timeout: 15)
  }

  nonisolated func browser(_: MCNearbyServiceBrowser, lostPeer _: MCPeerID) {}
}
