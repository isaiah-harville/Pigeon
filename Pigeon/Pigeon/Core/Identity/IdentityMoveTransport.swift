import Foundation
@preconcurrency import MultipeerConnectivity

/// Temporary local pipe for an owner-authorized device move. The move channel
/// authenticates and encrypts every secret frame above this transport.
@MainActor
@Observable
final class IdentityMoveTransport: NSObject {
  enum Role: Sendable {
    case source
    case destination
  }

  static let serviceType = "pigeon-move"

  nonisolated let role: Role
  private(set) var discoveredPeerNames: [String] = []
  private(set) var isConnected = false
  var onConnected: (() -> Void)?
  var onDisconnected: (() -> Void)?
  var onData: ((Data) -> Void)?

  private var discoveredPeers: [String: MCPeerID] = [:]
  nonisolated(unsafe) private let session: MCSession
  nonisolated(unsafe) private let advertiser: MCNearbyServiceAdvertiser
  nonisolated(unsafe) private let browser: MCNearbyServiceBrowser

  init(role: Role) {
    self.role = role
    let peer = MCPeerID(displayName: "M-" + UUID().uuidString.prefix(8))
    session = MCSession(peer: peer, securityIdentity: nil, encryptionPreference: .required)
    advertiser = MCNearbyServiceAdvertiser(
      peer: peer, discoveryInfo: nil, serviceType: Self.serviceType)
    browser = MCNearbyServiceBrowser(peer: peer, serviceType: Self.serviceType)
    super.init()
    session.delegate = self
    advertiser.delegate = self
    browser.delegate = self
  }

  deinit {
    advertiser.stopAdvertisingPeer()
    browser.stopBrowsingForPeers()
    session.disconnect()
  }

  func start() {
    switch role {
    case .source: advertiser.startAdvertisingPeer()
    case .destination: browser.startBrowsingForPeers()
    }
  }

  func stop() {
    advertiser.stopAdvertisingPeer()
    browser.stopBrowsingForPeers()
    session.disconnect()
    isConnected = false
  }

  func connect(to name: String) {
    guard role == .destination, let peer = discoveredPeers[name], !isConnected else { return }
    browser.invitePeer(peer, to: session, withContext: nil, timeout: 20)
  }

  func send(_ data: Data) throws {
    guard data.count <= 70 * 1024,
      let peer = session.connectedPeers.first, session.connectedPeers.count == 1
    else { throw IdentityMoveChannelError.unavailable }
    try session.send(data, toPeers: [peer], with: .reliable)
  }

  private func found(_ peer: MCPeerID) {
    guard role == .destination else { return }
    discoveredPeers[peer.displayName] = peer
    discoveredPeerNames = discoveredPeers.keys.sorted()
  }

  private func lost(_ peer: MCPeerID) {
    discoveredPeers.removeValue(forKey: peer.displayName)
    discoveredPeerNames = discoveredPeers.keys.sorted()
  }

  private func changed(_ state: MCSessionState) {
    if state == .connected {
      isConnected = true
      onConnected?()
    } else if state == .notConnected {
      isConnected = false
      onDisconnected?()
    }
  }
}

extension IdentityMoveTransport: MCSessionDelegate {
  nonisolated func session(
    _: MCSession, peer _: MCPeerID, didChange state: MCSessionState
  ) {
    DispatchQueue.main.async { self.changed(state) }
  }

  nonisolated func session(_: MCSession, didReceive data: Data, fromPeer _: MCPeerID) {
    DispatchQueue.main.async { self.onData?(data) }
  }

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

extension IdentityMoveTransport: MCNearbyServiceAdvertiserDelegate {
  nonisolated func advertiser(
    _: MCNearbyServiceAdvertiser, didReceiveInvitationFromPeer _: MCPeerID,
    withContext _: Data?, invitationHandler: @escaping (Bool, MCSession?) -> Void
  ) {
    switch role {
    case .source:
      let available = session.connectedPeers.isEmpty
      invitationHandler(available, available ? session : nil)
    case .destination: invitationHandler(false, nil)
    }
  }
}

extension IdentityMoveTransport: MCNearbyServiceBrowserDelegate {
  // MultipeerConnectivity requires this optional discovery-info parameter.
  // swiftlint:disable discouraged_optional_collection
  nonisolated func browser(
    _: MCNearbyServiceBrowser, foundPeer peerID: MCPeerID,
    withDiscoveryInfo _: [String: String]?
  ) {
    DispatchQueue.main.async { self.found(peerID) }
  }
  // swiftlint:enable discouraged_optional_collection

  nonisolated func browser(_: MCNearbyServiceBrowser, lostPeer peerID: MCPeerID) {
    DispatchQueue.main.async { self.lost(peerID) }
  }
}
