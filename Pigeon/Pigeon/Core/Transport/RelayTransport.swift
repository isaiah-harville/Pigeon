//
//  RelayTransport.swift
//  Pigeon
//
//  The internet `Transport`: delivers the same end-to-end ciphertext to peers
//  who are out of Bluetooth range, via one or more zero-knowledge relays (see
//  `pigeon-relay/` and SECURITY_MODEL §6.1). It is a dumb pipe like BLE — it moves
//  opaque bytes and never decrypts anything.
//
//  Addressing: a direct message carries its recipient's identity key, so we
//  deposit it only on *that* recipient's mailbox — on the relays they advertise
//  (federation: relay URLs travel in the contact's QR bundle). A contact that
//  advertises no relays is simply unreachable over the internet: we never fall
//  back to our own relays, because the recipient doesn't read them, so the
//  deposit could never be delivered. Address-less flood packets
//  (`recipient == nil`) are not sent over the internet at all.
//
//  To receive, we subscribe to our own mailbox on our own relays and prove
//  ownership by signing a server challenge with our identity key — so a relay
//  only ever learns public keys, never content. We also hold publish-only
//  connections to our contacts' relays so we can deposit to them.
//

import Foundation
import Network

@MainActor
@Observable
final class RelayTransport: Transport {

  /// Coarse link state for the UI (distinct from the BLE-shaped `status`).
  enum LinkState: Equatable {
    case disabled  // no relays configured
    case connecting  // configured, not yet authenticated anywhere
    case online  // authenticated to at least one relay
    case failed  // configured but currently unreachable
    case incompatible  // every configured receiving relay has a disjoint protocol range
  }

  let kind: TransportKind? = .relay
  private(set) var linkState: LinkState = .disabled
  private(set) var log: [String] = []

  /// Hosts of our own relays we're currently authenticated to (can receive on),
  /// for display in the UI. Empty when offline. Stored (not computed) so it is
  /// observed by SwiftUI: readiness lives on the `Connection` reference type
  /// inside `connections`, whose mutations `@Observable` can't see, so the chat
  /// header would otherwise never refresh when a relay comes up or drops.
  /// Recomputed from `connections` on every readiness change in `refreshLinkState`.
  private(set) var onlineRelayHosts: [String] = []

  /// Every relay endpoint we currently hold a *ready* connection to — our own
  /// (authenticated, for receiving) **and** publish-only contact relays (for
  /// depositing). Stored (so `@Observable` sees it) and recomputed in
  /// `refreshLinkState`, because readiness lives on the `Connection` reference
  /// type inside `connections`, which `@Observable` can't see. Drives the chat
  /// header's live "can a message actually go out over the relay" indicator,
  /// which depends on reaching the *recipient's* relay — not just our own.
  private(set) var readyRelayURLs: Set<URL> = []
  /// Endpoints that explicitly rejected this app's relay protocol range. They
  /// never become ready and are excluded from our advertised contact card.
  private(set) var incompatibleRelayURLs: Set<URL> = []
  var onCompatibilityChange: ((Set<URL>) -> Void)?

  // Relays are not "peers"; the headline status/peer-count stay BLE's.
  var status: TransportStatus { .idle }
  var connectedPeerCount: Int { 0 }
  var onMessage: ((_ message: Data, _ peerID: String) -> TransportMessageDisposition)?
  /// Fired when a relay connection comes up (we can publish to it now), so the
  /// session layer flushes pending work on the event rather than on a timer.
  var onConnectivity: (() -> Void)?

  /// Our own mailbox address: lowercase hex of our Ed25519 identity public key.
  private let mailboxHex: String
  /// Signs a relay challenge nonce with our identity key (kept in the Keychain;
  /// the transport never holds key material itself).
  private let sign: (Data) -> Data?
  /// Supplies the current contact identity keys (so we know whose relays to keep
  /// publish connections open to). Set after construction so the owner can
  /// capture itself safely.
  var recipients: () -> [Data] = { [] }
  /// Resolves a recipient's advertised relay endpoints (from their QR bundle).
  var relaysForRecipient: (Data) -> [URL] = { _ in [] }
  /// The relay the user prefers for a given recipient's conversation, or `nil`
  /// for automatic. When set and reachable we deposit there; otherwise we fall
  /// back to the contact's other relays.
  var preferredRelayForRecipient: (Data) -> URL? = { _ in nil }

  /// Our APNs device token (lowercase hex) when the user has opted into push
  /// wake-ups, else nil. Bound to our mailbox on each of our *own* relays so the
  /// official relay's gateway can wake a suspended or terminated app to drain
  /// it. Never sent on publish-only contact relays — only relays we authenticate
  /// to (which already know our mailbox) ever see it. Relays without a push
  /// gateway reply with an error we ignore (best-effort, exactly as before).
  var pushToken: String?
  private(set) var isEnabled: Bool

  /// Our own relays — where we subscribe to receive. We advertise these to
  /// contacts so they can deposit to us.
  var myRelays: [URL] = []

  private let urlSession = URLSession(configuration: .default)
  var connections: [URL: Connection] = [:]

  /// Outbound deposits without a positive relay receipt, held for re-send when
  /// a usable relay link comes up.
  /// Without this an envelope generated while our publish-only
  /// socket to the recipient's relay isn't ready yet — notably a delivery ack a
  /// freshly relaunched device emits before its links are up — is dropped and
  /// never retried, so "delivered" can wedge permanently. App *messages* survive
  /// because the session layer re-drives `pending` ones on connectivity, but
  /// acks and control envelopes aren't pending; this covers them too. The mesh's
  /// UUID/`SeenCache` dedup keeps any resulting duplicate harmless. Bounded so a
  /// peer that stays unreachable can't grow it without limit.
  var pendingDeposits = DepositQueue(bound: 256)
  var unconfirmedDepositCount = 0
  @ObservationIgnored var depositRetryTask: Task<Void, Never>?

  /// Watches the OS network path so relays reconnect the instant connectivity
  /// returns (Wi-Fi ↔ cellular, airplane mode off), rather than waiting out the
  /// supervise backoff. `@ObservationIgnored` — it drives reconnects, not UI.
  @ObservationIgnored let pathMonitor = NWPathMonitor()
  /// Whether the OS last reported a usable path. Tracked so we react only to the
  /// *transition* back to reachable, ignoring interface flaps while already up.
  @ObservationIgnored var networkAvailable = true

  /// One relay endpoint: its socket plus the supervising reconnect task.
  /// `authenticate` is true for our own relays (we subscribe + prove ownership
  /// to read); false for contacts' relays we only deposit to.
  final class Connection {
    let authenticate: Bool
    var socket: URLSessionWebSocketTask?
    var task: Task<Void, Never>?
    var ready = false
    init(authenticate: Bool) { self.authenticate = authenticate }
  }

  convenience init(mailboxHex: String, sign: @escaping (Data) -> Data?) {
    self.init(mailboxHex: mailboxHex, enabled: true, sign: sign)
  }

  init(mailboxHex: String, enabled: Bool, sign: @escaping (Data) -> Data?) {
    self.mailboxHex = mailboxHex
    isEnabled = enabled
    self.sign = sign
    startPathMonitor()
  }

  deinit { pathMonitor.cancel() }

  // MARK: - Configuration

  /// (Re)connects to our own relays (`myRelays`, for receiving) plus every
  /// contact's advertised relays (for depositing), dropping any endpoint no
  /// longer in that union. Call whenever our relays or the contact set change.
  func reconfigure(_ myRelays: [URL]) {
    self.myRelays = myRelays
    guard isEnabled else {
      refreshLinkState()
      return
    }
    // Disabling every receiving relay is the user's global serverless choice.
    // Do not keep publish-only sockets to contacts' relays in that state.
    let contactRelays = myRelays.isEmpty ? [] : recipients().flatMap { relaysForRecipient($0) }
    let wanted = Self.wantedConnections(myRelays: myRelays, contactRelays: contactRelays)
    let previousIncompatible = incompatibleRelayURLs
    incompatibleRelayURLs = Self.retainedIncompatibleRelays(
      current: incompatibleRelayURLs, wanted: wanted)

    for (url, connection) in connections where !wanted.contains(url) {
      connection.task?.cancel()
      connection.socket?.cancel(with: .goingAway, reason: nil)
      connections[url] = nil
    }
    for url in wanted {
      let shouldAuth = myRelays.contains(url)
      let retryCompatibility = incompatibleRelayURLs.contains(url)
      if let existing = connections[url] {
        if existing.authenticate == shouldAuth && !retryCompatibility { continue }
        existing.task?.cancel()
        existing.socket?.cancel(with: .goingAway, reason: nil)
        connections[url] = nil
      }
      let connection = Connection(authenticate: shouldAuth)
      connections[url] = connection
      connection.task = Task { [weak self] in await self?.supervise(url) }
    }
    if previousIncompatible != incompatibleRelayURLs {
      onCompatibilityChange?(incompatibleRelayURLs)
    }
    refreshLinkState()
  }

  // MARK: - Transport

  func refreshConnections() {
    guard isEnabled else { return }
    guard !connections.isEmpty || !myRelays.isEmpty else { return }
    let configuredRelays = myRelays
    // Pull-to-refresh intentionally tears down every relay socket, including
    // healthy publish-only contact relays, so reconfigure starts fresh.
    for connection in connections.values {
      connection.task?.cancel()
      connection.socket?.cancel(with: .goingAway, reason: nil)
    }
    connections.removeAll()
    note(.transportRefresh)
    reconfigure(configuredRelays)
  }

  func setEnabled(_ enabled: Bool) {
    guard isEnabled != enabled else { return }
    isEnabled = enabled
    if enabled {
      reconfigure(myRelays)
    } else {
      for connection in connections.values {
        connection.task?.cancel()
        connection.socket?.cancel(with: .goingAway, reason: nil)
      }
      connections.removeAll()
      onlineRelayHosts = []
      readyRelayURLs = []
      linkState = .disabled
    }
  }

}

// MARK: - Connection lifecycle

extension RelayTransport {

  /// Keeps one relay connected, reconnecting with capped backoff until the
  /// endpoint is removed (the task is cancelled).
  func supervise(_ url: URL) async {
    var backoff = 1.0
    while !Task.isCancelled {
      do {
        try await serve(url)
        backoff = 1.0
      } catch RelayError.incompatible {
        guard !Task.isCancelled else { break }
        connections[url]?.ready = false
        markIncompatible(url)
        note(.relayIncompatible)
        refreshLinkState()
        break
      } catch {
        guard !Task.isCancelled else { break }
        // A connection that had come up and then dropped (e.g. an airplane-mode
        // blip) should reconnect promptly, so only grow the backoff for endpoints
        // that never became ready in the first place.
        let wasReady = connections[url]?.ready == true
        connections[url]?.ready = false
        note(.relayOffline)
        refreshLinkState()
        if wasReady { backoff = 1.0 }
      }
      if Task.isCancelled { break }
      try? await Task.sleep(for: .seconds(min(backoff, 30)))
      backoff = min(backoff * 2, 30)
    }
  }

  /// Opens a socket, authenticates as the mailbox owner, then delivers inbound
  /// envelopes until the connection drops (which throws and triggers a retry).
  private func serve(_ url: URL) async throws {
    guard let connection = connections[url] else { return }
    let socket = urlSession.webSocketTask(with: url)
    connection.socket = socket
    socket.resume()

    try await negotiateProtocol(with: socket)
    markCompatible(url)

    if connection.authenticate { try await authenticate(socket) }

    connection.ready = true
    note(.relayReady)
    refreshLinkState()
    flushPendingDeposits()  // re-drive deposits queued while no relay was ready
    onConnectivity?()  // can publish to this relay now — flush pending work

    // Heartbeat alongside the blocking receive loop: a half-open socket (network
    // dropped and returned without a clean close) otherwise stays "ready" forever
    // while deposits vanish. A missed pong cancels the socket so receive() throws
    // and supervise() reconnects.
    let heartbeat = Task { [weak self] in await self?.keepAlive(socket) }
    defer { heartbeat.cancel() }

    while !Task.isCancelled {
      let message = try await receive(socket)
      switch Self.classifyInbound(message) {
      case .envelope(let envelope):
        consume(envelope, from: url, over: socket)
      case .published(let requestID):
        if pendingDeposits.acknowledge(requestID: requestID) {
          unconfirmedDepositCount = pendingDeposits.count
          if pendingDeposits.isEmpty {
            depositRetryTask?.cancel()
            depositRetryTask = nil
          }
        }
      case .error(_, let requestID):
        note(.relayError)
        if let requestID,
          pendingDeposits.deposits.contains(where: { $0.requestID == requestID })
        {
          scheduleDepositRetry()
        }
      case .ignored:
        break
      }
    }
  }

  private func consume(
    _ envelope: InboundFrame.Envelope, from url: URL, over socket: URLSessionWebSocketTask
  ) {
    let disposition =
      onMessage?(envelope.ciphertext, "relay:\(host(url))") ?? .retryAfterRestart
    // Delete only after the session layer confirms both message and ratchet are durable.
    if Self.shouldAcknowledge(disposition) {
      send(socket, ["type": "ack", "id": envelope.id])
    }
  }

  static func shouldAcknowledge(_ disposition: TransportMessageDisposition) -> Bool {
    disposition == .consumed
  }

  private func authenticate(_ socket: URLSessionWebSocketTask) async throws {
    send(socket, ["type": "subscribe", "mailbox": mailboxHex])
    let challenge = try await receive(socket)
    guard challenge["type"] as? String == "challenge",
      let nonceB64 = challenge["nonce"] as? String,
      let nonce = Data(base64Encoded: nonceB64),
      let signature = sign(nonce)
    else { throw RelayError.handshake }
    send(socket, ["type": "auth", "signature": signature.base64EncodedString()])
    let result = try await receive(socket)
    guard result["type"] as? String == "ok" else { throw RelayError.handshake }
    if let token = pushToken {
      send(socket, ["type": "register_push", "token": token])
    }
  }

  // MARK: - Framing

  func send(_ socket: URLSessionWebSocketTask, _ object: [String: Any]) {
    guard let data = try? JSONSerialization.data(withJSONObject: object) else { return }
    guard let text = String(bytes: data, encoding: .utf8) else { return }
    Task { try? await socket.send(.string(text)) }
  }

  private func negotiateProtocol(with socket: URLSessionWebSocketTask) async throws {
    send(
      socket,
      [
        "type": "hello",
        "min_protocol_version": Self.minimumProtocolVersion,
        "max_protocol_version": Self.maximumProtocolVersion,
      ])
    let result = try await receive(socket)
    guard result["type"] as? String == "compatible",
      let selected = result["protocol_version"] as? Int,
      (Self.minimumProtocolVersion...Self.maximumProtocolVersion).contains(selected)
    else {
      if result["type"] as? String == "incompatible" { throw RelayError.incompatible }
      throw RelayError.handshake
    }
  }

  private func receive(_ socket: URLSessionWebSocketTask) async throws -> [String: Any] {
    switch try await socket.receive() {
    case .string(let text):
      guard let data = text.data(using: .utf8),
        let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
      else { throw RelayError.protocolError }
      return object
    case .data(let data):
      guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw RelayError.protocolError
      }
      return object
    @unknown default:
      throw RelayError.protocolError
    }
  }

  // MARK: - Helpers

  /// Recomputes the observable link state from `connections`. Called on every
  /// readiness change (a relay coming up or dropping, reconfigure), so the UI
  /// stays live. Link state reflects our own mailbox relays (whether we can
  /// *receive*); publish-only connections to contacts' relays don't change it.
  private func refreshLinkState() {
    guard isEnabled else {
      onlineRelayHosts = []
      readyRelayURLs = []
      linkState = .disabled
      return
    }
    onlineRelayHosts = myRelays.compactMap { connections[$0]?.ready == true ? host($0) : nil }
    readyRelayURLs = Set(
      connections.filter { $0.value.ready && $0.value.socket != nil }.map(\.key))
    if myRelays.isEmpty {
      linkState = .disabled
    } else if !onlineRelayHosts.isEmpty {
      linkState = .online
    } else if myRelays.allSatisfy({ incompatibleRelayURLs.contains($0) }) {
      linkState = .incompatible
    } else {
      linkState = .connecting
    }
  }

  private func host(_ url: URL) -> String { url.host ?? url.absoluteString }

  private func markIncompatible(_ url: URL) {
    guard incompatibleRelayURLs.insert(url).inserted else { return }
    onCompatibilityChange?(incompatibleRelayURLs)
  }

  private func markCompatible(_ url: URL) {
    guard incompatibleRelayURLs.remove(url) != nil else { return }
    onCompatibilityChange?(incompatibleRelayURLs)
  }

  func note(_ event: DiagnosticEvent) {
    DiagnosticLog.record(event, in: &log, limit: 100)
  }

  static func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
  }
}
