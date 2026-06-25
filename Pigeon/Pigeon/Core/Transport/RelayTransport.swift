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

  // Relays are not "peers"; the headline status/peer-count stay BLE's.
  var status: TransportStatus { .idle }
  var connectedPeerCount: Int { 0 }
  var onMessage: ((_ message: Data, _ peerID: String) -> Void)?
  /// Fired when a relay connection comes up (we can publish to it now), so the
  /// session layer flushes pending work on the event rather than on a timer (#82).
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

  /// Whether we can durably take responsibility for a delivered envelope right
  /// now. When false (app locked — we can't decrypt or persist), we still
  /// surface the envelope for notification but do NOT ack it, so the relay
  /// retains its copy until we can process it after unlock. Set by the owner.
  var canConsume: () -> Bool = { true }

  /// Our APNs device token (lowercase hex) when the user has opted into push
  /// wake-ups, else nil. Bound to our mailbox on each of our *own* relays so the
  /// official relay's gateway can wake a suspended or terminated app to drain
  /// it. Never sent on publish-only contact relays — only relays we authenticate
  /// to (which already know our mailbox) ever see it. Relays without a push
  /// gateway reply with an error we ignore (best-effort, exactly as before).
  private(set) var pushToken: String?

  /// Our own relays — where we subscribe to receive. We advertise these to
  /// contacts so they can deposit to us.
  private var myRelays: [URL] = []

  private let urlSession = URLSession(configuration: .default)
  private var connections: [URL: Connection] = [:]

  /// Outbound deposits that found no *ready* relay when first attempted, held for
  /// re-send the instant a usable relay link comes up).
  /// Without this an envelope generated while our publish-only
  /// socket to the recipient's relay isn't ready yet — notably a delivery ack a
  /// freshly relaunched device emits before its links are up — is dropped and
  /// never retried, so "delivered" can wedge permanently. App *messages* survive
  /// because the session layer re-drives `pending` ones on connectivity, but
  /// acks and control envelopes aren't pending; this covers them too. The mesh's
  /// UUID/`SeenCache` dedup keeps any resulting duplicate harmless. Bounded so a
  /// peer that stays unreachable can't grow it without limit.
  private var pendingDeposits = DepositQueue(bound: 256)

  /// Watches the OS network path so relays reconnect the instant connectivity
  /// returns (Wi-Fi ↔ cellular, airplane mode off), rather than waiting out the
  /// supervise backoff (#76). `@ObservationIgnored` — it drives reconnects, not UI.
  @ObservationIgnored private let pathMonitor = NWPathMonitor()
  /// Whether the OS last reported a usable path. Tracked so we react only to the
  /// *transition* back to reachable, ignoring interface flaps while already up.
  @ObservationIgnored private var networkAvailable = true

  /// One relay endpoint: its socket plus the supervising reconnect task.
  /// `authenticate` is true for our own relays (we subscribe + prove ownership
  /// to read); false for contacts' relays we only deposit to.
  private final class Connection {
    let authenticate: Bool
    var socket: URLSessionWebSocketTask?
    var task: Task<Void, Never>?
    var ready = false
    init(authenticate: Bool) { self.authenticate = authenticate }
  }

  init(mailboxHex: String, sign: @escaping (Data) -> Data?) {
    self.mailboxHex = mailboxHex
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
    let contactRelays = recipients().flatMap { relaysForRecipient($0) }
    let wanted = Self.wantedConnections(myRelays: myRelays, contactRelays: contactRelays)

    for (url, connection) in connections where !wanted.contains(url) {
      connection.task?.cancel()
      connection.socket?.cancel(with: .goingAway, reason: nil)
      connections[url] = nil
    }
    for url in wanted {
      let shouldAuth = myRelays.contains(url)
      if let existing = connections[url] {
        if existing.authenticate == shouldAuth { continue }  // role unchanged
        existing.task?.cancel()
        existing.socket?.cancel(with: .goingAway, reason: nil)
        connections[url] = nil
      }
      let connection = Connection(authenticate: shouldAuth)
      connections[url] = connection
      connection.task = Task { [weak self] in await self?.supervise(url) }
    }
    refreshLinkState()
  }

  // MARK: - Transport

  func refreshConnections() {
    guard !connections.isEmpty || !myRelays.isEmpty else { return }
    let configuredRelays = myRelays
    // Pull-to-refresh intentionally tears down every relay socket, including
    // healthy publish-only contact relays, so reconfigure starts fresh.
    for connection in connections.values {
      connection.task?.cancel()
      connection.socket?.cancel(with: .goingAway, reason: nil)
    }
    connections.removeAll()
    note("Relay refresh requested")
    reconfigure(configuredRelays)
  }

  // MARK: - Connection lifecycle

  /// Keeps one relay connected, reconnecting with capped backoff until the
  /// endpoint is removed (the task is cancelled).
  private func supervise(_ url: URL) async {
    var backoff = 1.0
    while !Task.isCancelled {
      do {
        try await serve(url)
        backoff = 1.0
      } catch {
        guard !Task.isCancelled else { break }
        // A connection that had come up and then dropped (e.g. an airplane-mode
        // blip) should reconnect promptly, so only grow the backoff for endpoints
        // that never became ready in the first place.
        let wasReady = connections[url]?.ready == true
        connections[url]?.ready = false
        note("Relay \(host(url)) offline; retrying")
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

    if connection.authenticate {
      // Our own relay: prove we own our mailbox (subscribe → sign challenge →
      // auth) so we can read it. A publish-only connection skips this.
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
      // We can read our mailbox now; if push wake-up is opted in, bind our APNs
      // device token so this relay can wake us while suspended/terminated.
      if let token = pushToken {
        send(socket, ["type": "register_push", "token": token])
      }
    }

    connection.ready = true
    note("Relay \(host(url)) \(connection.authenticate ? "online" : "ready")")
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
        onMessage?(envelope.ciphertext, "relay:\(host(url))")
        // Ack (and so delete from the mailbox) only once we can durably handle
        // it. While locked we skip the ack, leaving the relay to retain and
        // re-deliver the envelope after the user unlocks.
        if canConsume() {
          send(socket, ["type": "ack", "id": envelope.id])
        }
      case .error(let detail):
        note("Relay \(host(url)): \(detail)")
      case .ignored:
        break
      }
    }
  }

  // MARK: - Framing

  private func send(_ socket: URLSessionWebSocketTask, _ object: [String: String]) {
    guard let data = try? JSONSerialization.data(withJSONObject: object) else { return }
    guard let text = String(bytes: data, encoding: .utf8) else { return }
    Task { try? await socket.send(.string(text)) }
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
    onlineRelayHosts = myRelays.compactMap { connections[$0]?.ready == true ? host($0) : nil }
    readyRelayURLs = Set(
      connections.filter { $0.value.ready && $0.value.socket != nil }.map(\.key))
    if myRelays.isEmpty {
      linkState = .disabled
    } else if !onlineRelayHosts.isEmpty {
      linkState = .online
    } else {
      linkState = .connecting
    }
  }

  private func host(_ url: URL) -> String { url.host ?? url.absoluteString }

  private func note(_ message: String) {
    log.append(message)
    if log.count > 100 { log.removeFirst(log.count - 100) }
  }

  private static func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
  }
}

// MARK: - Reachability & post-unlock re-flush

extension RelayTransport {

  /// Whether a message addressed to a contact who advertises `recipientRelays`
  /// can actually be deposited right now: we hold a ready connection to at least
  /// one relay they advertise. Mirrors `broadcast`'s target selection (any
  /// advertised relay that's ready), so the chat header's "reachable" cue
  /// reflects reaching the *recipient's* mailbox rather than merely our own
  /// relay being online. Empty `recipientRelays` ⇒ unreachable over the relay.
  func canReach(recipientRelays: [URL]) -> Bool {
    recipientRelays.contains { readyRelayURLs.contains($0) }
  }

  /// Reconnects our own (authenticated) relays so their mailbox queues are
  /// re-flushed. Called right after unlock: an envelope that arrived while we
  /// were locked was surfaced for notification but deliberately not acked (we
  /// couldn't durably consume it), so the relay still holds it. A live socket
  /// won't re-send on its own, so we re-subscribe to pull the retained copy now
  /// that we can process and ack it — instead of leaving it in the mailbox until
  /// some future reconnect. Publish-only contact relays are left untouched.
  func resubscribeOwnRelays() {
    for (url, connection) in connections where connection.authenticate {
      connection.task?.cancel()
      connection.socket?.cancel(with: .goingAway, reason: nil)
      let fresh = Connection(authenticate: true)
      connections[url] = fresh
      fresh.task = Task { [weak self] in await self?.supervise(url) }
    }
  }
}

// MARK: - Network path (proactive reconnect, #76)

extension RelayTransport {

  /// Starts watching the OS network path; a transition back to a usable path
  /// reconnects any relay that's currently down.
  func startPathMonitor() {
    pathMonitor.pathUpdateHandler = { [weak self] path in
      let available = path.status == .satisfied
      Task { @MainActor [weak self] in self?.handlePathChange(available: available) }
    }
    pathMonitor.start(queue: DispatchQueue(label: "com.isaiah-harville.Pigeon.relay.path"))
  }

  private func handlePathChange(available: Bool) {
    defer { networkAvailable = available }
    // Act only on the down→up transition; an interface change while already
    // online doesn't warrant tearing healthy sockets down.
    guard available, !networkAvailable else { return }
    reconnectStalled()
  }

  /// Immediately restarts the supervise loop for every relay that isn't currently
  /// connected, so a returning network reconnects now instead of after backoff.
  /// Healthy connections are left untouched. Keys are snapshotted first so the
  /// dictionary isn't mutated mid-iteration.
  private func reconnectStalled() {
    let stalled = connections.filter { !$0.value.ready }.map { ($0.key, $0.value.authenticate) }
    guard !stalled.isEmpty else { return }
    for (url, authenticate) in stalled {
      connections[url]?.task?.cancel()
      connections[url]?.socket?.cancel(with: .goingAway, reason: nil)
      let fresh = Connection(authenticate: authenticate)
      connections[url] = fresh
      fresh.task = Task { [weak self] in await self?.supervise(url) }
    }
    note("Network restored; reconnecting \(stalled.count) relay(s)")
  }
}

// MARK: - Heartbeat

extension RelayTransport {

  /// Periodically pings a live socket; a missed pong cancels it so the blocking
  /// `receive()` in `serve` throws and `supervise` reconnects. This is what
  /// rescues a connection silently killed mid-stream (the airplane-mode case)
  /// rather than leaving it "ready" with every deposit dropped on the floor.
  func keepAlive(_ socket: URLSessionWebSocketTask) async {
    while !Task.isCancelled {
      try? await Task.sleep(for: .seconds(15))
      guard !Task.isCancelled else { return }
      if await Self.isAlive(socket) { continue }
      socket.cancel(with: .goingAway, reason: nil)  // unblock receive() → reconnect
      return
    }
  }

  /// Sends a WebSocket ping and waits for the pong, treating no reply within a
  /// few seconds as a dead connection. `sendPing` has no built-in pong timeout,
  /// so we race it against a sleep — essential for spotting a half-open socket
  /// that would otherwise accept `sendPing` writes that never arrive.
  nonisolated static func isAlive(_ socket: URLSessionWebSocketTask) async -> Bool {
    await withTaskGroup(of: Bool.self) { group in
      group.addTask {
        await withCheckedContinuation { continuation in
          socket.sendPing { continuation.resume(returning: $0 == nil) }
        }
      }
      group.addTask {
        try? await Task.sleep(for: .seconds(8))
        return false
      }
      let alive = await group.next() ?? false
      group.cancelAll()
      return alive
    }
  }
}

// MARK: - Push wake-up registration

extension RelayTransport {

  /// Sets (or clears) our APNs device token and reconciles it across our live,
  /// authenticated relay connections: a rotated or cleared token is unregistered
  /// and the new one registered. New connections pick the current token up at
  /// auth time in `serve`. Only authenticated (own-mailbox) relays are touched.
  func setPushToken(_ token: String?) {
    let old = pushToken
    guard old != token else { return }
    pushToken = token
    for connection in connections.values where connection.authenticate && connection.ready {
      guard let socket = connection.socket else { continue }
      if let old { send(socket, ["type": "unregister_push", "token": old]) }
      if let token { send(socket, ["type": "register_push", "token": token]) }
    }
  }
}

// MARK: - Send (deposit + send-side store-and-forward, #106)

extension RelayTransport {

  func broadcast(_ message: Data, to recipient: Data?) {
    // Only directly-addressed messages go over the relay; flood packets don't.
    guard let recipient else { return }
    // No ready relay for this recipient yet: hold the deposit and retry on the
    // next connectivity event rather than dropping it.
    guard attemptDeposit(message, to: recipient) else {
      enqueueDeposit(message, to: recipient)
      return
    }
  }

  /// Tries to deposit `message` to a recipient's reachable relays right now.
  /// Returns `true` if it was published to at least one ready relay, `false` if
  /// none were ready (so the caller can queue it for later).
  @discardableResult
  private func attemptDeposit(_ message: Data, to recipient: Data) -> Bool {
    let preferred = preferredRelayForRecipient(recipient)
    let targets = Self.deliveryTargets(
      preferred: preferred, advertised: relaysForRecipient(recipient))
    let ready = targets.filter { connections[$0]?.ready == true && connections[$0]?.socket != nil }
    guard !ready.isEmpty else { return false }

    // Honor an explicitly chosen relay when it's reachable; otherwise fan out to
    // every reachable relay so a dead one doesn't strand the message.
    let chosen: [URL]
    if let preferred, ready.contains(preferred) {
      chosen = [preferred]
    } else {
      chosen = ready
    }

    let ciphertext = message.base64EncodedString()
    let recipientHex = Self.hex(recipient)
    var published = false
    for url in chosen {
      guard let socket = connections[url]?.socket else { continue }
      send(socket, ["type": "publish", "recipient": recipientHex, "ciphertext": ciphertext])
      published = true
    }
    return published
  }

  /// Holds a deposit that found no ready relay, dropping the oldest once the
  /// bound is reached so an unreachable recipient can't grow the queue without
  /// limit. Re-driven by `flushPendingDeposits` on the next connectivity event.
  private func enqueueDeposit(_ message: Data, to recipient: Data) {
    pendingDeposits.enqueue(.init(recipient: recipient, message: message))
  }

  /// Re-attempts every queued deposit, keeping the ones that still find no ready
  /// relay. Called from `serve` when a relay link comes up, so acks and control
  /// envelopes deposited while offline are delivered the moment a usable link
  /// appears — mirroring the session layer's `pending`-message re-drive.
  func flushPendingDeposits() {
    pendingDeposits.flush { attemptDeposit($0.message, to: $0.recipient) }
  }
}

// MARK: - Pure routing decisions (unit-tested)

extension RelayTransport {

  /// Where to deposit ciphertext for a recipient: the relays *they* advertise
  /// (federation). Only a relay the recipient actually subscribes to can deliver
  /// to them, so a contact that advertises none yields no targets — we do **not**
  /// fall back to our own relays. Depositing there is undeliverable (the
  /// recipient never reads our mailbox relays) and would worse-than-uselessly
  /// mask the failure by making the send look "sent". Address-less sends pass
  /// `advertised == []` and likewise target nothing.
  static func deliveryTargets(advertised: [URL]) -> [URL] {
    deliveryTargets(preferred: nil, advertised: advertised)
  }

  /// As above, but ordered to honor a user-chosen relay for this conversation:
  /// the preferred relay first (when it's one the recipient advertises), then
  /// their remaining relays, so a dead preferred falls through to the rest.
  static func deliveryTargets(preferred: URL?, advertised: [URL]) -> [URL] {
    guard let preferred, advertised.contains(preferred) else { return advertised }
    return [preferred] + advertised.filter { $0 != preferred }
  }

  /// The relays we keep connected: our own (to receive) plus every contact's
  /// advertised relays (to deposit), de-duplicated and order-preserving.
  static func wantedConnections(myRelays: [URL], contactRelays: [URL]) -> [URL] {
    var wanted: [URL] = []
    for url in myRelays + contactRelays where !wanted.contains(url) { wanted.append(url) }
    return wanted
  }

  /// A classified inbound server frame. Malformed envelopes (missing/!base64
  /// fields) and unknown types become `.ignored` rather than crashing.
  enum InboundFrame: Equatable {
    case envelope(Envelope)
    case error(String)
    case ignored

    /// A delivered ciphertext blob and the id used to ack it.
    struct Envelope: Equatable {
      let id: String
      let ciphertext: Data
    }
  }

  static func classifyInbound(_ message: [String: Any]) -> InboundFrame {
    switch message["type"] as? String {
    case "envelope":
      guard let id = message["id"] as? String,
        let ciphertextB64 = message["ciphertext"] as? String,
        let data = Data(base64Encoded: ciphertextB64)
      else { return .ignored }
      return .envelope(InboundFrame.Envelope(id: id, ciphertext: data))
    case "error":
      return .error(message["message"] as? String ?? "error")
    default:
      return .ignored
    }
  }
}

private enum RelayError: Error {
  case handshake
  case protocolError
}
