import Foundation
import Network

// MARK: - Reachability & post-unlock re-flush

extension RelayTransport {

  /// Whether a message addressed to a contact who advertises `recipientRelays`
  /// can actually be deposited right now: we hold a ready connection to at least
  /// one relay they advertise. Mirrors `broadcast`'s target selection (any
  /// advertised relay that's ready), so the chat header's "reachable" cue
  /// reflects reaching the *recipient's* mailbox rather than merely our own
  /// relay being online. Empty `recipientRelays` ⇒ unreachable over the relay.
  func canReach(recipientRelays: [URL]) -> Bool {
    !myRelays.isEmpty && recipientRelays.contains { readyRelayURLs.contains($0) }
  }

  /// Reconnects our own (authenticated) relays so their mailbox queues are
  /// re-flushed. Called right after unlock: an envelope that arrived while we
  /// were locked was surfaced for notification but deliberately not acked (we
  /// couldn't durably consume it), so the relay still holds it. A live socket
  /// won't re-send on its own, so we re-subscribe to pull the retained copy now
  /// that we can process and ack it — instead of leaving it in the mailbox until
  /// some future reconnect. Publish-only contact relays are left untouched.
  func resubscribeOwnRelays() {
    guard isEnabled else { return }
    for (url, connection) in connections where connection.authenticate {
      connection.task?.cancel()
      connection.socket?.cancel(with: .goingAway, reason: nil)
      let fresh = Connection(authenticate: true)
      connections[url] = fresh
      fresh.task = Task { [weak self] in await self?.supervise(url) }
    }
  }
}

// MARK: - Network path (proactive reconnect)

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
    guard isEnabled, available, !networkAvailable else { return }
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
    note(.networkRestored)
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

}

// MARK: - Push wake-up registration

extension RelayTransport {

  /// Best-effort removal of the APNs token from every reachable authenticated
  /// mailbox before an identity is retired. Awaiting each socket write ensures
  /// teardown does not cancel a merely queued unregister frame. Offline relays
  /// cannot be reached here and must expire stale registrations server-side.
  func unregisterPushForCleanSlate() async {
    guard let token = pushToken else { return }
    pushToken = nil
    for connection in connections.values where connection.authenticate && connection.ready {
      guard let socket = connection.socket,
        let data = try? JSONSerialization.data(
          withJSONObject: ["type": "unregister_push", "token": token]),
        let text = String(bytes: data, encoding: .utf8)
      else { continue }
      try? await socket.send(.string(text))
    }
  }

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

// MARK: - Send (deposit + send-side store-and-forward)

extension RelayTransport {

  func broadcast(_ message: Data, to recipient: Data?) {
    guard isEnabled, !myRelays.isEmpty else { return }
    // Only directly-addressed messages go over the relay; flood packets don't.
    guard let recipient else { return }
    let deposit = DepositQueue.Deposit(
      requestID: UUID().uuidString, recipient: recipient, message: message)
    pendingDeposits.enqueue(deposit)
    unconfirmedDepositCount = pendingDeposits.count
    _ = attemptDeposit(deposit)
    scheduleDepositRetry()
  }

  /// Tries to deposit `message` to a recipient's reachable relays right now.
  /// Returns whether at least one socket was ready. This does not confirm a
  /// deposit; its request remains queued until a `published` receipt arrives.
  @discardableResult
  private func attemptDeposit(_ deposit: DepositQueue.Deposit) -> Bool {
    let preferred = preferredRelayForRecipient(deposit.recipient)
    let targets = Self.deliveryTargets(
      preferred: preferred, advertised: relaysForRecipient(deposit.recipient))
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

    let ciphertext = deposit.message.base64EncodedString()
    let recipientHex = Self.hex(deposit.recipient)
    var published = false
    for url in chosen {
      guard let socket = connections[url]?.socket else { continue }
      send(
        socket,
        [
          "type": "publish", "recipient": recipientHex,
          "ciphertext": ciphertext, "request_id": deposit.requestID,
        ])
      published = true
    }
    return published
  }

  /// Re-attempts every unconfirmed deposit. Called when a relay link comes up,
  /// so acks and control
  /// envelopes deposited while offline are delivered the moment a usable link
  /// appears — mirroring the session layer's `pending`-message re-drive.
  func flushPendingDeposits() {
    pendingDeposits.flush { attemptDeposit($0) }
    if !pendingDeposits.isEmpty { scheduleDepositRetry() }
  }

  func scheduleDepositRetry() {
    guard depositRetryTask == nil else { return }
    depositRetryTask = Task { [weak self] in
      try? await Task.sleep(for: .seconds(30))
      guard !Task.isCancelled else { return }
      self?.depositRetryTask = nil
      self?.flushPendingDeposits()
    }
  }
}
