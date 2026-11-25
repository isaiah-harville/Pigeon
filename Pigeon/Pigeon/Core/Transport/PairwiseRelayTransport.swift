import CryptoKit
import Foundation
import PigeonFFI

struct PairwiseRelayEffect: Equatable {
  let id: String
  let recipient: Data
  let payload: Data

  /// The relay echoes request ids of at most 128 ASCII characters. Core item
  /// ids that fit are sent as-is; longer ones are replaced by their SHA-256.
  var requestID: String {
    if !id.isEmpty, id.utf8.count <= 128, id.allSatisfy(\.isASCII) { return id }
    return SHA256.hash(data: Data(id.utf8)).map { String(format: "%02x", $0) }.joined()
  }
}

/// Core-owned pairwise effects for one relay. Up to `window` deposits are in
/// flight at once, each correlated by its core item id echoed back as the
/// relay's `request_id`. A deposit the relay refuses is parked with its own
/// backoff instead of holding up everything queued behind it. Nothing leaves
/// the queue until the core durably acknowledges the relay's receipt.
struct PairwiseRelayDeliveryQueue {
  static let window = 16
  static let maximumRefusalBackoff: Duration = .seconds(300)

  private struct Parked {
    let effect: PairwiseRelayEffect
    let retryAt: ContinuousClock.Instant
  }

  private var queued: [PairwiseRelayEffect] = []
  private var parked: [Parked] = []
  private var refusals: [String: Int] = [:]
  private(set) var inFlight: [(effect: PairwiseRelayEffect, sentAt: ContinuousClock.Instant)] = []

  var isEmpty: Bool { queued.isEmpty && parked.isEmpty && inFlight.isEmpty }

  /// The send time of the oldest deposit still waiting for a receipt.
  var oldestInFlight: ContinuousClock.Instant? { inFlight.map(\.sentAt).min() }

  /// When the earliest parked deposit becomes eligible again.
  var nextParkedRetry: ContinuousClock.Instant? { parked.map(\.retryAt).min() }

  mutating func reconcile(_ desired: [PairwiseRelayEffect]) {
    let desiredIDs = Set(desired.map(\.id))
    queued.removeAll { !desiredIDs.contains($0.id) }
    parked.removeAll { !desiredIDs.contains($0.effect.id) }
    inFlight.removeAll { !desiredIDs.contains($0.effect.id) }
    refusals = refusals.filter { desiredIDs.contains($0.key) }
    let known = Set(queued.map(\.id))
      .union(parked.map(\.effect.id))
      .union(inFlight.map(\.effect.id))
    queued.append(contentsOf: desired.filter { !known.contains($0.id) })
  }

  /// The next deposit to send, if the in-flight window has room. Parked
  /// deposits whose backoff has elapsed go ahead of fresh ones.
  mutating func next(now: ContinuousClock.Instant) -> PairwiseRelayEffect? {
    guard inFlight.count < Self.window else { return nil }
    let effect: PairwiseRelayEffect
    if let index = parked.firstIndex(where: { $0.retryAt <= now }) {
      effect = parked.remove(at: index).effect
    } else if !queued.isEmpty {
      effect = queued.removeFirst()
    } else {
      return nil
    }
    inFlight.append((effect, now))
    return effect
  }

  /// Confirms the deposit a `published` receipt names. A receipt without a
  /// request id is accepted only while exactly one deposit is in flight, so it
  /// can never be attributed to the wrong item.
  mutating func confirm(
    requestID: String?, _ acknowledge: (String) -> Bool
  ) -> Bool {
    let index: Int
    if let requestID {
      guard let match = inFlight.firstIndex(where: { $0.effect.requestID == requestID }) else {
        return false
      }
      index = match
    } else {
      guard inFlight.count == 1 else { return false }
      index = 0
    }
    let id = inFlight[index].effect.id
    guard acknowledge(id) else { return false }
    inFlight.remove(at: index)
    refusals[id] = nil
    return true
  }

  /// Parks a deposit the relay refused. Each further refusal doubles its
  /// backoff up to `maximumRefusalBackoff`. Returns false for an unknown id.
  mutating func refuse(requestID: String, now: ContinuousClock.Instant) -> Bool {
    guard let index = inFlight.firstIndex(where: { $0.effect.requestID == requestID }) else {
      return false
    }
    let effect = inFlight.remove(at: index).effect
    let attempts = (refusals[effect.id] ?? 0) + 1
    refusals[effect.id] = attempts
    let backoff = min(
      Duration.seconds(1 << min(attempts - 1, 16)), Self.maximumRefusalBackoff)
    parked.append(Parked(effect: effect, retryAt: now + backoff))
    return true
  }

  /// Returns unconfirmed deposits to the front of the queue, in send order,
  /// after the connection that carried them is lost.
  mutating func retryInFlight() {
    queued.insert(contentsOf: inFlight.map(\.effect), at: 0)
    inFlight.removeAll()
  }
}

/// Publishes core-owned pairwise ciphertext and retains each effect until the
/// relay confirms durable storage. Connections are publish-only. Deposits are
/// written to the socket in queue order and pipelined up to the queue's
/// window; each `published` or `error` reply is matched to its item by the
/// echoed request id. A watchdog reconnects when a receipt is overdue or the
/// socket stops answering pings.
@MainActor
final class PairwiseRelayTransport {
  var onEffectDelivered: ((String) -> Bool)?

  private let sender: Data
  private let session: URLSession
  private var connections: [URL: Connection] = [:]

  private final class Connection {
    let url: URL
    var queue = PairwiseRelayDeliveryQueue()
    var socket: URLSessionWebSocketTask?
    var supervisor: Task<Void, Never>?
    var watchdog: Task<Void, Never>?
    /// The last queued socket write; each new write waits for it so frames
    /// leave in queue order.
    var writes: Task<Void, Never>?
    var ready = false
    var lastPing = ContinuousClock.now

    init(url: URL) { self.url = url }
  }

  convenience init(sender: Data) {
    self.init(sender: sender, session: .shared)
  }

  init(sender: Data, session: URLSession) {
    self.sender = sender
    self.session = session
  }

  func disconnect() {
    for connection in connections.values { stop(connection) }
    connections.removeAll()
  }

  func reconfigure(snapshot: PigeonCoreSnapshot) {
    let effects = snapshot.pendingOutbound.compactMap { item in
      item.localOnly ? nil : effect(item)
    }
    let effectsByRelay = Dictionary(grouping: effects) { routedEffect in
      routedEffect.relay
    }
    for (url, connection) in connections where effectsByRelay[url] == nil {
      stop(connection)
      connections[url] = nil
    }
    for (url, values) in effectsByRelay {
      let connection: Connection
      if let existing = connections[url] {
        connection = existing
      } else {
        connection = Connection(url: url)
        connections[url] = connection
        start(connection)
      }
      connection.queue.reconcile(values.map(\.effect))
      sendNext(connection)
    }
  }
}

extension PairwiseRelayTransport {
  private struct RoutedEffect {
    let relay: URL
    let effect: PairwiseRelayEffect
  }

  private func effect(_ item: PigeonCoreOutboundItem) -> RoutedEffect? {
    guard item.kind == .pairwise,
      item.destination.count == 32,
      !item.payload.isEmpty,
      let relay = URL(string: item.relayURL),
      let scheme = relay.scheme?.lowercased(),
      scheme == "ws" || scheme == "wss",
      relay.host?.isEmpty == false
    else { return nil }
    return RoutedEffect(
      relay: relay,
      effect: PairwiseRelayEffect(
        id: item.id, recipient: item.destination, payload: item.payload))
  }

  /// A receipt this late means the relay or the path to it is stuck.
  static let receiptTimeout: Duration = .seconds(20)
  static let watchdogInterval: Duration = .seconds(5)
  static let pingInterval: Duration = .seconds(30)

  private func start(_ connection: Connection) {
    connection.supervisor = Task { [weak self, weak connection] in
      guard let self, let connection else { return }
      var backoff = 1.0
      while !Task.isCancelled {
        do {
          try await self.serve(connection)
          backoff = 1
        } catch {
          guard !Task.isCancelled else { break }
          self.reset(connection)
          try? await Task.sleep(for: .seconds(min(backoff, 30)))
          backoff = min(backoff * 2, 30)
        }
      }
    }
    connection.watchdog = Task { [weak self, weak connection] in
      while !Task.isCancelled {
        try? await Task.sleep(for: Self.watchdogInterval)
        guard let self, let connection, !Task.isCancelled else { return }
        self.inspect(connection)
      }
    }
  }

  private func stop(_ connection: Connection) {
    connection.supervisor?.cancel()
    connection.watchdog?.cancel()
    connection.writes?.cancel()
    connection.socket?.cancel(with: .goingAway, reason: nil)
  }

  private func reset(_ connection: Connection) {
    connection.ready = false
    connection.queue.retryInFlight()
    connection.writes?.cancel()
    connection.writes = nil
    connection.socket?.cancel(with: .goingAway, reason: nil)
  }

  /// Reconnects a connection whose oldest receipt is overdue, keeps an idle
  /// socket honest with a ping, and releases parked deposits that are due.
  private func inspect(_ connection: Connection) {
    guard connection.ready, let socket = connection.socket else { return }
    let now = ContinuousClock.now
    if let oldest = connection.queue.oldestInFlight, now - oldest > Self.receiptTimeout {
      socket.cancel(with: .goingAway, reason: nil)
      return
    }
    if now - connection.lastPing >= Self.pingInterval {
      connection.lastPing = now
      socket.sendPing { error in
        if error != nil { socket.cancel(with: .goingAway, reason: nil) }
      }
    }
    sendNext(connection)
  }

  private func serve(_ connection: Connection) async throws {
    let socket = session.webSocketTask(with: connection.url)
    connection.socket = socket
    socket.resume()
    try await send(PairwiseRelayProtocol.hello(), over: socket)
    let hello = try await receive(over: socket)
    guard RelayTransport.relayInfo(from: hello)?.compatibility == .compatible else {
      throw RelayError.incompatible
    }
    connection.ready = true
    connection.lastPing = .now
    sendNext(connection)

    while !Task.isCancelled {
      switch PairwiseRelayProtocol.classify(try await receive(over: socket)) {
      case .published(let requestID):
        guard
          connection.queue.confirm(requestID: requestID, onEffectDelivered ?? { _ in false })
        else {
          throw RelayError.protocolError
        }
        sendNext(connection)
      case .refused(let requestID):
        // A refusal naming one deposit parks that deposit; anything else
        // means the connection itself is unusable.
        guard let requestID, connection.queue.refuse(requestID: requestID, now: .now) else {
          throw RelayError.protocolError
        }
        sendNext(connection)
      case .ignored:
        break
      }
    }
  }

  private func sendNext(_ connection: Connection) {
    guard connection.ready, let socket = connection.socket else { return }
    while let effect = connection.queue.next(now: .now) {
      let previous = connection.writes
      connection.writes = Task { [weak connection, sender] in
        await previous?.value
        guard !Task.isCancelled else { return }
        do {
          let data = try PairwiseRelayProtocol.publish(
            sender: sender, recipient: effect.recipient, payload: effect.payload,
            requestID: effect.requestID)
          try await self.send(data, over: socket)
        } catch {
          connection?.socket?.cancel(with: .internalServerError, reason: nil)
        }
      }
    }
  }

  private func send(_ data: Data, over socket: URLSessionWebSocketTask) async throws {
    guard let text = String(data: data, encoding: .utf8) else {
      throw RelayError.protocolError
    }
    try await socket.send(.string(text))
  }

  private func receive(over socket: URLSessionWebSocketTask) async throws -> [String: Any] {
    let data: Data
    switch try await socket.receive() {
    case .data(let value): data = value
    case .string(let value):
      guard let value = value.data(using: .utf8) else { throw RelayError.protocolError }
      data = value
    @unknown default:
      throw RelayError.protocolError
    }
    guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
      throw RelayError.protocolError
    }
    return object
  }
}
