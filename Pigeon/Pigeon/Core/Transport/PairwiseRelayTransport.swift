import Foundation
import PigeonFFI

struct PairwiseRelayEffect: Equatable {
  let id: String
  let recipient: Data
  let payload: Data
}

struct PairwiseRelayDeliveryQueue {
  private var queued: [PairwiseRelayEffect] = []
  private(set) var awaiting: PairwiseRelayEffect?

  mutating func reconcile(_ desired: [PairwiseRelayEffect]) {
    let desiredIDs = Set(desired.map(\.id))
    queued.removeAll { !desiredIDs.contains($0.id) }
    if let awaiting, !desiredIDs.contains(awaiting.id) { self.awaiting = nil }
    let known = Set(queued.map(\.id)).union(awaiting.map { [$0.id] } ?? [])
    queued.append(contentsOf: desired.filter { !known.contains($0.id) })
  }

  mutating func next() -> PairwiseRelayEffect? {
    guard awaiting == nil, !queued.isEmpty else { return nil }
    let effect = queued.removeFirst()
    awaiting = effect
    return effect
  }

  mutating func confirm(_ acknowledge: (String) -> Bool) -> Bool {
    guard let awaiting, acknowledge(awaiting.id) else { return false }
    self.awaiting = nil
    return true
  }

  mutating func retryAwaiting() {
    guard let awaiting else { return }
    queued.insert(awaiting, at: 0)
    self.awaiting = nil
  }
}

/// Publishes core-owned pairwise control ciphertext and retains each effect
/// until the relay confirms durable storage. Connections are publish-only and
/// serialize deposits so an anonymous `published` reply maps to exactly one
/// pending core item.
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
    var ready = false

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
    let effects = snapshot.pendingOutbound.compactMap(effect)
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
          connection.ready = false
          connection.queue.retryAwaiting()
          connection.socket?.cancel(with: .goingAway, reason: nil)
          try? await Task.sleep(for: .seconds(min(backoff, 30)))
          backoff = min(backoff * 2, 30)
        }
      }
    }
  }

  private func stop(_ connection: Connection) {
    connection.supervisor?.cancel()
    connection.socket?.cancel(with: .goingAway, reason: nil)
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
    sendNext(connection)

    while !Task.isCancelled {
      switch PairwiseRelayProtocol.classify(try await receive(over: socket)) {
      case .published:
        guard connection.queue.confirm(onEffectDelivered ?? { _ in false }) else {
          throw RelayError.protocolError
        }
        sendNext(connection)
      case .error:
        throw RelayError.protocolError
      case .ignored:
        break
      }
    }
  }

  private func sendNext(_ connection: Connection) {
    guard connection.ready,
      let socket = connection.socket,
      let effect = connection.queue.next()
    else { return }
    Task { [weak connection] in
      do {
        let data = try PairwiseRelayProtocol.publish(
          sender: sender, recipient: effect.recipient, payload: effect.payload)
        try await send(data, over: socket)
      } catch {
        connection?.socket?.cancel(with: .internalServerError, reason: nil)
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
