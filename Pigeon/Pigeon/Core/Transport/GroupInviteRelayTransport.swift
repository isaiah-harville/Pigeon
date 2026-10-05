import Foundation

/// Carries opaque invite requests and replies through ephemeral relay inboxes.
/// Core owns the private inbox keys, ciphertext, and durable outbound queue.
@MainActor
final class GroupInviteRelayTransport {
  struct Subscription: Hashable {
    let relayURL: URL
    let address: Data
  }

  struct Outbound: Equatable {
    let id: String
    let relayURL: URL
    let destination: Data
    let ciphertext: Data
  }

  typealias ChallengeSigner = (_ address: Data, _ nonce: Data) throws -> Data
  typealias EnvelopeConsumer = (_ address: Data, _ ciphertext: Data, _ requestID: String) -> Bool

  var onEnvelope: EnvelopeConsumer?
  var onEffectDelivered: ((_ id: String) -> Bool)?

  private let session: URLSession
  private let signer: ChallengeSigner
  private var subscribers: [Subscription: Connection] = [:]
  private var publishers: [URL: Connection] = [:]

  private final class Connection {
    var task: Task<Void, Never>?
    var socket: URLSessionWebSocketTask?
    var pending: [Outbound] = []
    var processingEnvelope = false
    var stopAfterAck = false
  }

  convenience init(signer: @escaping ChallengeSigner) {
    self.init(session: .shared, signer: signer)
  }

  init(session: URLSession, signer: @escaping ChallengeSigner) {
    self.session = session
    self.signer = signer
  }

  func disconnect() {
    for connection in subscribers.values { stop(connection) }
    for connection in publishers.values { stop(connection) }
    subscribers.removeAll()
    publishers.removeAll()
  }

  /// Rebuilds only from core checkpoint state. A socket write never removes an
  /// outbound effect; the relay receipt and core commit are both required.
  func reconfigure(subscriptions: [Subscription], outbound: [Outbound]) {
    let wanted = Set(
      subscriptions.filter { subscription in
        subscription.address.count == 32 && Self.endpoint(for: subscription.relayURL) != nil
      })
    for (key, connection) in subscribers where !wanted.contains(key) {
      stop(connection)
      subscribers[key] = nil
    }
    for key in wanted where subscribers[key] == nil {
      let connection = Connection()
      subscribers[key] = connection
      connection.task = Task { [weak self, weak connection] in
        guard let self, let connection else { return }
        await self.supervise(connection) { try await self.receiveInbox(key, on: connection) }
      }
    }

    let grouped = Dictionary(
      grouping: outbound.filter { item in
        item.destination.count == 32 && Self.endpoint(for: item.relayURL) != nil
      }, by: \.relayURL)
    for (url, connection) in publishers where grouped[url] == nil {
      stop(connection)
      publishers[url] = nil
    }
    for (url, items) in grouped {
      if let connection = publishers[url] {
        if connection.pending != items {
          connection.pending = items
          connection.socket?.cancel(with: .goingAway, reason: nil)
        }
      } else {
        let connection = Connection()
        connection.pending = items
        publishers[url] = connection
        connection.task = Task { [weak self, weak connection] in
          guard let self, let connection else { return }
          await self.supervise(connection) { try await self.publish(url, on: connection) }
        }
      }
    }
  }

  private func supervise(
    _ connection: Connection, serve: () async throws -> Void
  ) async {
    var delay = 1.0
    while !Task.isCancelled {
      do {
        try await serve()
        delay = 1
      } catch {
        if Task.isCancelled { break }
      }
      connection.socket?.cancel(with: .goingAway, reason: nil)
      connection.socket = nil
      if Task.isCancelled { break }
      try? await Task.sleep(for: .seconds(delay))
      delay = min(delay * 2, 30)
    }
  }

  private func receiveInbox(_ key: Subscription, on connection: Connection) async throws {
    let socket = try await connect(key.relayURL, on: connection)
    try await send(GroupInviteRelayProtocol.subscribe(key.address), over: socket)
    guard case .challenge(let nonce) = try await receive(over: socket, timeout: 15) else {
      throw RelayError.handshake
    }
    let signature = try signer(key.address, nonce)
    try await send(GroupInviteRelayProtocol.auth(signature), over: socket)
    guard case .ok = try await receive(over: socket, timeout: 15) else {
      throw RelayError.handshake
    }
    while !Task.isCancelled {
      try await receiveEnvelope(for: key, over: socket, on: connection)
      if connection.stopAfterAck {
        stop(connection)
        return
      }
    }
  }

  private func receiveEnvelope(
    for key: Subscription, over socket: URLSessionWebSocketTask, on connection: Connection
  ) async throws {
    guard case .envelope(let id, let ciphertext) = try await receive(over: socket) else {
      throw RelayError.protocolError
    }
    let requestID = "invite-\(key.address.hexEncoded)-\(id)"
    connection.processingEnvelope = true
    defer { connection.processingEnvelope = false }
    guard onEnvelope?(key.address, ciphertext, requestID) == true else {
      throw RelayError.protocolError
    }
    try await send(GroupInviteRelayProtocol.ack(id), over: socket)
  }

  private func publish(_ url: URL, on connection: Connection) async throws {
    let socket = try await connect(url, on: connection)
    while !Task.isCancelled {
      guard let effect = connection.pending.first else {
        // A reconfigure with new effects cancels this idle socket and reconnects.
        _ = try await receive(over: socket)
        continue
      }
      try await send(GroupInviteRelayProtocol.publish(effect), over: socket)
      guard case .published(let requestID) = try await receive(over: socket, timeout: 30),
        requestID == effect.id, onEffectDelivered?(effect.id) == true
      else { throw RelayError.protocolError }
      // The core commit above may reconfigure this connection synchronously.
      // Remove only the confirmed effect; a newer effect can already be first.
      connection.pending = Self.pendingAfterReceipt(connection.pending, confirmedID: effect.id)
    }
  }

  private func connect(_ url: URL, on connection: Connection) async throws
    -> URLSessionWebSocketTask
  {
    guard let endpoint = Self.endpoint(for: url) else { throw RelayError.protocolError }
    let socket = session.webSocketTask(with: endpoint)
    connection.socket = socket
    socket.resume()
    try await send(GroupInviteRelayProtocol.hello(), over: socket)
    guard case .compatible = try await receive(over: socket, timeout: 15) else {
      throw RelayError.incompatible
    }
    return socket
  }

}

extension GroupInviteRelayTransport {
  private func send(_ data: Data, over socket: URLSessionWebSocketTask) async throws {
    guard let text = String(data: data, encoding: .utf8) else { throw RelayError.protocolError }
    try await socket.send(.string(text))
  }

  private func receive(over socket: URLSessionWebSocketTask, timeout: Double? = nil)
    async throws
    -> GroupInviteRelayProtocol.Frame
  {
    let message: URLSessionWebSocketTask.Message
    if let timeout {
      message = try await withThrowingTaskGroup(
        of: URLSessionWebSocketTask.Message.self
      ) { group in
        group.addTask { try await socket.receive() }
        group.addTask {
          try await Task.sleep(for: .seconds(timeout))
          socket.cancel(with: .goingAway, reason: nil)
          throw RelayError.timeout
        }
        guard let first = try await group.next() else { throw RelayError.timeout }
        group.cancelAll()
        return first
      }
    } else {
      message = try await socket.receive()
    }
    let data: Data
    switch message {
    case .string(let text): data = Data(text.utf8)
    case .data(let bytes): data = bytes
    @unknown default: throw RelayError.protocolError
    }
    return try GroupInviteRelayProtocol.decode(data)
  }

  private func stop(_ connection: Connection) {
    if connection.processingEnvelope {
      connection.stopAfterAck = true
      return
    }
    connection.task?.cancel()
    connection.socket?.cancel(with: .goingAway, reason: nil)
  }

  static func pendingAfterReceipt(_ pending: [Outbound], confirmedID: String) -> [Outbound] {
    pending.filter { $0.id != confirmedID }
  }

  static func endpoint(for relayURL: URL) -> URL? {
    guard var components = URLComponents(url: relayURL, resolvingAgainstBaseURL: false),
      components.host != nil, components.user == nil, components.password == nil,
      components.query == nil, components.fragment == nil
    else { return nil }
    switch components.scheme {
    case "https", "wss": components.scheme = "wss"
    default: return nil
    }
    components.path = "/ws"
    return components.url
  }
}
