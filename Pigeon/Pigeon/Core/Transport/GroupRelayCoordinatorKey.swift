import Foundation

/// Resolves the Ed25519 key used to authenticate this relay's MLS coordinator
/// receipts. Discovery is anonymous and protocol-versioned; the resolved key is
/// bound into the group policy by `pigeon-core` at creation time.
enum GroupRelayCoordinatorKey {
  static func resolve(for relayURL: URL) async throws -> Data {
    guard let endpoint = GroupRelayTransport.endpoint(for: relayURL) else {
      throw RelayError.protocolError
    }
    let request = URLRequest(url: endpoint, timeoutInterval: 15)
    let socket = URLSession.shared.webSocketTask(with: request)
    socket.resume()
    defer { socket.cancel(with: .normalClosure, reason: nil) }

    try await send(GroupRelayProtocol.hello(), over: socket)
    guard case .compatible(let version, _) = try await receive(over: socket),
      version == GroupRelayProtocol.version
    else { throw RelayError.incompatible }
    try await send(GroupRelayProtocol.coordinatorKey(), over: socket)
    guard case .coordinatorKey(let key) = try await receive(over: socket) else {
      throw RelayError.handshake
    }
    return key
  }

  private static func send(_ data: Data, over socket: URLSessionWebSocketTask) async throws {
    guard let text = String(data: data, encoding: .utf8) else {
      throw RelayError.protocolError
    }
    try await socket.send(.string(text))
  }

  private static func receive(over socket: URLSessionWebSocketTask) async throws
    -> GroupRelayProtocol.ServerFrame
  {
    let data: Data
    switch try await socket.receive() {
    case .string(let text): data = Data(text.utf8)
    case .data(let value): data = value
    @unknown default: throw RelayError.protocolError
    }
    guard data.count <= 64 * 1024,
      let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
    else { throw RelayError.protocolError }
    return GroupRelayProtocol.classify(object)
  }
}
