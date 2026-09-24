import Foundation

enum GroupRelaySocket {
  static func send(_ data: Data, over socket: URLSessionWebSocketTask) async throws {
    guard let text = String(data: data, encoding: .utf8) else { throw RelayError.protocolError }
    try await socket.send(.string(text))
  }

  static func receive(over socket: URLSessionWebSocketTask) async throws
    -> GroupRelayProtocol.ServerFrame
  {
    let data: Data
    switch try await socket.receive() {
    case .string(let text): data = Data(text.utf8)
    case .data(let bytes): data = bytes
    @unknown default: throw RelayError.protocolError
    }
    guard data.count <= 2 * 1024 * 1024,
      let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
    else { throw RelayError.protocolError }
    return GroupRelayProtocol.classify(object)
  }
}
