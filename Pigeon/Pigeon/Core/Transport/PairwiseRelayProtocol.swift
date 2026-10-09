import Foundation
import PigeonFFI

enum PairwiseRelayProtocol {
  enum ServerFrame: Equatable {
    case published
    case error
    case ignored
  }

  static func publish(sender: Data, recipient: Data, payload: Data) throws -> Data {
    guard sender.count == 32, recipient.count == 32, !payload.isEmpty else {
      throw RelayError.protocolError
    }
    let envelope = SessionEnvelope(
      type: .pairwise, sender: sender, recipient: recipient, payload: payload)
    return try encode([
      "type": "publish",
      "recipient": recipient.hexEncoded,
      "ciphertext": envelope.encoded().base64EncodedString(),
    ])
  }

  static func hello() throws -> Data {
    try encode([
      "type": "hello",
      "min_protocol_version": RelayTransport.minimumProtocolVersion,
      "max_protocol_version": RelayTransport.maximumProtocolVersion,
    ])
  }

  static func classify(_ object: [String: Any]) -> ServerFrame {
    switch object["type"] as? String {
    case "published":
      guard let id = object["id"] as? String, !id.isEmpty else { return .ignored }
      return .published
    case "error":
      return .error
    default:
      return .ignored
    }
  }

  private static func encode(_ object: [String: Any]) throws -> Data {
    guard JSONSerialization.isValidJSONObject(object) else { throw RelayError.protocolError }
    return try JSONSerialization.data(withJSONObject: object)
  }
}
