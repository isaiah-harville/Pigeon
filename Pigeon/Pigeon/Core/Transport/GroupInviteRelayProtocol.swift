import Foundation

/// Wire framing for the anonymous invite inbox on the pairwise `/ws` endpoint.
enum GroupInviteRelayProtocol {
  static let version = 3
  static let maximumFrameBytes = 2 * 1024 * 1024

  enum Frame: Equatable {
    case compatible
    case challenge(Data)
    case ok
    case published(requestID: String)
    case envelope(id: String, ciphertext: Data)
    case error(requestID: String?)
  }

  static func hello() throws -> Data {
    try encode([
      "type": "hello", "min_protocol_version": version,
      "max_protocol_version": version,
    ])
  }

  static func publish(_ effect: GroupInviteRelayTransport.Outbound) throws -> Data {
    guard effect.destination.count == 32, UUID(uuidString: effect.id) != nil,
      !effect.ciphertext.isEmpty
    else { throw RelayError.protocolError }
    return try encode([
      "type": "invite_publish", "recipient": effect.destination.hexEncoded,
      "ciphertext": effect.ciphertext.base64EncodedString(), "request_id": effect.id,
    ])
  }

  static func subscribe(_ address: Data) throws -> Data {
    guard address.count == 32 else { throw RelayError.protocolError }
    return try encode(["type": "invite_subscribe", "mailbox": address.hexEncoded])
  }

  static func auth(_ signature: Data) throws -> Data {
    guard signature.count == 64 else { throw RelayError.protocolError }
    return try encode(["type": "auth", "signature": signature.base64EncodedString()])
  }

  static func ack(_ id: String) throws -> Data {
    guard isEnvelopeID(id) else { throw RelayError.protocolError }
    return try encode(["type": "ack", "id": id])
  }

  static func decode(_ data: Data) throws -> Frame {
    guard data.count <= maximumFrameBytes,
      let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      let type = object["type"] as? String
    else { throw RelayError.protocolError }
    switch type {
    case "compatible":
      guard object["protocol_version"] as? Int == version else { break }
      return .compatible
    case "challenge":
      guard let value = object["nonce"] as? String,
        let nonce = Data(base64Encoded: value), nonce.count == 32
      else { break }
      return .challenge(nonce)
    case "ok":
      return .ok
    case "published":
      guard let id = object["id"] as? String, isEnvelopeID(id),
        let requestID = object["request_id"] as? String,
        UUID(uuidString: requestID) != nil
      else { break }
      return .published(requestID: requestID)
    case "envelope":
      guard let id = object["id"] as? String, isEnvelopeID(id),
        let value = object["ciphertext"] as? String,
        let ciphertext = Data(base64Encoded: value), !ciphertext.isEmpty
      else { break }
      return .envelope(id: id, ciphertext: ciphertext)
    case "error":
      return .error(requestID: object["request_id"] as? String)
    default:
      break
    }
    throw RelayError.protocolError
  }

  private static func isEnvelopeID(_ id: String) -> Bool {
    id.utf8.count == 32
      && id.utf8.allSatisfy { byte in
        (48...57).contains(byte) || (97...102).contains(byte)
      }
  }

  private static func encode(_ object: [String: Any]) throws -> Data {
    try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
  }
}
