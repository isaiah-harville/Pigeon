import Foundation
import PigeonFFI

enum PairwiseRelayProtocol {
  enum ServerFrame: Equatable {
    /// The relay stored a deposit; `requestID` names it when the relay echoed one.
    case published(requestID: String?)
    /// The relay refused a request; `requestID` names the deposit, if any.
    case refused(requestID: String?)
    case ignored
  }

  static func publish(
    sender: Data, recipient: Data, payload: Data, requestID: String?
  ) throws -> Data {
    guard sender.count == 32, recipient.count == 32, !payload.isEmpty else {
      throw RelayError.protocolError
    }
    let envelope = SessionEnvelope(
      type: .pairwise, sender: sender, recipient: recipient, payload: payload)
    // The relay receiver enters through MeshService; a one-hop packet keeps it
    // from flooding this addressed delivery onto nearby links.
    let packet = MeshPacket(
      packetId: MeshPacket.randomID(), ttl: 1, payload: envelope.encoded())
    var frame: [String: Any] = [
      "type": "publish",
      "recipient": recipient.hexEncoded,
      "ciphertext": packet.encoded().base64EncodedString(),
    ]
    if let requestID { frame["request_id"] = requestID }
    return try encode(frame)
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
      return .published(requestID: requestID(object))
    case "error":
      return .refused(requestID: requestID(object))
    default:
      return .ignored
    }
  }

  private static func requestID(_ object: [String: Any]) -> String? {
    guard let id = object["request_id"] as? String, !id.isEmpty else { return nil }
    return id
  }

  private static func encode(_ object: [String: Any]) throws -> Data {
    guard JSONSerialization.isValidJSONObject(object) else { throw RelayError.protocolError }
    return try JSONSerialization.data(withJSONObject: object)
  }
}
