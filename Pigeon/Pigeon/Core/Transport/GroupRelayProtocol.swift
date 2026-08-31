import Foundation
import PigeonFFI

enum GroupRelayProtocol {
  nonisolated static let version = 4
  nonisolated private static let identifierBytes = 32

  nonisolated static func hello() throws -> Data {
    try encode([
      "type": "hello",
      "min_protocol_version": version,
      "max_protocol_version": version,
    ])
  }

  nonisolated static func register(_ registration: PigeonGroupRelayRegistration) throws -> Data {
    try encode([
      "type": "register",
      "coordination_id": registration.coordinationID.hexEncoded,
      "capabilities": registration.capabilities.map(capabilityObject),
      "signature": registration.signature.base64EncodedString(),
    ])
  }

  nonisolated static func authenticate(coordinationID: Data, capabilityKey: Data) throws -> Data {
    guard coordinationID.count == identifierBytes, capabilityKey.count == identifierBytes else {
      throw RelayError.protocolError
    }
    return try encode([
      "type": "authenticate",
      "coordination_id": coordinationID.hexEncoded,
      "capability_key": capabilityKey.hexEncoded,
    ])
  }

  nonisolated static func auth(signature: Data) throws -> Data {
    try encode(["type": "auth", "signature": signature.base64EncodedString()])
  }

  nonisolated static func action(_ action: PigeonCoreRelayAction) throws -> Data {
    switch action {
    case .append(let value):
      return try encode(["type": "append", "ciphertext": value.ciphertext.base64EncodedString()])
    case .registration(let value):
      return try register(value)
    case .control(let value):
      return try control(value)
    case .coordinatorSubmission(let value):
      return try encode([
        "type": "coordinator_submit", "claimed_base_epoch": value.claimedBaseEpoch,
        "candidate": value.candidate.base64EncodedString(),
      ])
    case .coordinatorFetch(let value):
      let cursor = value.fromEpoch == 0 ? 0 : value.fromEpoch - 1
      return try encode(["type": "coordinator_fetch", "after_sequence": cursor])
    }
  }

  nonisolated static func fetch(after cursor: UInt64) throws -> Data {
    try encode(["type": "fetch", "after_cursor": cursor])
  }

  nonisolated static func advance(to sequence: UInt64) throws -> Data {
    try encode(["type": "advance", "sequence": sequence])
  }

  nonisolated static func coordinatorFetch(after sequence: UInt64) throws -> Data {
    try encode(["type": "coordinator_fetch", "after_sequence": sequence])
  }

  nonisolated private static func control(_ value: PigeonGroupRelayControl) throws -> Data {
    switch value.kind {
    case .grant:
      return try encode([
        "type": "grant",
        "capability": capabilityObject(
          PigeonGroupRelayCapability(
            publicKey: value.publicKey, canAppend: true, canRead: true, canControl: false)),
      ])
    case .revoke:
      return try encode(["type": "revoke", "public_key": value.publicKey.hexEncoded])
    case .promoteAdmin, .demoteAdmin:
      return try encode([
        "type": "update", "public_key": value.publicKey.hexEncoded,
        "can_control": value.kind == .promoteAdmin,
      ])
    case .unspecified, .unknown:
      throw RelayError.protocolError
    }
  }

  nonisolated private static func capabilityObject(
    _ value: PigeonGroupRelayCapability
  ) -> [String: Any] {
    [
      "public_key": value.publicKey.hexEncoded,
      "can_append": value.canAppend,
      "can_read": value.canRead,
      "can_control": value.canControl,
    ]
  }

  nonisolated private static func encode(_ object: [String: Any]) throws -> Data {
    guard JSONSerialization.isValidJSONObject(object) else { throw RelayError.protocolError }
    return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
  }

}

extension Data {
  nonisolated var hexEncoded: String {
    map { String(format: "%02x", $0) }.joined()
  }
}
