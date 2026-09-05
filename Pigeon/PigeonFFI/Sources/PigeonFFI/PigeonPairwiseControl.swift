import Foundation

/// Public contact material accepted by the core. The prekey bundle is verified
/// and retained as opaque bytes; Swift never receives an Olm account or ratchet.
public struct PigeonRegisterPairwiseContact: Equatable, Sendable {
  public let prekeyBundle: Data
  public let relayURL: String

  public init(prekeyBundle: Data, relayURL: String) {
    self.prekeyBundle = prekeyBundle
    self.relayURL = relayURL
  }
}

/// A typed control payload that the core encrypts over its durable pairwise
/// session before returning an opaque outbound envelope.
public struct PigeonSendPairwiseControl: Equatable, Sendable {
  public let recipientIdentity: Data
  public let contentKind: PigeonCoreOutboundKind
  public let payload: Data

  public init(
    recipientIdentity: Data,
    contentKind: PigeonCoreOutboundKind,
    payload: Data
  ) {
    self.recipientIdentity = recipientIdentity
    self.contentKind = contentKind
    self.payload = payload
  }
}

extension PigeonRegisterPairwiseContact {
  func proto() -> Pigeon_Wire_V1_RegisterPairwiseContact {
    var body = Pigeon_Wire_V1_RegisterPairwiseContact()
    body.prekeyBundle = prekeyBundle
    body.relayURL = relayURL
    return body
  }
}

extension PigeonSendPairwiseControl {
  func proto() throws -> Pigeon_Wire_V1_SendPairwiseControl {
    var body = Pigeon_Wire_V1_SendPairwiseControl()
    body.recipientIdentity = recipientIdentity
    body.contentKind = try contentKind.proto()
    body.payload = payload
    return body
  }
}
