import Foundation

public struct PigeonLegacyPairwiseMigration: Equatable, Sendable {
  public let accountState: Data
  public let fallbackKey: Data
  public let sessions: [PigeonLegacyPairwiseSession]

  public init(
    accountState: Data, fallbackKey: Data,
    sessions: [PigeonLegacyPairwiseSession]
  ) {
    self.accountState = accountState
    self.fallbackKey = fallbackKey
    self.sessions = sessions
  }
}

public struct PigeonLegacyPairwiseSession: Equatable, Sendable {
  public let remoteIdentity: Data
  public let state: Data

  public init(remoteIdentity: Data, state: Data) {
    self.remoteIdentity = remoteIdentity
    self.state = state
  }
}

/// Public contact material accepted by the core. The prekey bundle is verified
/// and retained as opaque bytes; Swift never receives an Olm account or ratchet.
public struct PigeonRegisterPairwiseContact: Equatable, Sendable {
  public let prekeyBundle: Data
  public let relayURL: String
  public let relationship: PigeonPairwiseRelationship

  public init(
    prekeyBundle: Data, relayURL: String,
    relationship: PigeonPairwiseRelationship = .contact
  ) {
    self.prekeyBundle = prekeyBundle
    self.relayURL = relayURL
    self.relationship = relationship
  }
}

public enum PigeonPairwiseRelationship: Equatable, Sendable {
  case contact
  case outgoingRequest
  case incomingRequest
  case unknown(Int)
}

public struct PigeonPairwiseContactState: Equatable, Sendable {
  public let identity: Data
  public let relationship: PigeonPairwiseRelationship
  public let introductionReceived: Bool
  public let introductionSent: Bool

  public init(
    identity: Data, relationship: PigeonPairwiseRelationship,
    introductionReceived: Bool, introductionSent: Bool
  ) {
    self.identity = identity
    self.relationship = relationship
    self.introductionReceived = introductionReceived
    self.introductionSent = introductionSent
  }
}

public struct PigeonSetPairwiseRelationship: Equatable, Sendable {
  public let identity: Data
  public let relationship: PigeonPairwiseRelationship

  public init(identity: Data, relationship: PigeonPairwiseRelationship) {
    self.identity = identity
    self.relationship = relationship
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
  func proto() throws -> Pigeon_Wire_V1_RegisterPairwiseContact {
    var body = Pigeon_Wire_V1_RegisterPairwiseContact()
    body.prekeyBundle = prekeyBundle
    body.relayURL = relayURL
    body.relationship = try relationship.proto()
    return body
  }
}

extension PigeonSetPairwiseRelationship {
  func proto() throws -> Pigeon_Wire_V1_SetPairwiseRelationship {
    var body = Pigeon_Wire_V1_SetPairwiseRelationship()
    body.identity = identity
    body.relationship = try relationship.proto()
    return body
  }
}

extension PigeonPairwiseRelationship {
  init(proto: Pigeon_Wire_V1_PairwiseRelationship) {
    switch proto {
    case .contact: self = .contact
    case .outgoingRequest: self = .outgoingRequest
    case .incomingRequest: self = .incomingRequest
    case .unspecified: self = .unknown(0)
    case .UNRECOGNIZED(let raw): self = .unknown(raw)
    }
  }

  func proto() throws -> Pigeon_Wire_V1_PairwiseRelationship {
    switch self {
    case .contact: return .contact
    case .outgoingRequest: return .outgoingRequest
    case .incomingRequest: return .incomingRequest
    case .unknown(let raw): throw PigeonCoreWireError.invalidPairwiseRelationship(raw)
    }
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
