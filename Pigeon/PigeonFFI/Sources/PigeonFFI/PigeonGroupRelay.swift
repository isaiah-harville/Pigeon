import Foundation

public enum PigeonCoreRelayAction: Equatable, Sendable {
  case append(PigeonGroupRelayAppend)
  case registration(PigeonGroupRelayRegistration)
  case control(PigeonGroupRelayControl)
  case coordinatorSubmission(PigeonGroupCoordinatorSubmission)
  case coordinatorFetch(PigeonGroupCoordinatorFetch)
}

public struct PigeonGroupRelayAppend: Equatable, Sendable {
  public let coordinationID: Data
  public let ciphertext: Data

  public init(coordinationID: Data, ciphertext: Data) {
    self.coordinationID = coordinationID
    self.ciphertext = ciphertext
  }
}

public struct PigeonGroupRelayCapability: Equatable, Sendable {
  public let publicKey: Data
  public let canAppend: Bool
  public let canRead: Bool
  public let canControl: Bool

  public init(publicKey: Data, canAppend: Bool, canRead: Bool, canControl: Bool) {
    self.publicKey = publicKey
    self.canAppend = canAppend
    self.canRead = canRead
    self.canControl = canControl
  }
}

public struct PigeonGroupRelayRegistration: Equatable, Sendable {
  public let coordinationID: Data
  public let capabilities: [PigeonGroupRelayCapability]
  public let signature: Data

  public init(
    coordinationID: Data,
    capabilities: [PigeonGroupRelayCapability],
    signature: Data
  ) {
    self.coordinationID = coordinationID
    self.capabilities = capabilities
    self.signature = signature
  }
}

public enum PigeonGroupRelayControlKind: Equatable, Sendable {
  case unspecified
  case grant
  case revoke
  case promoteAdmin
  case demoteAdmin
  case unknown(Int)
}

public struct PigeonGroupRelayControl: Equatable, Sendable {
  public let coordinationID: Data
  public let kind: PigeonGroupRelayControlKind
  public let publicKey: Data

  public init(coordinationID: Data, kind: PigeonGroupRelayControlKind, publicKey: Data) {
    self.coordinationID = coordinationID
    self.kind = kind
    self.publicKey = publicKey
  }
}

public struct PigeonGroupCoordinatorSubmission: Equatable, Sendable {
  public let coordinationID: Data
  public let claimedBaseEpoch: UInt64
  public let candidate: Data

  public init(coordinationID: Data, claimedBaseEpoch: UInt64, candidate: Data) {
    self.coordinationID = coordinationID
    self.claimedBaseEpoch = claimedBaseEpoch
    self.candidate = candidate
  }
}

public struct PigeonGroupCoordinatorFetch: Equatable, Sendable {
  public let coordinationID: Data
  public let groupID: Data
  public let fromEpoch: UInt64
  public let throughEpoch: UInt64

  public init(coordinationID: Data, groupID: Data, fromEpoch: UInt64, throughEpoch: UInt64) {
    self.coordinationID = coordinationID
    self.groupID = groupID
    self.fromEpoch = fromEpoch
    self.throughEpoch = throughEpoch
  }
}
