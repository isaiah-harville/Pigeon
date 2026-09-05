import Foundation
import SwiftProtobuf

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

public struct PigeonCoordinatorReceipt: Equatable, Sendable {
  public let coordinationID: Data
  public let sequence: UInt64
  public let priorReceiptHash: Data
  public let claimedBaseEpoch: UInt64
  public let entryHash: Data
  public let signature: Data

  public init(
    coordinationID: Data, sequence: UInt64, priorReceiptHash: Data,
    claimedBaseEpoch: UInt64, entryHash: Data, signature: Data
  ) {
    self.coordinationID = coordinationID
    self.sequence = sequence
    self.priorReceiptHash = priorReceiptHash
    self.claimedBaseEpoch = claimedBaseEpoch
    self.entryHash = entryHash
    self.signature = signature
  }
}

extension PigeonApplyInbound {
  public static func coordinatorCandidate(
    receipt: PigeonCoordinatorReceipt,
    candidate: Data,
    requestID: String
  ) throws -> Self {
    guard receipt.coordinationID.count == 32,
      receipt.priorReceiptHash.count == 32,
      receipt.entryHash.count == 32,
      receipt.signature.count == 64,
      !candidate.isEmpty
    else {
      throw PigeonCoreWireError.malformedRelayAction
    }
    var wireReceipt = Pigeon_Wire_V1_CoordinatorReceipt()
    wireReceipt.version = 1
    wireReceipt.coordinationID = receipt.coordinationID
    wireReceipt.sequence = receipt.sequence
    wireReceipt.priorReceiptHash = receipt.priorReceiptHash
    wireReceipt.claimedBaseEpoch = receipt.claimedBaseEpoch
    wireReceipt.entryHash = receipt.entryHash
    wireReceipt.signature = receipt.signature
    var wireCandidate = Pigeon_Wire_V1_CoordinatorCandidate()
    wireCandidate.receipt = wireReceipt
    wireCandidate.candidate = candidate
    return try Self(
      kind: .groupCoordinator,
      payload: wireCandidate.serializedData(),
      requestID: requestID)
  }
}
