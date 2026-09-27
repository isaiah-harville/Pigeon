import Foundation

/// Authenticated group state needed by a host UI and its opaque transports.
public struct PigeonGroupState: Equatable, Sendable {
  public let groupID: Data
  public let ownerIdentity: Data
  public let adminIdentities: [Data]
  public let memberIdentities: [Data]
  public let name: String
  public let relayURL: String
  public let coordinationID: Data
  public let meshEnabled: Bool
  public let epoch: UInt64
  public let policyRevision: UInt64
  public let dissolved: Bool
  public let capabilityPublicKey: Data
  public let capabilityID: Data
  public let coordinatorPublicKey: Data
  public let coordinatorSequence: UInt64
  public let localLeavePending: Bool

  public init(
    groupID: Data, ownerIdentity: Data, adminIdentities: [Data],
    memberIdentities: [Data], name: String, relayURL: String, coordinationID: Data,
    meshEnabled: Bool, epoch: UInt64, policyRevision: UInt64, dissolved: Bool,
    capabilityPublicKey: Data, capabilityID: Data, coordinatorPublicKey: Data,
    coordinatorSequence: UInt64 = 0, localLeavePending: Bool = false
  ) {
    self.groupID = groupID
    self.ownerIdentity = ownerIdentity
    self.adminIdentities = adminIdentities
    self.memberIdentities = memberIdentities
    self.name = name
    self.relayURL = relayURL
    self.coordinationID = coordinationID
    self.meshEnabled = meshEnabled
    self.epoch = epoch
    self.policyRevision = policyRevision
    self.dissolved = dissolved
    self.capabilityPublicKey = capabilityPublicKey
    self.capabilityID = capabilityID
    self.coordinatorPublicKey = coordinatorPublicKey
    self.coordinatorSequence = coordinatorSequence
    self.localLeavePending = localLeavePending
  }
}
