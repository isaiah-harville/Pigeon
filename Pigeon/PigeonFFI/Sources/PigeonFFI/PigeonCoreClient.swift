import Foundation

public struct PigeonCoreCommand: Equatable, Sendable {
  public enum Body: Equatable, Sendable {
    case createGroup(PigeonCreateGroup)
    case sendGroupMessage(PigeonSendGroupMessage)
    case applyInbound(PigeonApplyInbound)
    case changeGroupPolicy(PigeonChangeGroupPolicy)
  }

  public let id: String
  public let body: Body

  public init(id: String, body: Body) {
    self.id = id
    self.body = body
  }
}

public struct PigeonCreateGroup: Equatable, Sendable {
  public let name: String
  public let memberIdentities: [Data]
  public let relayURL: String
  public let meshEnabled: Bool
  public let coordinatorPublicKey: Data

  public init(
    name: String,
    memberIdentities: [Data],
    relayURL: String,
    meshEnabled: Bool,
    coordinatorPublicKey: Data
  ) {
    self.name = name
    self.memberIdentities = memberIdentities
    self.relayURL = relayURL
    self.meshEnabled = meshEnabled
    self.coordinatorPublicKey = coordinatorPublicKey
  }
}

public struct PigeonSendGroupMessage: Equatable, Sendable {
  public let groupID: Data
  public let messageID: String
  public let body: Data
  public let replyToMessageID: String?
  public let senderTimestampMilliseconds: Int64

  public init(
    groupID: Data,
    messageID: String,
    body: Data,
    senderTimestampMilliseconds: Int64,
    replyToMessageID: String? = nil
  ) {
    self.groupID = groupID
    self.messageID = messageID
    self.body = body
    self.replyToMessageID = replyToMessageID
    self.senderTimestampMilliseconds = senderTimestampMilliseconds
  }
}

public struct PigeonApplyInbound: Equatable, Sendable {
  public let kind: PigeonCoreOutboundKind
  public let payload: Data
  public let requestID: String

  public init(kind: PigeonCoreOutboundKind, payload: Data, requestID: String) {
    self.kind = kind
    self.payload = payload
    self.requestID = requestID
  }
}

public struct PigeonChangeGroupPolicy: Equatable, Sendable {
  public let groupID: Data
  public let kind: PigeonGroupPolicyChangeKind
  public let subjectIdentity: Data
  public let stringValue: String
  public let boolValue: Bool

  public init(
    groupID: Data,
    kind: PigeonGroupPolicyChangeKind,
    subjectIdentity: Data = Data(),
    stringValue: String = "",
    boolValue: Bool = false
  ) {
    self.groupID = groupID
    self.kind = kind
    self.subjectIdentity = subjectIdentity
    self.stringValue = stringValue
    self.boolValue = boolValue
  }
}

public enum PigeonCoreOutboundKind: Equatable, Sendable {
  case unspecified
  case pairwise
  case groupMessage
  case groupCoordinator
  case groupJoinRequest
  case mesh
  case groupJoinMaterial
  case groupWelcome
  case groupRelayRegistration
  case groupRelayControl
  case groupLeaveProposal
  case unknown(Int)
}

public enum PigeonGroupPolicyChangeKind: Equatable, Sendable {
  case unspecified
  case memberAdded
  case memberRemoved
  case memberLeft
  case adminPromoted
  case adminDemoted
  case nameChanged
  case meshChanged
  case relayChanged
  case dissolved
  case unknown(Int)
}

public enum PigeonGroupDeliveryState: Equatable, Sendable {
  case unspecified
  case sending
  case sent
  case deliveredTo
  case delivered
  case failed
  case expired
  case unknown(Int)
}

public struct PigeonCoreOutput: Equatable, Sendable {
  public let checkpointGeneration: UInt64
  public let events: [PigeonCoreEvent]
  public let outbound: [PigeonCoreOutboundItem]
}

/// Durable, read-only application projection rebuilt from the core checkpoint.
public struct PigeonCoreSnapshot: Equatable, Sendable {
  public let checkpointGeneration: UInt64
  public let groups: [PigeonGroupState]

  public init(checkpointGeneration: UInt64, groups: [PigeonGroupState]) {
    self.checkpointGeneration = checkpointGeneration
    self.groups = groups
  }
}

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
  public let coordinatorPublicKey: Data

  public init(
    groupID: Data, ownerIdentity: Data, adminIdentities: [Data],
    memberIdentities: [Data], name: String, relayURL: String, coordinationID: Data,
    meshEnabled: Bool, epoch: UInt64, policyRevision: UInt64, dissolved: Bool,
    capabilityPublicKey: Data, coordinatorPublicKey: Data
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
    self.coordinatorPublicKey = coordinatorPublicKey
  }
}

public struct PigeonCoreOutboundItem: Equatable, Sendable {
  public let id: String
  public let kind: PigeonCoreOutboundKind
  public let relayURL: String
  public let destination: Data
  public let payload: Data
}

public struct PigeonCoreEvent: Equatable, Sendable {
  public enum Body: Equatable, Sendable {
    case groupCreated(PigeonGroupCreatedEvent)
    case groupMessageReceived(PigeonGroupMessageReceivedEvent)
    case groupReactionReceived(PigeonGroupReactionReceivedEvent)
    case groupPolicyChanged(PigeonGroupPolicyChangedEvent)
    case groupDeliveryChanged(PigeonGroupDeliveryChangedEvent)
    case groupSecurityWarning(PigeonGroupSecurityWarningEvent)
  }

  public let id: String
  public let body: Body
}

public struct PigeonGroupCreatedEvent: Equatable, Sendable {
  public let groupID: Data
  public let ownerIdentity: Data
  public let name: String
  public let relayURL: String
  public let meshEnabled: Bool
  public let epoch: UInt64
  public let policyRevision: UInt64

  public init(
    groupID: Data, ownerIdentity: Data, name: String, relayURL: String,
    meshEnabled: Bool, epoch: UInt64, policyRevision: UInt64
  ) {
    self.groupID = groupID
    self.ownerIdentity = ownerIdentity
    self.name = name
    self.relayURL = relayURL
    self.meshEnabled = meshEnabled
    self.epoch = epoch
    self.policyRevision = policyRevision
  }

}

public struct PigeonGroupMessageReceivedEvent: Equatable, Sendable {
  public let groupID: Data
  public let messageID: String
  public let senderIdentity: Data
  public let body: Data
  public let replyToMessageID: String?
  public let epoch: UInt64

  public init(
    groupID: Data, messageID: String, senderIdentity: Data, body: Data,
    replyToMessageID: String?, epoch: UInt64
  ) {
    self.groupID = groupID
    self.messageID = messageID
    self.senderIdentity = senderIdentity
    self.body = body
    self.replyToMessageID = replyToMessageID
    self.epoch = epoch
  }

}

public struct PigeonGroupReactionReceivedEvent: Equatable, Sendable {
  public let groupID: Data
  public let messageID: String
  public let senderIdentity: Data
  public let targetMessageID: String
  public let reaction: String
  public let epoch: UInt64

  public init(
    groupID: Data, messageID: String, senderIdentity: Data, targetMessageID: String,
    reaction: String, epoch: UInt64
  ) {
    self.groupID = groupID
    self.messageID = messageID
    self.senderIdentity = senderIdentity
    self.targetMessageID = targetMessageID
    self.reaction = reaction
    self.epoch = epoch
  }

}

public struct PigeonGroupPolicyChangedEvent: Equatable, Sendable {
  public let kind: PigeonGroupPolicyChangeKind
  public let groupID: Data
  public let actorIdentity: Data
  public let subjectIdentity: Data
  public let epoch: UInt64
  public let policyRevision: UInt64
  public let name: String
  public let meshEnabled: Bool
  public let relayURL: String

  public init(
    kind: PigeonGroupPolicyChangeKind, groupID: Data, actorIdentity: Data,
    subjectIdentity: Data, epoch: UInt64, policyRevision: UInt64, name: String,
    meshEnabled: Bool, relayURL: String
  ) {
    self.kind = kind
    self.groupID = groupID
    self.actorIdentity = actorIdentity
    self.subjectIdentity = subjectIdentity
    self.epoch = epoch
    self.policyRevision = policyRevision
    self.name = name
    self.meshEnabled = meshEnabled
    self.relayURL = relayURL
  }

}

public struct PigeonGroupDeliveryChangedEvent: Equatable, Sendable {
  public let groupID: Data
  public let messageID: String
  public let state: PigeonGroupDeliveryState
  public let epoch: UInt64
  public let deliveredCount: UInt32
  public let intendedCount: UInt32

  public init(
    groupID: Data, messageID: String, state: PigeonGroupDeliveryState, epoch: UInt64,
    deliveredCount: UInt32, intendedCount: UInt32
  ) {
    self.groupID = groupID
    self.messageID = messageID
    self.state = state
    self.epoch = epoch
    self.deliveredCount = deliveredCount
    self.intendedCount = intendedCount
  }

}

public struct PigeonGroupSecurityWarningEvent: Equatable, Sendable {
  public let groupID: Data
  public let code: UInt32
  public let evidenceID: Data
  public let epoch: UInt64

  public init(groupID: Data, code: UInt32, evidenceID: Data, epoch: UInt64) {
    self.groupID = groupID
    self.code = code
    self.evidenceID = evidenceID
    self.epoch = epoch
  }

}
