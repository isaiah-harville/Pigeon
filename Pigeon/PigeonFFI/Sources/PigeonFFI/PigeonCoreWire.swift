import Foundation
import SwiftProtobuf

public enum PigeonCoreWireError: Error, Equatable, Sendable {
  case missingEventBody
  case invalidOutboundKind(Int)
  case invalidPolicyChangeKind(Int)
}

extension FfiClient {
  public func execute(_ command: PigeonCoreCommand) throws -> PigeonCoreOutput {
    let proto = try command.proto()
    let encoded = try proto.serializedData()
    let output = try Pigeon_Wire_V1_ClientOutput(serializedBytes: execute(command: encoded))
    return try PigeonCoreOutput(proto: output)
  }
}

extension PigeonCoreOutput {
  init(proto: Pigeon_Wire_V1_ClientOutput) throws {
    checkpointGeneration = proto.checkpointGeneration
    events = try proto.events.map(PigeonCoreEvent.init(proto:))
    outbound = proto.outbound.map(PigeonCoreOutboundItem.init(proto:))
  }
}

extension PigeonCoreCommand {
  func proto() throws -> Pigeon_Wire_V1_ClientCommand {
    var command = Pigeon_Wire_V1_ClientCommand()
    command.version = 1
    command.commandID = id
    switch body {
    case .createGroup(let value):
      var body = Pigeon_Wire_V1_CreateGroup()
      body.name = value.name
      body.memberIdentities = value.memberIdentities
      body.relayURL = value.relayURL
      body.meshEnabled = value.meshEnabled
      body.coordinatorPublicKey = value.coordinatorPublicKey
      command.createGroup = body
    case .sendGroupMessage(let value):
      var body = Pigeon_Wire_V1_SendGroupMessage()
      body.groupID = value.groupID
      body.messageID = value.messageID
      body.body = value.body
      body.replyToMessageID = value.replyToMessageID ?? ""
      body.senderTimestampMs = value.senderTimestampMilliseconds
      command.sendGroupMessage = body
    case .applyInbound(let value):
      var body = Pigeon_Wire_V1_ApplyInbound()
      body.kind = try value.kind.proto()
      body.payload = value.payload
      body.requestID = value.requestID
      command.applyInbound = body
    case .changeGroupPolicy(let value):
      var body = Pigeon_Wire_V1_ChangeGroupPolicy()
      body.groupID = value.groupID
      body.kind = try value.kind.proto()
      body.subjectIdentity = value.subjectIdentity
      body.stringValue = value.stringValue
      body.boolValue = value.boolValue
      command.changeGroupPolicy = body
    }
    return command
  }
}

extension PigeonCoreOutboundItem {
  init(proto: Pigeon_Wire_V1_OutboundItem) {
    id = proto.itemID
    kind = PigeonCoreOutboundKind(proto: proto.kind)
    relayURL = proto.relayURL
    destination = proto.destination
    payload = proto.payload
  }
}

extension PigeonCoreEvent {
  init(proto: Pigeon_Wire_V1_AppEvent) throws {
    id = proto.eventID
    switch proto.body {
    case .groupCreated(let event):
      body = .groupCreated(PigeonGroupCreatedEvent(proto: event))
    case .groupMessageReceived(let event):
      body = .groupMessageReceived(PigeonGroupMessageReceivedEvent(proto: event))
    case .groupReactionReceived(let event):
      body = .groupReactionReceived(PigeonGroupReactionReceivedEvent(proto: event))
    case .groupPolicyChanged(let event):
      body = .groupPolicyChanged(PigeonGroupPolicyChangedEvent(proto: event))
    case .groupDeliveryChanged(let event):
      body = .groupDeliveryChanged(PigeonGroupDeliveryChangedEvent(proto: event))
    case .groupSecurityWarning(let event):
      body = .groupSecurityWarning(PigeonGroupSecurityWarningEvent(proto: event))
    case nil:
      throw PigeonCoreWireError.missingEventBody
    }
  }
}

extension PigeonGroupCreatedEvent {
  init(proto: Pigeon_Wire_V1_GroupCreated) {
    self.init(
      groupID: proto.groupID, ownerIdentity: proto.ownerIdentity, name: proto.name,
      relayURL: proto.relayURL, meshEnabled: proto.meshEnabled, epoch: proto.epoch,
      policyRevision: proto.policyRevision)
  }
}

extension PigeonGroupMessageReceivedEvent {
  init(proto: Pigeon_Wire_V1_GroupMessageReceived) {
    self.init(
      groupID: proto.groupID, messageID: proto.messageID,
      senderIdentity: proto.senderIdentity, body: proto.body,
      replyToMessageID: proto.replyToMessageID.nilIfEmpty, epoch: proto.epoch)
  }
}

extension PigeonGroupReactionReceivedEvent {
  init(proto: Pigeon_Wire_V1_GroupReactionReceived) {
    self.init(
      groupID: proto.groupID, messageID: proto.messageID,
      senderIdentity: proto.senderIdentity, targetMessageID: proto.targetMessageID,
      reaction: proto.reaction, epoch: proto.epoch)
  }
}

extension PigeonGroupPolicyChangedEvent {
  init(proto: Pigeon_Wire_V1_GroupPolicyChanged) {
    self.init(
      kind: PigeonGroupPolicyChangeKind(proto: proto.kind), groupID: proto.groupID,
      actorIdentity: proto.actorIdentity, subjectIdentity: proto.subjectIdentity,
      epoch: proto.epoch, policyRevision: proto.policyRevision, name: proto.name,
      meshEnabled: proto.meshEnabled, relayURL: proto.relayURL)
  }
}

extension PigeonGroupDeliveryChangedEvent {
  init(proto: Pigeon_Wire_V1_GroupDeliveryChanged) {
    self.init(
      groupID: proto.groupID, messageID: proto.messageID,
      state: PigeonGroupDeliveryState(proto: proto.state), epoch: proto.epoch,
      deliveredCount: proto.deliveredCount, intendedCount: proto.intendedCount)
  }
}

extension PigeonGroupSecurityWarningEvent {
  init(proto: Pigeon_Wire_V1_GroupSecurityWarning) {
    self.init(
      groupID: proto.groupID, code: proto.code,
      evidenceID: proto.evidenceID, epoch: proto.epoch)
  }
}

extension PigeonCoreOutboundKind {
  init(proto: Pigeon_Wire_V1_OutboundKind) {
    switch proto {
    case .unspecified: self = .unspecified
    case .pairwise: self = .pairwise
    case .groupMessage: self = .groupMessage
    case .groupCoordinator: self = .groupCoordinator
    case .groupJoinRequest: self = .groupJoinRequest
    case .mesh: self = .mesh
    case .groupJoinMaterial: self = .groupJoinMaterial
    case .groupWelcome: self = .groupWelcome
    case .groupRelayRegistration: self = .groupRelayRegistration
    case .groupRelayControl: self = .groupRelayControl
    case .groupLeaveProposal: self = .groupLeaveProposal
    case .UNRECOGNIZED(let raw): self = .unknown(raw)
    }
  }

  func proto() throws -> Pigeon_Wire_V1_OutboundKind {
    switch self {
    case .unspecified: return .unspecified
    case .pairwise: return .pairwise
    case .groupMessage: return .groupMessage
    case .groupCoordinator: return .groupCoordinator
    case .groupJoinRequest: return .groupJoinRequest
    case .mesh: return .mesh
    case .groupJoinMaterial: return .groupJoinMaterial
    case .groupWelcome: return .groupWelcome
    case .groupRelayRegistration: return .groupRelayRegistration
    case .groupRelayControl: return .groupRelayControl
    case .groupLeaveProposal: return .groupLeaveProposal
    case .unknown(let raw): throw PigeonCoreWireError.invalidOutboundKind(raw)
    }
  }
}

extension PigeonGroupPolicyChangeKind {
  init(proto: Pigeon_Wire_V1_GroupPolicyChangeKind) {
    switch proto {
    case .unspecified: self = .unspecified
    case .memberAdded: self = .memberAdded
    case .memberRemoved: self = .memberRemoved
    case .memberLeft: self = .memberLeft
    case .adminPromoted: self = .adminPromoted
    case .adminDemoted: self = .adminDemoted
    case .nameChanged: self = .nameChanged
    case .meshChanged: self = .meshChanged
    case .relayChanged: self = .relayChanged
    case .dissolved: self = .dissolved
    case .UNRECOGNIZED(let raw): self = .unknown(raw)
    }
  }

  func proto() throws -> Pigeon_Wire_V1_GroupPolicyChangeKind {
    switch self {
    case .unspecified: return .unspecified
    case .memberAdded: return .memberAdded
    case .memberRemoved: return .memberRemoved
    case .memberLeft: return .memberLeft
    case .adminPromoted: return .adminPromoted
    case .adminDemoted: return .adminDemoted
    case .nameChanged: return .nameChanged
    case .meshChanged: return .meshChanged
    case .relayChanged: return .relayChanged
    case .dissolved: return .dissolved
    case .unknown(let raw): throw PigeonCoreWireError.invalidPolicyChangeKind(raw)
    }
  }
}

extension PigeonGroupDeliveryState {
  init(proto: Pigeon_Wire_V1_GroupDeliveryState) {
    switch proto {
    case .unspecified: self = .unspecified
    case .sending: self = .sending
    case .sent: self = .sent
    case .deliveredTo: self = .deliveredTo
    case .delivered: self = .delivered
    case .failed: self = .failed
    case .expired: self = .expired
    case .UNRECOGNIZED(let raw): self = .unknown(raw)
    }
  }
}

extension String {
  var nilIfEmpty: String? { isEmpty ? nil : self }
}
