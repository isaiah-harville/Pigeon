import Foundation
import SwiftProtobuf

public enum PigeonCoreWireError: Error, Equatable, Sendable {
  case invalidCommandBody
  case missingEventBody
  case invalidOutboundKind(Int)
  case invalidPolicyChangeKind(Int)
  case invalidDirectTransportMode(Int)
  case invalidPairwiseRelationship(Int)
  case notRelayAction(PigeonCoreOutboundKind)
  case malformedRelayAction
}

extension FfiClient {
  public func execute(_ command: PigeonCoreCommand) throws -> PigeonCoreOutput {
    let proto = try command.proto()
    let encoded = try proto.serializedData()
    let output = try Pigeon_Wire_V1_ClientOutput(serializedBytes: execute(command: encoded))
    return try PigeonCoreOutput(proto: output)
  }

  public func stateSnapshot() throws -> PigeonCoreSnapshot {
    let proto = try Pigeon_Wire_V1_ClientSnapshot(serializedBytes: snapshot())
    return try PigeonCoreSnapshot(proto: proto)
  }

  /// Signs a relay-issued nonce with the authenticated capability for this
  /// group. Transcript construction and private-key access remain in Rust.
  public func relayChallengeSignature(groupID: Data, nonce: Data) throws -> Data {
    try signGroupRelayChallenge(groupId: groupID, nonce: nonce)
  }
}

extension PigeonCoreOutput {
  init(proto: Pigeon_Wire_V1_ClientOutput) throws {
    checkpointGeneration = proto.checkpointGeneration
    events = try proto.events.map(PigeonCoreEvent.init(proto:))
    outbound = proto.outbound.map(PigeonCoreOutboundItem.init(proto:))
  }
}

extension PigeonCreateGroup {
  func proto() -> Pigeon_Wire_V1_CreateGroup {
    var body = Pigeon_Wire_V1_CreateGroup()
    body.name = name
    body.memberIdentities = memberIdentities
    body.relayURL = relayURL
    body.meshEnabled = meshEnabled
    body.coordinatorPublicKey = coordinatorPublicKey
    return body
  }
}

extension PigeonAcknowledgeEffects {
  func proto() -> Pigeon_Wire_V1_AcknowledgeEffects {
    var body = Pigeon_Wire_V1_AcknowledgeEffects()
    body.outboundItemIds = outboundItemIDs
    body.eventIds = eventIDs
    return body
  }
}

extension PigeonCoreOutboundItem {
  init(proto: Pigeon_Wire_V1_OutboundItem) {
    id = proto.itemID
    kind = PigeonCoreOutboundKind(proto: proto.kind)
    relayURL = proto.relayURL
    destination = proto.destination
    payload = proto.payload
    localOnly = proto.localOnly
  }

  public func relayAction() throws -> PigeonCoreRelayAction {
    guard destination.count == 32, !payload.isEmpty else {
      throw PigeonCoreWireError.malformedRelayAction
    }
    switch kind {
    case .groupMessage:
      return .append(
        PigeonGroupRelayAppend(coordinationID: destination, ciphertext: payload))
    case .groupRelayRegistration:
      return try decodeRegistration()
    case .groupRelayControl:
      return try decodeControl()
    case .groupCoordinator:
      return try decodeCoordinatorAction()
    default:
      throw PigeonCoreWireError.notRelayAction(kind)
    }
  }

  private func decodeRegistration() throws -> PigeonCoreRelayAction {
    let value = try Pigeon_Wire_V1_GroupRelayRegistration(serializedBytes: payload)
    guard value.version == 2,
      value.coordinationID == destination,
      value.signature.count == 64,
      value.permanentControllerPublicKey.count == 32,
      !value.capabilities.isEmpty,
      value.capabilities.allSatisfy({ $0.capabilityID.count == 32 && $0.publicKey.count == 32 })
    else {
      throw PigeonCoreWireError.malformedRelayAction
    }
    return .registration(
      PigeonGroupRelayRegistration(
        coordinationID: value.coordinationID,
        capabilities: value.capabilities.map(PigeonGroupRelayCapability.init(proto:)),
        signature: value.signature,
        authorizationGeneration: value.authorizationGeneration,
        permanentControllerPublicKey: value.permanentControllerPublicKey))
  }

  private func decodeControl() throws -> PigeonCoreRelayAction {
    let value = try Pigeon_Wire_V1_GroupRelayControl(serializedBytes: payload)
    guard value.version == 2,
      value.coordinationID == destination,
      value.permanentControllerPublicKey.count == 32,
      value.capabilities.allSatisfy({ $0.capabilityID.count == 32 && $0.publicKey.count == 32 })
    else {
      throw PigeonCoreWireError.malformedRelayAction
    }
    return .control(PigeonGroupRelayControl(proto: value))
  }

  private func decodeCoordinatorAction() throws -> PigeonCoreRelayAction {
    if let fetch = try? Pigeon_Wire_V1_GroupEpochFetch(serializedBytes: payload),
      fetch.version == 1,
      fetch.groupID.count == 32,
      fetch.fromEpoch <= fetch.throughEpoch
    {
      return .coordinatorFetch(
        PigeonGroupCoordinatorFetch(
          coordinationID: destination, groupID: fetch.groupID,
          fromEpoch: fetch.fromEpoch, throughEpoch: fetch.throughEpoch))
    }
    let submission = try Pigeon_Wire_V1_GroupCoordinatorSubmission(serializedBytes: payload)
    guard submission.version == 1, !submission.candidate.isEmpty else {
      throw PigeonCoreWireError.malformedRelayAction
    }
    return .coordinatorSubmission(
      PigeonGroupCoordinatorSubmission(
        coordinationID: destination, claimedBaseEpoch: submission.claimedBaseEpoch,
        candidate: submission.candidate))
  }
}

extension PigeonGroupRelayCapability {
  init(proto: Pigeon_Wire_V1_GroupRelayCapability) {
    self.init(
      capabilityID: proto.capabilityID, publicKey: proto.publicKey, canAppend: proto.canAppend,
      canRead: proto.canRead, canControl: proto.canControl)
  }
}

extension PigeonGroupRelayControl {
  init(proto: Pigeon_Wire_V1_GroupRelayControl) {
    self.init(
      coordinationID: proto.coordinationID,
      kind: PigeonGroupRelayControlKind(proto: proto.kind),
      publicKey: proto.publicKey,
      capabilities: proto.capabilities.map(PigeonGroupRelayCapability.init(proto:)),
      expectedGeneration: proto.expectedGeneration,
      newGeneration: proto.newGeneration,
      permanentControllerPublicKey: proto.permanentControllerPublicKey)
  }
}

extension PigeonGroupRelayControlKind {
  init(proto: Pigeon_Wire_V1_GroupRelayControlKind) {
    switch proto {
    case .unspecified: self = .unspecified
    case .replaceAll: self = .replaceAll
    case .grant, .revoke, .promoteAdmin, .demoteAdmin: self = .unknown(proto.rawValue)
    case .UNRECOGNIZED(let raw): self = .unknown(raw)
    }
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
    case .directApplicationReceived(let event):
      body = .directApplicationReceived(
        PigeonDirectApplicationReceivedEvent(
          senderIdentity: event.senderIdentity,
          application: try PigeonDirectApplication(proto: event.application),
          senderContactCard: event.senderContactCard))
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
