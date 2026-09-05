import Foundation
import PigeonFFI

enum GroupEventReducer {
  static func reduce(
    _ event: PigeonCoreEvent,
    into conversation: inout GroupConversation,
    localIdentity: Data
  ) throws {
    guard !conversation.hasProcessed(event.id) else { return }
    switch event.body {
    case .groupCreated(let value):
      try reduceCreated(value, eventID: event.id, into: &conversation, localIdentity: localIdentity)
    case .groupMessageReceived(let value):
      try reduceMessage(value, into: &conversation, localIdentity: localIdentity)
    case .groupReactionReceived(let value):
      try reduceReaction(value, into: &conversation)
    case .groupPolicyChanged(let value):
      try reducePolicy(value, eventID: event.id, into: &conversation, localIdentity: localIdentity)
    case .groupDeliveryChanged(let value):
      try reduceDelivery(value, into: &conversation)
    case .groupSecurityWarning(let value):
      try reduceWarning(value, eventID: event.id, into: &conversation)
    }
    conversation.markProcessed(event.id)
  }

  private static func reduceReaction(
    _ event: PigeonGroupReactionReceivedEvent,
    into conversation: inout GroupConversation
  ) throws {
    try requireGroup(event.groupID, in: conversation)
    guard isCanonicalMessageID(event.messageID), isCanonicalMessageID(event.targetMessageID) else {
      throw GroupEventReductionError.invalidMessageID
    }
    guard let index = conversation.messages.firstIndex(where: { $0.id == event.targetMessageID })
    else {
      throw GroupEventReductionError.missingTargetMessage
    }
    conversation.messages[index].reactions[event.senderIdentity] = event.reaction
  }

  private static func reduceDelivery(
    _ event: PigeonGroupDeliveryChangedEvent,
    into conversation: inout GroupConversation
  ) throws {
    try requireGroup(event.groupID, in: conversation)
    guard isCanonicalMessageID(event.messageID) else {
      throw GroupEventReductionError.invalidMessageID
    }
    guard let index = conversation.messages.firstIndex(where: { $0.id == event.messageID }) else {
      throw GroupEventReductionError.missingTargetMessage
    }
    conversation.messages[index].delivery = GroupDeliverySummary(
      state: try delivery(from: event.state),
      deliveredCount: event.deliveredCount,
      intendedCount: event.intendedCount)
  }

  private static func reduceCreated(
    _ event: PigeonGroupCreatedEvent,
    eventID: String,
    into conversation: inout GroupConversation,
    localIdentity: Data
  ) throws {
    try requireGroup(event.groupID, in: conversation)
    conversation.messages.append(
      GroupChatEntry(
        id: eventID,
        senderIdentity: event.ownerIdentity,
        mine: event.ownerIdentity == localIdentity,
        content: .status(.created(owner: event.ownerIdentity)),
        epoch: event.epoch))
  }

  private static func reduceMessage(
    _ event: PigeonGroupMessageReceivedEvent,
    into conversation: inout GroupConversation,
    localIdentity: Data
  ) throws {
    try requireGroup(event.groupID, in: conversation)
    guard isCanonicalMessageID(event.messageID) else {
      throw GroupEventReductionError.invalidMessageID
    }
    guard let text = String(data: event.body, encoding: .utf8) else {
      throw GroupEventReductionError.invalidMessageBody
    }
    if !conversation.messages.contains(where: { $0.id == event.messageID }) {
      conversation.messages.append(
        GroupChatEntry(
          id: event.messageID,
          senderIdentity: event.senderIdentity,
          mine: event.senderIdentity == localIdentity,
          content: .message(text, replyToMessageID: event.replyToMessageID),
          epoch: event.epoch))
    }
  }

  private static func isCanonicalMessageID(_ value: String) -> Bool {
    value.utf8.count == 32
      && value.utf8.allSatisfy { byte in
        (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
          || (UInt8(ascii: "a")...UInt8(ascii: "f")).contains(byte)
      }
  }

  private static func reducePolicy(
    _ event: PigeonGroupPolicyChangedEvent,
    eventID: String,
    into conversation: inout GroupConversation,
    localIdentity: Data
  ) throws {
    try requireGroup(event.groupID, in: conversation)
    conversation.messages.append(
      GroupChatEntry(
        id: eventID,
        senderIdentity: event.actorIdentity,
        mine: event.actorIdentity == localIdentity,
        content: .status(try status(from: event)),
        epoch: event.epoch))
  }

  private static func reduceWarning(
    _ event: PigeonGroupSecurityWarningEvent,
    eventID: String,
    into conversation: inout GroupConversation
  ) throws {
    try requireGroup(event.groupID, in: conversation)
    conversation.messages.append(
      GroupChatEntry(
        id: eventID,
        senderIdentity: nil,
        mine: false,
        content: .securityWarning(code: event.code, evidenceID: event.evidenceID),
        epoch: event.epoch))
  }

  private static func requireGroup(
    _ groupID: Data,
    in conversation: GroupConversation
  ) throws {
    guard groupID == conversation.id else {
      throw GroupEventReductionError.unsupportedEvent
    }
  }

  private static func status(
    from event: PigeonGroupPolicyChangedEvent
  ) throws -> GroupStatusEvent {
    switch event.kind {
    case .memberAdded:
      return .memberAdded(actor: event.actorIdentity, subject: event.subjectIdentity)
    case .memberRemoved:
      return .memberRemoved(actor: event.actorIdentity, subject: event.subjectIdentity)
    case .memberLeft:
      return .memberLeft(actor: event.actorIdentity, subject: event.subjectIdentity)
    case .adminPromoted:
      return .adminPromoted(actor: event.actorIdentity, subject: event.subjectIdentity)
    case .adminDemoted:
      return .adminDemoted(actor: event.actorIdentity, subject: event.subjectIdentity)
    case .nameChanged:
      return .nameChanged(actor: event.actorIdentity, name: event.name)
    case .meshChanged:
      return .meshChanged(actor: event.actorIdentity, enabled: event.meshEnabled)
    case .relayChanged:
      return .relayChanged(actor: event.actorIdentity, relayURL: event.relayURL)
    case .dissolved:
      return .dissolved(actor: event.actorIdentity)
    case .unspecified, .unknown:
      throw GroupEventReductionError.unsupportedEvent
    }
  }

  private static func delivery(
    from state: PigeonGroupDeliveryState
  ) throws -> GroupDeliveryStatus {
    switch state {
    case .sending: return .sending
    case .sent: return .sent
    case .deliveredTo: return .deliveredTo
    case .delivered: return .delivered
    case .failed: return .failed
    case .expired: return .expired
    case .unspecified, .unknown:
      throw GroupEventReductionError.unsupportedEvent
    }
  }
}
