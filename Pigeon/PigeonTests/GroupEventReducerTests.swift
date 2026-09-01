import Foundation
import PigeonFFI
import XCTest

@testable import Pigeon

final class GroupEventReducerTests: XCTestCase {
  private let groupID = Data(repeating: 1, count: 32)
  private let alice = Data(repeating: 2, count: 32)
  private let bob = Data(repeating: 3, count: 32)

  func testMemberAddedProducesStructuredStatusWithoutRemoteText() throws {
    var conversation = GroupConversation(id: groupID)
    let event = PigeonCoreEvent(
      id: "policy-1",
      body: .groupPolicyChanged(
        PigeonGroupPolicyChangedEvent(
          kind: .memberAdded,
          groupID: groupID,
          actorIdentity: alice,
          subjectIdentity: bob,
          epoch: 4,
          policyRevision: 2,
          name: "Birds",
          meshEnabled: false,
          relayURL: "https://relay.example")))

    try GroupEventReducer.reduce(event, into: &conversation, localIdentity: alice)

    XCTAssertEqual(
      conversation.messages.last?.content,
      .status(.memberAdded(actor: alice, subject: bob)))
  }

  func testMessageReactionAndDeliveryReduceByAuthenticatedIdentifiers() throws {
    var conversation = GroupConversation(id: groupID)
    let messageID = UUID().uuidString
    let message = PigeonCoreEvent(
      id: "message-event",
      body: .groupMessageReceived(
        PigeonGroupMessageReceivedEvent(
          groupID: groupID,
          messageID: messageID,
          senderIdentity: bob,
          body: Data("hello".utf8),
          replyToMessageID: nil,
          epoch: 3)))
    let reaction = PigeonCoreEvent(
      id: "reaction-event",
      body: .groupReactionReceived(
        PigeonGroupReactionReceivedEvent(
          groupID: groupID,
          messageID: UUID().uuidString,
          senderIdentity: alice,
          targetMessageID: messageID,
          reaction: "👍",
          epoch: 3)))
    let delivery = PigeonCoreEvent(
      id: "delivery-event",
      body: .groupDeliveryChanged(
        PigeonGroupDeliveryChangedEvent(
          groupID: groupID,
          messageID: messageID,
          state: .deliveredTo,
          epoch: 3,
          deliveredCount: 1,
          intendedCount: 2)))

    try GroupEventReducer.reduce(message, into: &conversation, localIdentity: alice)
    try GroupEventReducer.reduce(reaction, into: &conversation, localIdentity: alice)
    try GroupEventReducer.reduce(delivery, into: &conversation, localIdentity: alice)

    XCTAssertEqual(conversation.messages.first?.content, .message("hello", replyToMessageID: nil))
    XCTAssertEqual(conversation.messages.first?.reactions, [alice: "👍"])
    XCTAssertEqual(
      conversation.messages.first?.delivery,
      GroupDeliverySummary(state: .deliveredTo, deliveredCount: 1, intendedCount: 2))
  }

  func testDuplicateEventIsIgnored() throws {
    var conversation = GroupConversation(id: groupID)
    let event = PigeonCoreEvent(
      id: "created",
      body: .groupCreated(
        PigeonGroupCreatedEvent(
          groupID: groupID,
          ownerIdentity: alice,
          name: "Birds",
          relayURL: "https://relay.example",
          meshEnabled: false,
          epoch: 1,
          policyRevision: 1)))

    try GroupEventReducer.reduce(event, into: &conversation, localIdentity: alice)
    try GroupEventReducer.reduce(event, into: &conversation, localIdentity: alice)

    XCTAssertEqual(conversation.messages.count, 1)
  }
}
