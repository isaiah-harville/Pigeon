//
//  ScreenshotOutboxTests.swift
//  PigeonTests
//

import XCTest

@testable import Pigeon

@MainActor
final class ScreenshotOutboxTests: XCTestCase {
  func testEphemeralScreenshotPersistsOnlyUntilDelivered() throws {
    let contactID = Data(repeating: 3, count: 32)
    var event = ChatMessage(mine: true, text: "You reported a screenshot", pending: true)
    event.system = true
    event.event = .screenshot
    event.transientOutbox = true
    let store = ConversationStore()

    store.record(event, for: contactID, ephemeral: true)

    XCTAssertEqual(store.pending(for: contactID).map(\.id), [event.id])
    XCTAssertEqual(store.persistedConversations[contactID]?.map(\.id), [event.id])

    store.setDelivery(.delivered, messageID: event.id, contactID: contactID)

    XCTAssertEqual(store.messages(for: contactID).first?.delivery, .delivered)
    XCTAssertNil(store.persistedConversations[contactID])
  }

  func testOrdinaryEphemeralMessagesNeverEnterOutbox() {
    let contactID = Data(repeating: 4, count: 32)
    let message = ChatMessage(mine: true, text: "secret", pending: true)
    let store = ConversationStore()

    store.record(message, for: contactID, ephemeral: true)

    XCTAssertNil(store.persistedConversations[contactID])
  }
}
