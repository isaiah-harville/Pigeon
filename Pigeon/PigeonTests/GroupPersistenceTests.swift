import CryptoKit
import Foundation
import XCTest

@testable import Pigeon

@MainActor
final class GroupPersistenceTests: XCTestCase {
  func testGroupConversationHistorySurvivesSaveAndReload() throws {
    let store = freshStore()
    let persistence = SessionPersistence()
    let groupID = Data(repeating: 31, count: 32)
    var conversation = GroupConversation(id: groupID)
    conversation.messages.append(
      GroupChatEntry(
        id: UUID().uuidString,
        senderIdentity: Data(repeating: 32, count: 32),
        mine: true,
        content: .message("hello flock", replyToMessageID: nil),
        epoch: 2))
    conversation.markProcessed("event-1")

    _ = try persistence.attach(store)
    XCTAssertTrue(
      persistence.save(
        SessionPersistence.Snapshot(
          contacts: [],
          conversations: [:],
          groupConversations: [groupID: conversation],
          ephemeralContactIDs: [],
          bluetoothChatIDs: [],
          myName: "Alice")))

    let reloaded = try persistence.attach(store)
    XCTAssertEqual(reloaded.groupConversations[groupID], conversation)
  }

  private func freshStore() -> EncryptedStore {
    let store = EncryptedStore(key: SymmetricKey(size: .bits256))
    store.wipe()
    store.companion(suffix: ".crypto").wipe()
    store.companion(suffix: ".transaction").wipe()
    return store
  }
}
