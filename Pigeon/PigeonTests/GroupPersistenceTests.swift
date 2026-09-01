import CryptoKit
import Foundation
import PigeonFFI
import XCTest

@testable import Pigeon

@MainActor
final class GroupPersistenceTests: XCTestCase {
  func testGroupConversationHistorySurvivesSaveAndReload() throws {
    let store = freshStore()
    let persistence = SessionPersistence()
    let account = try PigeonAccount.generate()
    let groupID = Data(repeating: 31, count: 32)
    var conversation = GroupConversation(id: groupID)
    conversation.messages.append(
      GroupChatEntry(
        id: UUID().uuidString,
        senderIdentity: account.identityPublicKey(),
        mine: true,
        content: .message("hello flock", replyToMessageID: nil),
        epoch: 2))
    conversation.markProcessed("event-1")

    _ = try persistence.attach(store, identitySeed: account.exportSeed())
    XCTAssertTrue(
      persistence.save(
        SessionPersistence.Snapshot(
          contacts: [],
          conversations: [:],
          groupConversations: [groupID: conversation],
          ephemeralContactIDs: [],
          bluetoothChatIDs: [],
          myName: "Alice",
          account: account,
          sessions: [:],
          pendingInitiation: [:],
          lastInitiationIn: [:],
          fallbackRotatedAt: nil)))

    let reloaded = try persistence.attach(store, identitySeed: account.exportSeed())
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
