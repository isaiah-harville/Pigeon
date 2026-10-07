import CryptoKit
import XCTest

@testable import Pigeon

final class IdentityMoveArchiveTests: XCTestCase {
  func testArchiveKeepsGroupProjectionAndOmitsSavedHistory() throws {
    let groupID = Data(repeating: 5, count: 32)
    var group = GroupConversation(id: groupID)
    group.messages = [
      GroupChatEntry(
        id: "old-message", senderIdentity: nil, mine: true,
        content: .message("old text", replyToMessageID: nil), epoch: 1)
    ]
    group.markProcessed("old-message")
    var state = PersistedState()
    state.conversations["peer"] = []
    state.groupConversations[groupID.base64EncodedString()] = group
    state.myName = "Ada"
    let checkpointBytes = Data("checkpoint".utf8)
    let checkpoint = PersistedCoreCheckpoint(
      generation: 1, bytes: checkpointBytes,
      sha256: Data(SHA256.hash(data: checkpointBytes)))

    let archive = try IdentityMoveArchive(
      transferID: UUID(), rootSeed: Data(repeating: 9, count: 32),
      scopedKeySeeds: ["identity.mls.ed25519.private": Data(repeating: 8, count: 32)],
      checkpoint: checkpoint, appState: state, relayURLs: [])
    let decoded = try IdentityMoveArchive.decode(archive.encode())

    XCTAssertEqual(decoded.appState.myName, "Ada")
    XCTAssertTrue(decoded.appState.conversations.isEmpty)
    XCTAssertTrue(
      decoded.appState.groupConversations[groupID.base64EncodedString()]?.messages.isEmpty == true)
    XCTAssertTrue(
      decoded.appState.groupConversations[groupID.base64EncodedString()]?.hasProcessed(
        "old-message") == true)
  }

  func testArchiveRejectsWrongCheckpointDigestAndInvalidKeySlot() {
    let checkpoint = PersistedCoreCheckpoint(
      generation: 1, bytes: Data("checkpoint".utf8), sha256: Data(repeating: 0, count: 32))
    XCTAssertThrowsError(
      try IdentityMoveArchive(
        transferID: UUID(), rootSeed: Data(repeating: 9, count: 32),
        scopedKeySeeds: [:], checkpoint: checkpoint, appState: PersistedState(), relayURLs: []))
    let validBytes = Data("checkpoint".utf8)
    let validCheckpoint = PersistedCoreCheckpoint(
      generation: 1, bytes: validBytes, sha256: Data(SHA256.hash(data: validBytes)))
    XCTAssertThrowsError(
      try IdentityMoveArchive(
        transferID: UUID(), rootSeed: Data(repeating: 9, count: 32),
        scopedKeySeeds: ["identity.ed25519.private": Data(repeating: 8, count: 32)],
        checkpoint: validCheckpoint, appState: PersistedState(), relayURLs: []))
  }
}
