import CryptoKit
import PigeonFFI
import XCTest

@testable import Pigeon

// Blocking and relaunch durability for message requests. Shares the two-device
// helpers in MessageRequestTests.swift.
// swiftlint:disable identifier_name
extension MessageRequestTests {
  func testBlockedIdentityCannotCreateAnotherRequestAndCanBeUnblocked() throws {
    let bus = TestBus()
    let keyA = SymmetricKey(size: .bits256)
    let keyB = SymmetricKey(size: .bits256)
    wipe(keyA, "requests-block-a.store")
    wipe(keyB, "requests-block-b.store")
    let a = try launch(seed: seed(), key: keyA, file: "requests-block-a.store", bus: bus)
    let b = try launch(seed: seed(), key: keyB, file: "requests-block-b.store", bus: bus)

    try addRemoteCard(of: b, to: a)
    a.send("intro", to: try XCTUnwrap(a.contacts.first { $0.id == b.myID }))
    let request = try XCTUnwrap(b.contacts.first { $0.id == a.myID })
    b.blockContact(request)

    XCTAssertTrue(b.blockedContactIDs.contains(a.myID))
    XCTAssertFalse(b.contacts.contains { $0.id == a.myID })
    a.send("blocked retry", to: try XCTUnwrap(a.contacts.first { $0.id == b.myID }))
    XCTAssertFalse(b.contacts.contains { $0.id == a.myID })

    b.unblockContact(id: a.myID)
    XCTAssertFalse(b.blockedContactIDs.contains(a.myID))
  }

  func testRequestAndBlockedIdentitiesSurviveRelaunch() throws {
    let bus = TestBus()
    let keyA = SymmetricKey(size: .bits256)
    let keyB = SymmetricKey(size: .bits256)
    let fileA = "requests-persist-a.store"
    let fileB = "requests-persist-b.store"
    wipe(keyA, fileA)
    wipe(keyB, fileB)
    let seedA = seed()
    let seedB = seed()
    let a = try launch(seed: seedA, key: keyA, file: fileA, bus: bus)
    let b = try launch(seed: seedB, key: keyB, file: fileB, bus: bus)

    try addRemoteCard(of: b, to: a)
    a.send("intro", to: try XCTUnwrap(a.contacts.first { $0.id == b.myID }))
    let request = try XCTUnwrap(b.contacts.first { $0.id == a.myID })
    XCTAssertEqual(request.requestState, .incoming)
    b.blockContact(request)

    bus.disconnect(b.myID)
    let relaunched = try launch(seed: seedB, key: keyB, file: fileB, bus: bus)
    XCTAssertTrue(relaunched.blockedContactIDs.contains(a.myID))
  }

  func testOutgoingIntroductionLimitSurvivesConversationDeletionAndRelaunch() throws {
    let bus = TestBus()
    let keyA = SymmetricKey(size: .bits256)
    let keyB = SymmetricKey(size: .bits256)
    let fileA = "requests-intro-limit-a.store"
    let fileB = "requests-intro-limit-b.store"
    wipe(keyA, fileA)
    wipe(keyB, fileB)
    let seedA = seed()
    let a = try launch(seed: seedA, key: keyA, file: fileA, bus: bus)
    let b = try launch(seed: seed(), key: keyB, file: fileB, bus: bus)

    try addRemoteCard(of: b, to: a)
    let bOnA = try XCTUnwrap(a.contacts.first { $0.id == b.myID })
    a.send("only introduction", to: bOnA)
    a.deleteConversation(with: bOnA)
    XCTAssertFalse(a.canSendMessage(to: bOnA))
    try addRemoteCard(of: b, to: a)
    XCTAssertFalse(
      a.canSendMessage(to: try XCTUnwrap(a.contacts.first { $0.id == b.myID })),
      "re-importing the same contact link must not reset the introduction limit")

    bus.disconnect(a.myID)
    let relaunched = try launch(seed: seedA, key: keyA, file: fileA, bus: bus)
    let restored = try XCTUnwrap(relaunched.contacts.first { $0.id == b.myID })
    XCTAssertFalse(relaunched.canSendMessage(to: restored))
  }
}
// swiftlint:enable identifier_name
