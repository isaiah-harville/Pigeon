import CryptoKit
import PigeonFFI
import XCTest

@testable import Pigeon

// Message requests between peers where one side also scanned the other in
// person. Shares the two-device helpers in MessageRequestTests.swift.
// swiftlint:disable identifier_name
extension MessageRequestTests {
  func testScanningAnIncomingRequesterInPersonAcceptsTheRequest() throws {
    let bus = TestBus()
    let keyA = SymmetricKey(size: .bits256)
    let keyB = SymmetricKey(size: .bits256)
    let a = try launchFresh(seed: seed(), key: keyA, file: "requests-rescan-a.store", bus: bus)
    let b = try launchFresh(seed: seed(), key: keyB, file: "requests-rescan-b.store", bus: bus)
    try addRemoteCard(of: b, to: a)
    let bOnA = try XCTUnwrap(a.contacts.first { $0.id == b.myID })
    a.send("Hello from Alice", to: bOnA)
    XCTAssertEqual(b.contacts.first { $0.id == a.myID }?.requestState, .incoming)

    try addCard(of: a, to: b, admission: .verifiedInPerson)

    let aOnB = try XCTUnwrap(b.contacts.first { $0.id == a.myID })
    XCTAssertEqual(aOnB.requestState, .none)
    XCTAssertTrue(b.canSendMessage(to: aOnB))
    b.send("Hi Alice", to: aOnB)
    XCTAssertEqual(a.messages(with: bOnA).last { !$0.system }?.text, "Hi Alice")
    XCTAssertEqual(
      a.contacts.first { $0.id == b.myID }?.requestState, ContactRequestState.none)
    a.send("Glad we met", to: bOnA)
    XCTAssertEqual(b.messages(with: aOnB).last { !$0.system }?.text, "Glad we met")
  }

  func testRequestToSomeoneWhoScannedUsInPersonOpensTheChat() throws {
    let bus = TestBus()
    let keyA = SymmetricKey(size: .bits256)
    let keyB = SymmetricKey(size: .bits256)
    let a = try launchFresh(seed: seed(), key: keyA, file: "requests-scanned-us-a.store", bus: bus)
    let b = try launchFresh(seed: seed(), key: keyB, file: "requests-scanned-us-b.store", bus: bus)
    try addCard(of: a, to: b, admission: .verifiedInPerson)
    try addRemoteCard(of: b, to: a)
    let bOnA = try XCTUnwrap(a.contacts.first { $0.id == b.myID })

    a.send("Hello from Alice", to: bOnA)

    let aOnB = try XCTUnwrap(b.contacts.first { $0.id == a.myID })
    XCTAssertEqual(b.messages(with: aOnB).last { !$0.system }?.text, "Hello from Alice")
    b.send("Hi Alice", to: aOnB)
    XCTAssertEqual(a.messages(with: bOnA).last { !$0.system }?.text, "Hi Alice")
    XCTAssertEqual(
      a.contacts.first { $0.id == b.myID }?.requestState, ContactRequestState.none)
  }
}
// swiftlint:enable identifier_name
