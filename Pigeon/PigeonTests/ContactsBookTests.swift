//
//  ContactsBookTests.swift
//  PigeonTests
//
//  Coordinator-level tests for the contacts-book / conversation split (#69, #75):
//  deleting a conversation must clear its history and drop it from the home (chats)
//  list while keeping the contact and its live Olm session — so re-opening the chat
//  continues with no re-handshake and no re-scan. Reuses the in-process bus harness
//  from SessionRelaunchDeliveryTests.
//

import CryptoKit
import PigeonFFI
import XCTest

@testable import Pigeon

@MainActor
final class ContactsBookTests: XCTestCase {

  // MARK: - Harness

  private func launch(seed: Data, key: SymmetricKey, storeFile: String, bus: TestBus) throws
    -> SessionManager
  {
    let identity = try IdentityManager(store: InMemoryKeyStore(seed: seed))
    let transport = FakeTransport(identity: identity.publicKey.rawRepresentation, bus: bus)
    let manager = SessionManager(identity: identity, mesh: MeshService(transport: transport))
    let store = EncryptedStore(key: key, fileName: storeFile)
    manager.attachStore(store)
    bus.connect(identity.publicKey.rawRepresentation, transport)
    return manager
  }

  private func card(_ manager: SessionManager) throws -> (PigeonIdentityBundle, PigeonPrekeyBundle)
  {
    let account = try XCTUnwrap(manager.account)
    return (
      try PigeonIdentityBundle(decoding: account.identityBundle()),
      try PigeonPrekeyBundle(decoding: account.signedPrekeyBundle())
    )
  }

  private func newSeed() -> Data { Curve25519.Signing.PrivateKey().rawRepresentation }

  private func wipe(_ key: SymmetricKey, _ file: String) {
    EncryptedStore(key: key, fileName: file).wipe()
    EncryptedStore(key: key, fileName: file).companion(suffix: ".crypto").wipe()
  }

  private func contact(_ manager: SessionManager, _ id: Data) -> Contact {
    manager.contacts.first { $0.id == id }!
  }

  /// Stands up an established session between two managers, ordering the adds by
  /// the deterministic initiator rule so neither initiation is dropped on arrival.
  private func establish(_ a: SessionManager, _ b: SessionManager) throws {
    let aIsInitiator = a.isInitiator(toward: b.myID)
    let initiator = aIsInitiator ? a : b
    let responder = aIsInitiator ? b : a
    let (initiatorBundle, initiatorPrekey) = try card(initiator)
    let (responderBundle, responderPrekey) = try card(responder)
    responder.addContact(
      initiatorBundle, name: "Init", relayURLs: [], prekeyBundle: initiatorPrekey,
      verifiedInPerson: true)
    initiator.addContact(
      responderBundle, name: "Resp", relayURLs: [], prekeyBundle: responderPrekey,
      verifiedInPerson: true)
    XCTAssertTrue(a.establishedContactIDs.contains(b.myID))
    XCTAssertTrue(b.establishedContactIDs.contains(a.myID))
  }

  // MARK: - Tests

  /// Deleting a conversation clears its history and drops it from the chats list,
  /// but keeps the contact in the book and its session live — and re-opening the
  /// chat then sending works with no re-handshake.
  func testDeleteConversationKeepsContactAndSession() throws {
    let bus = TestBus()
    let (keyA, keyB) = (SymmetricKey(size: .bits256), SymmetricKey(size: .bits256))
    wipe(keyA, "cbookA.store")
    wipe(keyB, "cbookB.store")

    let a = try launch(seed: newSeed(), key: keyA, storeFile: "cbookA.store", bus: bus)
    let b = try launch(seed: newSeed(), key: keyB, storeFile: "cbookB.store", bus: bus)
    try establish(a, b)

    // A sends; B receives, so B has a real conversation on its chats list.
    a.send("hi there", to: contact(a, b.myID))
    XCTAssertTrue(b.messages(with: contact(b, a.myID)).contains { $0.text == "hi there" })
    XCTAssertTrue(b.chatContacts.contains { $0.id == a.myID })

    // B deletes the conversation.
    b.deleteConversation(with: contact(b, a.myID))

    XCTAssertTrue(b.contacts.contains { $0.id == a.myID }, "contact stays in the book")
    XCTAssertFalse(b.chatContacts.contains { $0.id == a.myID }, "chat leaves the home list")
    XCTAssertTrue(b.messages(with: contact(b, a.myID)).isEmpty, "history is cleared")
    XCTAssertNotNil(b.sessions[a.myID], "Olm session is untouched")
    XCTAssertTrue(b.establishedContactIDs.contains(a.myID), "still established")

    // Re-open from the book and send: no re-handshake, A receives it.
    b.startConversation(with: contact(b, a.myID))
    XCTAssertTrue(b.chatContacts.contains { $0.id == a.myID })
    b.send("back again", to: contact(b, a.myID))
    XCTAssertTrue(a.messages(with: contact(a, b.myID)).contains { $0.text == "back again" })
  }

  /// A deleted conversation stays deleted across relaunch (the active-conversation
  /// set persists), while the contact remains in the book.
  func testDeletedConversationStaysDeletedAfterRelaunch() throws {
    let bus = TestBus()
    let seedA = newSeed()
    let (keyA, keyB) = (SymmetricKey(size: .bits256), SymmetricKey(size: .bits256))
    wipe(keyA, "cbookRA.store")
    wipe(keyB, "cbookRB.store")

    let a = try launch(seed: seedA, key: keyA, storeFile: "cbookRA.store", bus: bus)
    let b = try launch(seed: newSeed(), key: keyB, storeFile: "cbookRB.store", bus: bus)
    try establish(a, b)
    b.send("yo", to: contact(b, a.myID))
    let bID = b.myID

    a.deleteConversation(with: contact(a, bID))
    XCTAssertFalse(a.chatContacts.contains { $0.id == bID })

    // Relaunch A from its persisted store.
    let relaunched = try launch(seed: seedA, key: keyA, storeFile: "cbookRA.store", bus: bus)
    XCTAssertTrue(relaunched.contacts.contains { $0.id == bID }, "contact persists")
    XCTAssertFalse(
      relaunched.chatContacts.contains { $0.id == bID }, "deletion persists across relaunch")
  }

  /// `removeContact` fully forgets a contact: it leaves the book and its session
  /// is reset (the deliberate re-scan path), unlike `deleteConversation`.
  func testRemoveContactForgetsEverything() throws {
    let bus = TestBus()
    let (keyA, keyB) = (SymmetricKey(size: .bits256), SymmetricKey(size: .bits256))
    wipe(keyA, "cbookXA.store")
    wipe(keyB, "cbookXB.store")

    let a = try launch(seed: newSeed(), key: keyA, storeFile: "cbookXA.store", bus: bus)
    let b = try launch(seed: newSeed(), key: keyB, storeFile: "cbookXB.store", bus: bus)
    try establish(a, b)
    let aID = a.myID

    b.removeContact(contact(b, aID))

    XCTAssertFalse(b.contacts.contains { $0.id == aID }, "contact is gone from the book")
    XCTAssertFalse(b.chatContacts.contains { $0.id == aID })
    XCTAssertNil(b.sessions[aID], "session is reset")
    XCTAssertFalse(b.establishedContactIDs.contains(aID))
  }
}
