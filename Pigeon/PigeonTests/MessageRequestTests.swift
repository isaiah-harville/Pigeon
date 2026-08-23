import CryptoKit
import PigeonFFI
import XCTest

@testable import Pigeon

// Short peer names keep two-party protocol tests readable.
// swiftlint:disable type_body_length identifier_name
@MainActor
final class MessageRequestTests: XCTestCase {
  private func launch(seed: Data, key: SymmetricKey, file: String, bus: TestBus) throws
    -> SessionManager
  {
    let identity = try IdentityManager(store: InMemoryKeyStore(seed: seed))
    let transport = FakeTransport(identity: identity.publicKey.rawRepresentation, bus: bus)
    let manager = SessionManager(identity: identity, mesh: MeshService(transport: transport))
    try manager.attachStore(EncryptedStore(key: key, fileName: file))
    bus.connect(manager.myID, transport)
    return manager
  }

  private func seed() -> Data { Curve25519.Signing.PrivateKey().rawRepresentation }

  private func wipe(_ key: SymmetricKey, _ file: String) {
    let store = EncryptedStore(key: key, fileName: file)
    store.wipe()
    store.companion(suffix: ".crypto").wipe()
    store.companion(suffix: ".transaction").wipe()
  }

  private func addRemoteCard(of recipient: SessionManager, to sender: SessionManager) throws {
    let card = try XCTUnwrap(recipient.myCard)
    XCTAssertTrue(
      sender.addContact(
        card.bundle, name: card.name, relayURLs: card.relayURLs,
        prekeyBundle: card.prekeyBundle, admission: .outgoingRequest))
  }

  // swiftlint:disable:next function_body_length
  func testUnknownSenderCanDeliverExactlyOneIntroductionThenRecipientAccepts() throws {
    let bus = TestBus()
    let keyA = SymmetricKey(size: .bits256)
    let keyB = SymmetricKey(size: .bits256)
    wipe(keyA, "requests-a.store")
    wipe(keyB, "requests-b.store")
    let a = try launch(seed: seed(), key: keyA, file: "requests-a.store", bus: bus)
    let b = try launch(seed: seed(), key: keyB, file: "requests-b.store", bus: bus)
    a.setMyName("Alice")
    b.setMyName("Bob")

    try addRemoteCard(of: b, to: a)
    let bOnA = try XCTUnwrap(a.contacts.first { $0.id == b.myID })

    XCTAssertEqual(bOnA.requestState, .outgoing)
    XCTAssertTrue(a.canSendMessage(to: bOnA))
    a.activeChatID = b.myID
    a.reportScreenshotTaken()
    let stagedAOnB = try XCTUnwrap(b.contacts.first { $0.id == a.myID })
    XCTAssertFalse(
      b.messages(with: stagedAOnB).contains { $0.event == .screenshot },
      "system events cannot become an introduction")
    a.send("Hello from Alice", to: bOnA)

    let aOnB = try XCTUnwrap(b.contacts.first { $0.id == a.myID })
    XCTAssertEqual(aOnB.requestState, .incoming)
    XCTAssertEqual(b.incomingMessageRequests.map(\.id), [a.myID])
    XCTAssertEqual(b.messages(with: aOnB).filter { !$0.system }.map(\.text), ["Hello from Alice"])
    XCTAssertFalse(a.canSendMessage(to: bOnA))

    a.send("This must not be sent", to: bOnA)
    XCTAssertEqual(b.messages(with: aOnB).filter { !$0.system }.count, 1)
    a.reportScreenshotTaken()
    XCTAssertFalse(
      b.messages(with: aOnB).contains { $0.event == .screenshot },
      "requests cannot use system events to bypass the one-introduction limit")
    let sharedRelay = try XCTUnwrap(URL(string: "wss://shared.example/ws"))
    a.relayURLs = [sharedRelay]
    a.shareRelay(sharedRelay, with: bOnA)
    XCTAssertFalse(
      b.messages(with: aOnB).contains { $0.event == .relayRecommendation },
      "relay recommendations cannot be sent during a pending request")

    a.setEphemeral(true, for: bOnA)
    a.setChatUsesBluetooth(true, for: bOnA)
    XCTAssertFalse(a.isEphemeral(bOnA), "pending requests cannot change chat persistence")
    XCTAssertFalse(a.bluetoothChatIDs.contains(b.myID), "pending requests cannot change transport")

    b.acceptMessageRequest(from: aOnB)
    XCTAssertEqual(
      b.contacts.first { $0.id == a.myID }?.requestState, ContactRequestState.none)
    XCTAssertEqual(
      a.contacts.first { $0.id == b.myID }?.requestState, ContactRequestState.none)
    XCTAssertTrue(a.canSendMessage(to: bOnA))
    a.setEphemeral(true, for: bOnA)
    a.setChatUsesBluetooth(true, for: bOnA)
    XCTAssertTrue(a.isEphemeral(bOnA), "accepted chats can enable ephemeral mode")
    XCTAssertTrue(a.bluetoothChatIDs.contains(b.myID), "accepted chats can switch transport")
    a.shareRelay(sharedRelay, with: bOnA)
    XCTAssertEqual(
      b.messages(with: aOnB).last { $0.event == .relayRecommendation }?
        .relayRecommendationURLs,
      [sharedRelay.absoluteString])
  }

  func testRemoteRequestWorksWhenSenderIsNotLexicographicInitiator() throws {
    let bus = TestBus()
    let keyA = SymmetricKey(size: .bits256)
    let keyB = SymmetricKey(size: .bits256)
    wipe(keyA, "requests-order-a.store")
    wipe(keyB, "requests-order-b.store")
    var sender = try launch(seed: seed(), key: keyA, file: "requests-order-a.store", bus: bus)
    var recipient = try launch(seed: seed(), key: keyB, file: "requests-order-b.store", bus: bus)
    if sender.isInitiator(toward: recipient.myID) {
      swap(&sender, &recipient)
    }

    try addRemoteCard(of: recipient, to: sender)
    let contact = try XCTUnwrap(sender.contacts.first { $0.id == recipient.myID })
    sender.send("One-sided hello", to: contact)

    XCTAssertEqual(
      recipient.contacts.first { $0.id == sender.myID }?.requestState, .incoming)
    let receivedContact = try XCTUnwrap(recipient.contacts.first { $0.id == sender.myID })
    XCTAssertEqual(recipient.messages(with: receivedContact).last?.text, "One-sided hello")
  }

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
    a.resetSession(for: b.myID)
    a.establishViaPrekey(try XCTUnwrap(a.contacts.first { $0.id == b.myID }))
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

  func testIncomingRequestRejectsControlsAndRemembersEphemeralIntroduction() throws {
    let bus = TestBus()
    let keyA = SymmetricKey(size: .bits256)
    let keyB = SymmetricKey(size: .bits256)
    let fileA = "requests-incoming-admission-a.store"
    let fileB = "requests-incoming-admission-b.store"
    wipe(keyA, fileA)
    wipe(keyB, fileB)
    let seedB = seed()
    let a = try launch(seed: seed(), key: keyA, file: fileA, bus: bus)
    let b = try launch(seed: seedB, key: keyB, file: fileB, bus: bus)

    try addRemoteCard(of: b, to: a)
    let bOnA = try XCTUnwrap(a.contacts.first { $0.id == b.myID })
    a.establishIfNeeded(contactID: b.myID)
    a.applyEphemeral(true, for: b.myID, announce: false)
    a.sendEphemeralState(to: bOnA)
    let aOnB = try XCTUnwrap(b.contacts.first { $0.id == a.myID })
    XCTAssertFalse(b.isEphemeral(aOnB), "request-stage controls must not mutate chat state")

    b.applyEphemeral(true, for: a.myID, announce: false)
    a.send("first introduction", to: bOnA)
    XCTAssertEqual(b.messages(with: aOnB).filter { !$0.system }.count, 1)

    bus.disconnect(b.myID)
    let relaunched = try launch(seed: seedB, key: keyB, file: fileB, bus: bus)
    let restored = try XCTUnwrap(relaunched.contacts.first { $0.id == a.myID })
    XCTAssertTrue(relaunched.messages(with: restored).isEmpty)

    let forgedExtra = ChatMessage(mine: true, text: "second introduction", pending: true)
    a.transmit(forgedExtra, to: bOnA)
    XCTAssertTrue(relaunched.messages(with: restored).isEmpty)
  }

  func testOutgoingAcceptanceMutationWaitsForEnclosingMessageTransaction() throws {
    let bus = TestBus()
    let keyA = SymmetricKey(size: .bits256)
    let keyB = SymmetricKey(size: .bits256)
    let fileA = "requests-accept-transaction-a.store"
    let fileB = "requests-accept-transaction-b.store"
    wipe(keyA, fileA)
    wipe(keyB, fileB)
    let seedA = seed()
    let a = try launch(seed: seedA, key: keyA, file: fileA, bus: bus)
    let b = try launch(seed: seed(), key: keyB, file: fileB, bus: bus)

    try addRemoteCard(of: b, to: a)
    a.acceptOutgoingRequest(from: b.myID)
    XCTAssertEqual(
      a.contacts.first { $0.id == b.myID }?.requestState, ContactRequestState.none)

    bus.disconnect(a.myID)
    let relaunched = try launch(seed: seedA, key: keyA, file: fileA, bus: bus)
    XCTAssertEqual(relaunched.contacts.first { $0.id == b.myID }?.requestState, .outgoing)
  }

  func testIncomingRequestQuarantineIsBoundedAndExpiredEntriesArePurged() throws {
    let bus = TestBus()
    let key = SymmetricKey(size: .bits256)
    let file = "requests-quarantine.store"
    wipe(key, file)
    let localSeed = seed()
    let local = try launch(seed: localSeed, key: key, file: file, bus: bus)
    let remote = try launch(
      seed: seed(), key: SymmetricKey(size: .bits256),
      file: "requests-quarantine-remote.store", bus: bus)
    let card = try XCTUnwrap(remote.myCard)
    let expired = Contact(
      bundle: card.bundle, displayName: "Expired", relayURLs: card.relayURLs,
      prekeyBundle: card.prekeyBundle, verifiedInPerson: false, requestState: .incoming,
      requestCreatedAt: Date().addingTimeInterval(-SessionManager.incomingRequestLifetime - 1))
    local.contacts.append(expired)
    XCTAssertTrue(local.persist())

    bus.disconnect(local.myID)
    let relaunched = try launch(seed: localSeed, key: key, file: file, bus: bus)
    XCTAssertFalse(relaunched.contacts.contains { $0.id == remote.myID })

    let dates = Array(
      repeating: Date(), count: SessionManager.maximumIncomingRequests)
    XCTAssertFalse(SessionManager.canAdmitIncomingRequest(existingDates: dates, now: Date()))
  }

  func testIncomingRequestRelaysRemainInactiveUntilAcceptance() throws {
    let bus = TestBus()
    let local = try launch(
      seed: seed(), key: SymmetricKey(size: .bits256),
      file: "requests-relay-policy-local.store", bus: bus)
    let remote = try launch(
      seed: seed(), key: SymmetricKey(size: .bits256),
      file: "requests-relay-policy-remote.store", bus: bus)
    let card = try XCTUnwrap(remote.myCard)
    local.contacts.append(
      Contact(
        bundle: card.bundle, displayName: "Requester",
        relayURLs: [try XCTUnwrap(URL(string: "wss://relay.example"))],
        prekeyBundle: card.prekeyBundle, verifiedInPerson: false,
        requestState: .incoming, requestCreatedAt: Date()))

    XCTAssertTrue(local.relayEligibleContactIDs.isEmpty)
    local.contacts[0].requestState = .none
    XCTAssertEqual(local.relayEligibleContactIDs, [remote.myID])
  }

  func testPreIntroductionStageIsShortLivedAndUserClearable() throws {
    let bus = TestBus()
    let local = try launch(
      seed: seed(), key: SymmetricKey(size: .bits256),
      file: "requests-short-stage-local.store", bus: bus)
    let remote = try launch(
      seed: seed(), key: SymmetricKey(size: .bits256),
      file: "requests-short-stage-remote.store", bus: bus)
    let card = try XCTUnwrap(remote.myCard)
    local.contacts.append(
      Contact(
        bundle: card.bundle, displayName: "Pending", prekeyBundle: card.prekeyBundle,
        verifiedInPerson: false, requestState: .incoming,
        requestCreatedAt: Date().addingTimeInterval(
          -SessionManager.preIntroductionLifetime - 1)))

    XCTAssertTrue(local.purgeExpiredIncomingRequests(now: Date()))
    XCTAssertTrue(local.contacts.isEmpty)

    local.contacts.append(
      Contact(
        bundle: card.bundle, displayName: "Pending", prekeyBundle: card.prekeyBundle,
        verifiedInPerson: false, requestState: .incoming, requestCreatedAt: Date()))
    XCTAssertEqual(local.stagedIncomingRequestCount, 1)
    local.clearStagedIncomingRequests()
    XCTAssertTrue(local.contacts.isEmpty)
  }

  func testPendingRequestIgnoresUnauthenticatedRehandshake() throws {
    let bus = TestBus()
    var sender = try launch(
      seed: seed(), key: SymmetricKey(size: .bits256),
      file: "requests-rehandshake-sender.store", bus: bus)
    var recipient = try launch(
      seed: seed(), key: SymmetricKey(size: .bits256),
      file: "requests-rehandshake-recipient.store", bus: bus)
    if !recipient.isInitiator(toward: sender.myID) {
      swap(&sender, &recipient)
    }
    try addRemoteCard(of: recipient, to: sender)
    let recipientOnSender = try XCTUnwrap(sender.contacts.first { $0.id == recipient.myID })
    sender.establishIfNeeded(contactID: recipient.myID)
    let senderOnRecipient = try XCTUnwrap(
      recipient.contacts.first { $0.id == sender.myID })
    let establishedSession = try XCTUnwrap(recipient.sessions[sender.myID])

    recipient.handleRehandshakeRequest(from: senderOnRecipient)

    XCTAssertTrue(recipient.sessions[sender.myID] === establishedSession)
    XCTAssertEqual(sender.contacts.first { $0.id == recipient.myID }?.requestState, .outgoing)
    XCTAssertEqual(recipientOnSender.requestState, .outgoing)
  }
}
// swiftlint:enable type_body_length identifier_name
