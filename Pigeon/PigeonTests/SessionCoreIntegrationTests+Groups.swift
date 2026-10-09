import CryptoKit
import Foundation
import PigeonFFI
import XCTest

@testable import Pigeon

extension SessionCoreIntegrationTests {
  func testCreateGroupResolvesCoordinatorKeyAndStagesPairwiseInvitations() async throws {
    let fixture = try makeFixture()
    defer { wipe(fixture.store) }
    try fixture.manager.attachStore(fixture.store)
    let relay = try XCTUnwrap(URL(string: "wss://relay.example/ws"))
    let peers = try [33, 34].map { seed -> Contact in
      let peer = try makeCorePeer(seedByte: UInt8(seed))
      XCTAssertTrue(
        fixture.manager.addContact(
          peer.bundle, name: "Peer \(seed)", relayURLs: [relay],
          prekeys: ContactPrekeyBundles(chat: nil, control: peer.prekey),
          admission: .verifiedInPerson))
      return try XCTUnwrap(fixture.manager.contacts.first { $0.id == peer.bundle.identityKey })
    }
    let coordinatorKey = fixture.manager.myID
    fixture.manager.resolveGroupCoordinatorKey = { requestedRelay in
      XCTAssertEqual(requestedRelay, relay)
      return coordinatorKey
    }

    let output = try await fixture.manager.createGroup(
      name: "Bird Friends", memberIDs: Set(peers.map(\.id)), relayURL: relay)

    XCTAssertEqual(output.outbound.count, 2)
    XCTAssertTrue(output.outbound.allSatisfy { $0.kind == .pairwise })
    XCTAssertEqual(Set(output.outbound.map(\.relayURL)), [relay.absoluteString])
  }

  func testCreateGroupRejectsContactsWithoutCoreControlPrekeys() async throws {
    let fixture = try makeFixture()
    defer { wipe(fixture.store) }
    try fixture.manager.attachStore(fixture.store)
    let relay = try XCTUnwrap(URL(string: "wss://relay.example/ws"))
    let peers = try [35, 36].map { seed -> Contact in
      let peer = try makeCorePeer(seedByte: UInt8(seed))
      return Contact(bundle: peer.bundle, displayName: "Peer \(seed)", relayURLs: [relay])
    }
    fixture.manager.contacts = peers
    fixture.manager.resolveGroupCoordinatorKey = { _ in
      XCTFail("invalid draft must not contact the relay")
      return Data()
    }

    do {
      _ = try await fixture.manager.createGroup(
        name: "Bird Friends", memberIDs: Set(peers.map(\.id)), relayURL: relay)
      XCTFail("Expected unreachable member error")
    } catch {
      XCTAssertEqual(error as? SessionManager.GroupCreationError, .unreachableMember)
    }
  }

  func testRecoverGroupRejectsNonAdminBeforeResolvingReplacementRelay() async throws {
    let fixture = try makeFixture()
    defer { wipe(fixture.store) }
    let relay = try XCTUnwrap(URL(string: "wss://replacement.example/group/ws"))
    let group = PigeonGroupState(
      groupID: Data(repeating: 1, count: 32),
      ownerIdentity: Data(repeating: 2, count: 32),
      adminIdentities: [Data(repeating: 2, count: 32)],
      memberIdentities: [
        Data(repeating: 2, count: 32), fixture.manager.myID, Data(repeating: 4, count: 32),
      ],
      name: "Birds", relayURL: "https://relay.example",
      coordinationID: Data(repeating: 5, count: 32), meshEnabled: false,
      epoch: 3, policyRevision: 1, dissolved: false,
      capabilityPublicKey: Data(repeating: 6, count: 32),
      capabilityID: Data(repeating: 8, count: 32),
      coordinatorPublicKey: Data(repeating: 7, count: 32))
    fixture.manager.resolveGroupCoordinatorKey = { _ in
      XCTFail("unauthorized recovery must not contact the replacement relay")
      return Data()
    }

    do {
      _ = try await fixture.manager.recoverGroup(
        group, using: relay)
      XCTFail("Expected unauthorized recovery error")
    } catch {
      XCTAssertEqual(error as? SessionManager.GroupRecoveryError, .unauthorized)
    }
  }

  func testOwnerRelayChangeRejectsDifferentCoordinatorBeforeCallingCore() async throws {
    let fixture = try makeFixture()
    defer { wipe(fixture.store) }
    let relay = try XCTUnwrap(URL(string: "wss://replacement.example/group/ws"))
    let group = PigeonGroupState(
      groupID: Data(repeating: 1, count: 32),
      ownerIdentity: fixture.manager.myID,
      adminIdentities: [fixture.manager.myID],
      memberIdentities: [
        fixture.manager.myID, Data(repeating: 3, count: 32), Data(repeating: 4, count: 32),
      ],
      name: "Birds", relayURL: "https://relay.example",
      coordinationID: Data(repeating: 5, count: 32), meshEnabled: false,
      epoch: 3, policyRevision: 1, dissolved: false,
      capabilityPublicKey: Data(repeating: 6, count: 32),
      capabilityID: Data(repeating: 8, count: 32),
      coordinatorPublicKey: Data(repeating: 7, count: 32))
    fixture.manager.resolveGroupCoordinatorKey = { _ in Data(repeating: 9, count: 32) }

    do {
      _ = try await fixture.manager.changeGroupRelay(group, to: relay)
      XCTFail("Expected coordinator mismatch")
    } catch {
      XCTAssertEqual(error as? SessionManager.GroupRecoveryError, .coordinatorMismatch)
    }
  }

  func testGroupSendRejectsWhitespaceBeforeCallingCore() throws {
    let fixture = try makeFixture()
    defer { wipe(fixture.store) }

    XCTAssertThrowsError(
      try fixture.manager.sendGroupMessage(
        "   \n", in: groupState(name: "Birds", revision: 1), replyToMessageID: nil)
    ) { error in
      XCTAssertEqual(error as? SessionManager.GroupMessagingError, .invalidMessage)
    }
  }

  func testGroupSendRejectsInactiveMembershipBeforeCallingCore() throws {
    let fixture = try makeFixture()
    defer { wipe(fixture.store) }

    XCTAssertThrowsError(
      try fixture.manager.sendGroupMessage(
        "hello", in: groupState(name: "Birds", revision: 1), replyToMessageID: nil)
    ) { error in
      XCTAssertEqual(error as? SessionManager.GroupMessagingError, .inactiveGroup)
    }
  }

  func testAddingContactRegistersCorePairwiseControlPrekey() throws {
    let fixture = try makeFixture()
    defer { wipe(fixture.store) }
    try fixture.manager.attachStore(fixture.store)
    let peer = try makeCorePeer(seedByte: 32)
    let relay = try XCTUnwrap(URL(string: "wss://relay.example/ws"))

    XCTAssertTrue(
      fixture.manager.addContact(
        peer.bundle, name: "Peer", relayURLs: [relay],
        prekeys: ContactPrekeyBundles(chat: nil, control: peer.prekey),
        admission: .outgoingRequest))
    let output = try fixture.manager.executeCore(
      PigeonCoreCommand(
        id: "send-registered-control",
        body: .sendPairwiseControl(
          PigeonSendPairwiseControl(
            recipientIdentity: peer.bundle.identityKey,
            contentKind: .groupWelcome,
            payload: Data("opaque welcome".utf8)))))

    XCTAssertEqual(output.outbound.map(\.kind), [.pairwise])
    XCTAssertEqual(output.outbound.first?.relayURL, relay.absoluteString)
  }
}
