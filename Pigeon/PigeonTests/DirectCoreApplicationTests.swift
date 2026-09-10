import Foundation
import PigeonFFI
import XCTest

@testable import Pigeon

extension SessionCoreIntegrationTests {
  func testPersistedDirectSystemEventStagesEndToEndAcknowledgement() throws {
    let fixture = try makeFixture()
    defer { wipe(fixture.store) }
    try fixture.manager.attachStore(fixture.store)
    let peer = try PigeonAccount.fromIdentitySeed(seed: Data(repeating: 62, count: 32))
    let peerBundle = try PigeonIdentityBundle(decoding: peer.identityBundle())
    let peerPrekey = try PigeonPrekeyBundle(decoding: peer.signedPrekeyBundle())
    let relay = try XCTUnwrap(URL(string: "wss://relay.example/ws"))
    XCTAssertTrue(
      fixture.manager.addContact(
        peerBundle, name: "Peer", relayURLs: [relay],
        prekeys: ContactPrekeyBundles(chat: nil, control: peerPrekey),
        admission: .verifiedInPerson))
    let contact = try XCTUnwrap(fixture.manager.contacts.first)
    let applicationID = "22222222-2222-2222-2222-222222222223"
    let event = PigeonCoreEvent(
      id: "direct-system-event",
      body: .directApplicationReceived(
        PigeonDirectApplicationReceivedEvent(
          senderIdentity: contact.id,
          application: PigeonDirectApplication(
            id: applicationID,
            body: .screenshotNotice))))

    try fixture.manager.absorbCoreEvents([event])

    XCTAssertEqual(fixture.manager.conversationStore.messages(for: contact.id).count, 1)
    let snapshot = try XCTUnwrap(fixture.manager.coreClient?.stateSnapshot())
    XCTAssertTrue(snapshot.pendingEvents.isEmpty)
    XCTAssertEqual(snapshot.pendingOutbound.count, 1)
    XCTAssertEqual(snapshot.pendingOutbound.first?.kind, .pairwise)
  }
}
