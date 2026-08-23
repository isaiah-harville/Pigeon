//
//  StartupPolicyTests.swift
//  PigeonTests
//

import CryptoKit
import PigeonFFI
import XCTest

@testable import Pigeon

@MainActor
final class StartupPolicyTests: XCTestCase {

  func testUnlockedStartupLoadsFullServices() {
    XCTAssertEqual(
      StartupPolicy.identityCreationPolicy(protectedDataAvailable: true),
      .allowCreation)
    XCTAssertTrue(
      StartupPolicy.shouldAttemptIdentityLoad(
        protectedDataAvailable: true, backgroundDeliveryEnabled: false))
    XCTAssertEqual(
      StartupPolicy.mode(
        protectedDataAvailable: true, backgroundDeliveryEnabled: false,
        identityReadable: true),
      .unlocked)
  }

  func testLockedAfterFirstUnlockStartsTransportOnlyWhenOptedIn() {
    XCTAssertTrue(
      StartupPolicy.shouldAttemptIdentityLoad(
        protectedDataAvailable: false, backgroundDeliveryEnabled: true))
    XCTAssertEqual(
      StartupPolicy.mode(
        protectedDataAvailable: false, backgroundDeliveryEnabled: true,
        identityReadable: true),
      .lockedTransportOnly)
  }

  func testLockedBeforeFirstUnlockWaitsWhenIdentityIsUnreadable() {
    XCTAssertEqual(
      StartupPolicy.identityCreationPolicy(protectedDataAvailable: false),
      .existingOnly)
    XCTAssertEqual(
      StartupPolicy.mode(
        protectedDataAvailable: false, backgroundDeliveryEnabled: true,
        identityReadable: false),
      .waitForUnlock)
  }

  func testLockedOptOutDoesNotAttemptIdentityLoad() {
    XCTAssertFalse(
      StartupPolicy.shouldAttemptIdentityLoad(
        protectedDataAvailable: false, backgroundDeliveryEnabled: false))
    XCTAssertEqual(
      StartupPolicy.mode(
        protectedDataAvailable: false, backgroundDeliveryEnabled: false,
        identityReadable: true),
      .waitForUnlock)
  }

  func testLockedEnvelopeIsUnacknowledgedAndDrainedAfterVaultUnlock() throws {
    let identity = try IdentityManager(
      store: InMemoryKeyStore(seed: Curve25519.Signing.PrivateKey().rawRepresentation))
    let manager = SessionManager(identity: identity, mesh: MeshService(transport: NoopTransport()))
    var notificationCount = 0
    manager.onIncomingNotification = { notificationCount += 1 }
    let envelope = SessionEnvelope(
      type: .message, sender: Data(repeating: 7, count: 32), recipient: manager.myID,
      payload: Data([1, 2, 3]))

    XCTAssertEqual(
      manager.handleInbound(envelope.encoded(), channel: .relay(host: "relay.example")),
      .retryAfterRestart)
    XCTAssertFalse(manager.lockedInbox.isEmpty)
    XCTAssertEqual(notificationCount, 1)

    let key = SymmetricKey(size: .bits256)
    let store = EncryptedStore(key: key, fileName: "startup-locked-inbox.store")
    store.wipe()
    store.companion(suffix: ".crypto").wipe()
    store.companion(suffix: ".transaction").wipe()
    try manager.attachStore(store)

    XCTAssertTrue(manager.lockedInbox.isEmpty)
  }
}

@MainActor
private final class NoopTransport: Transport {
  let kind: TransportKind? = .relay
  var status: TransportStatus = .idle
  var connectedPeerCount = 0
  var log: [String] = []
  var onMessage: ((Data, String) -> TransportMessageDisposition)?
  var onConnectivity: (() -> Void)?

  func broadcast(_: Data, to _: Data?) {}
}
