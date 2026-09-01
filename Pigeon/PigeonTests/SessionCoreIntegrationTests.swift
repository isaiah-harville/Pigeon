import CryptoKit
import Foundation
import PigeonFFI
import XCTest

@testable import Pigeon

@MainActor
final class SessionCoreIntegrationTests: XCTestCase {
  private enum InjectedFailure: Error {
    case write
  }

  func testAttachStoreBuildsTransactionalCoreBeforeUnlockCompletes() throws {
    let fixture = try makeFixture()
    defer { wipe(fixture.store) }

    try fixture.manager.attachStore(fixture.store)

    XCTAssertTrue(fixture.manager.isUnlocked)
    XCTAssertEqual(try fixture.manager.coreClient?.checkpointGeneration(), 0)
    XCTAssertEqual(fixture.manager.coreSnapshotGeneration, 0)
    XCTAssertEqual(fixture.manager.groups, [])
  }

  func testCoreSnapshotAtomicallyReplacesGroupProjectionAndRejectsRollback() throws {
    let fixture = try makeFixture()
    defer { wipe(fixture.store) }
    let current = groupState(name: "Birds", revision: 2)

    fixture.manager.applyCoreSnapshot(
      PigeonCoreSnapshot(
        checkpointGeneration: 5, groups: [current]))
    fixture.manager.applyCoreSnapshot(
      PigeonCoreSnapshot(
        checkpointGeneration: 4, groups: [groupState(name: "Stale", revision: 1)]))

    XCTAssertEqual(fixture.manager.coreSnapshotGeneration, 5)
    XCTAssertEqual(fixture.manager.groups, [current])
  }

  func testExecutingCoreCommandRefreshesDurableSnapshot() throws {
    let fixture = try makeFixture()
    defer { wipe(fixture.store) }
    try fixture.manager.attachStore(fixture.store)

    let output = try fixture.manager.executeCore(
      PigeonCoreCommand(
        id: "ack-empty-effects",
        body: .acknowledgeEffects(PigeonAcknowledgeEffects())))

    XCTAssertEqual(output.checkpointGeneration, 1)
    XCTAssertEqual(fixture.manager.coreSnapshotGeneration, 1)
  }

  func testInvalidGroupRelayMessageDoesNotAdvanceCoreState() throws {
    let fixture = try makeFixture()
    defer { wipe(fixture.store) }
    try fixture.manager.attachStore(fixture.store)

    XCTAssertFalse(
      fixture.manager.consumeGroupRelayMessage(
        Data("not an MLS message".utf8), requestID: "relay-entry-1"))
    XCTAssertEqual(fixture.manager.coreSnapshotGeneration, 0)
  }

  func testCoreEventIsAcknowledgedOnlyAfterGroupHistoryPersists() throws {
    let fixture = try makeFixture()
    defer { wipe(fixture.store) }
    try fixture.manager.attachStore(fixture.store)
    let groupID = Data(repeating: 41, count: 32)
    let event = PigeonCoreEvent(
      id: "created-event",
      body: .groupCreated(
        PigeonGroupCreatedEvent(
          groupID: groupID,
          ownerIdentity: fixture.manager.myID,
          name: "Birds",
          relayURL: "https://relay.example",
          meshEnabled: false,
          epoch: 1,
          policyRevision: 1)))

    try fixture.manager.absorbCoreEvents([event])

    XCTAssertEqual(fixture.manager.groupConversations[groupID]?.messages.count, 1)
    XCTAssertEqual(fixture.manager.coreSnapshotGeneration, 1)

    let restored = SessionManager(
      identity: fixture.manager.identity,
      mesh: MeshService(transport: SessionCoreNoopTransport()))
    try restored.attachStore(fixture.store)
    XCTAssertEqual(restored.groupConversations[groupID]?.messages.count, 1)
  }

  func testCoreEventRemainsUnacknowledgedWhenGroupHistorySaveFails() throws {
    let url = FileManager.default.temporaryDirectory
      .appendingPathComponent("pigeon-core-event-failure-\(UUID().uuidString).store")
    let key = SymmetricKey(size: .bits256)
    var failWrites = false
    let store = EncryptedStore(
      key: key,
      url: url,
      io: EncryptedStoreIO(
        write: { data, destination, options in
          if failWrites { throw InjectedFailure.write }
          try data.write(to: destination, options: options)
        },
        remove: { try FileManager.default.removeItem(at: $0) }))
    let identity = try IdentityManager(
      store: InMemoryKeyStore(seed: Data(repeating: 29, count: 32)))
    let manager = SessionManager(
      identity: identity,
      mesh: MeshService(transport: SessionCoreNoopTransport()))
    defer { wipe(store) }
    try manager.attachStore(store)
    let event = PigeonCoreEvent(
      id: "must-remain-pending",
      body: .groupCreated(
        PigeonGroupCreatedEvent(
          groupID: Data(repeating: 42, count: 32),
          ownerIdentity: manager.myID,
          name: "Birds",
          relayURL: "https://relay.example",
          meshEnabled: false,
          epoch: 1,
          policyRevision: 1)))

    failWrites = true
    XCTAssertThrowsError(try manager.absorbCoreEvents([event]))
    XCTAssertEqual(try manager.coreClient?.checkpointGeneration(), 0)
  }

  func testCorruptCoreCheckpointKeepsSessionLocked() throws {
    let fixture = try makeFixture()
    defer { wipe(fixture.store) }
    let coreStore = fixture.store.companion(suffix: CoreCheckpointStore.companionSuffix)
    XCTAssertTrue(
      coreStore.save(
        PersistedCoreCheckpoint(
          generation: 1,
          bytes: Data("corrupt core".utf8),
          sha256: Data(repeating: 0, count: 32))))

    XCTAssertThrowsError(try fixture.manager.attachStore(fixture.store))
    XCTAssertFalse(fixture.manager.isUnlocked)
    XCTAssertNil(fixture.manager.account)
    XCTAssertNil(fixture.manager.coreClient)
  }

  private func makeFixture() throws -> (manager: SessionManager, store: EncryptedStore) {
    let identity = try IdentityManager(
      store: InMemoryKeyStore(seed: Data(repeating: 23, count: 32)))
    let manager = SessionManager(
      identity: identity,
      mesh: MeshService(transport: SessionCoreNoopTransport()))
    let url = FileManager.default.temporaryDirectory
      .appendingPathComponent("pigeon-session-core-\(UUID().uuidString).store")
    return (manager, EncryptedStore(key: SymmetricKey(size: .bits256), url: url))
  }

  private func groupState(name: String, revision: UInt64) -> PigeonGroupState {
    PigeonGroupState(
      groupID: Data(repeating: 1, count: 32),
      ownerIdentity: Data(repeating: 2, count: 32),
      adminIdentities: [Data(repeating: 2, count: 32)],
      memberIdentities: [
        Data(repeating: 2, count: 32), Data(repeating: 3, count: 32),
        Data(repeating: 4, count: 32),
      ],
      name: name, relayURL: "https://relay.example",
      coordinationID: Data(repeating: 5, count: 32), meshEnabled: false,
      epoch: 3, policyRevision: revision, dissolved: false,
      capabilityPublicKey: Data(repeating: 6, count: 32),
      coordinatorPublicKey: Data(repeating: 7, count: 32))
  }

  private func wipe(_ store: EncryptedStore) {
    store.wipe()
    store.companion(suffix: ".crypto").wipe()
    store.companion(suffix: ".transaction").wipe()
    store.companion(suffix: CoreCheckpointStore.companionSuffix).wipe()
  }
}

@MainActor
private final class SessionCoreNoopTransport: Transport {
  let kind: TransportKind? = .relay
  var status: TransportStatus = .idle
  var connectedPeerCount = 0
  var log: [String] = []
  var onMessage: ((Data, String) -> TransportMessageDisposition)?
  var onConnectivity: (() -> Void)?

  func broadcast(_: Data, to _: Data?) {}
}
