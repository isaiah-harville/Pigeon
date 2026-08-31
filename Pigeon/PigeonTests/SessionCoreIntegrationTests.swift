import CryptoKit
import Foundation
import PigeonFFI
import XCTest

@testable import Pigeon

@MainActor
final class SessionCoreIntegrationTests: XCTestCase {
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
