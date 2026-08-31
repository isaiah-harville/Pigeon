import CryptoKit
import Foundation
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
