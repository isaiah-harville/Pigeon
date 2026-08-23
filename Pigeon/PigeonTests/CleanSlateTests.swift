//
//  CleanSlateTests.swift
//  PigeonTests
//

import CryptoKit
import XCTest

@testable import Pigeon

@MainActor
final class CleanSlateTests: XCTestCase {

  func testWipeAndTrustRootsRotateInOrder() throws {
    var events: [String] = []

    try CleanSlateExecutor.run(
      wipe: {
        events.append("wipe")
        return true
      },
      rotateIdentity: { events.append("identity") },
      rotateVault: { events.append("vault") })

    XCTAssertEqual(events, ["wipe", "identity", "vault"])
  }

  func testFailedWipePreventsIdentityRotation() {
    var rotated = false

    XCTAssertThrowsError(
      try CleanSlateExecutor.run(
        wipe: { false },
        rotateIdentity: { rotated = true },
        rotateVault: {}))

    XCTAssertFalse(rotated)
  }

  func testFailedIdentityRotationPreventsVaultRotation() {
    var vaultRotated = false

    XCTAssertThrowsError(
      try CleanSlateExecutor.run(
        wipe: { true },
        rotateIdentity: { throw CleanSlateTestError.injected },
        rotateVault: { vaultRotated = true })
    ) { error in
      XCTAssertEqual(error as? CleanSlateError, .identityRotationFailed)
    }

    XCTAssertFalse(vaultRotated)
  }

  func testVaultRotationFailureIsExplicit() {
    XCTAssertThrowsError(
      try CleanSlateExecutor.run(
        wipe: { true },
        rotateIdentity: {},
        rotateVault: { throw CleanSlateTestError.injected })
    ) { error in
      XCTAssertEqual(error as? CleanSlateError, .vaultRotationFailed)
    }
  }

  func testPersistenceWipeRemovesEntireStoreFamily() throws {
    let url = FileManager.default.temporaryDirectory
      .appendingPathComponent("pigeon-clean-slate-\(UUID().uuidString).store")
    let key = SymmetricKey(size: .bits256)
    let store = EncryptedStore(key: key, url: url)
    let crypto = store.companion(suffix: ".crypto")
    let transaction = store.companion(suffix: ".transaction")
    defer {
      store.wipe()
      crypto.wipe()
      transaction.wipe()
    }
    let persistence = SessionPersistence()
    _ = try persistence.attach(store, identitySeed: Data(repeating: 4, count: 32))
    XCTAssertTrue(store.save(PersistedState(myName: "Before")))
    XCTAssertTrue(crypto.save(PersistedCrypto()))
    XCTAssertTrue(
      transaction.save(
        PersistedStateTransaction(bulk: PersistedState(), crypto: PersistedCrypto())))

    XCTAssertTrue(persistence.wipeAll())

    XCTAssertNil(try store.load(PersistedState.self))
    XCTAssertNil(try crypto.load(PersistedCrypto.self))
    XCTAssertNil(try transaction.load(PersistedStateTransaction.self))
  }

  func testPartialStoreFamilyWipeCanBeRetried() throws {
    let url = FileManager.default.temporaryDirectory
      .appendingPathComponent("pigeon-clean-slate-retry-\(UUID().uuidString).store")
    var failedOnce = false
    let io = EncryptedStoreIO(
      write: { try $0.write(to: $1, options: $2) },
      remove: { target in
        if target.lastPathComponent.hasSuffix(".crypto"), !failedOnce {
          failedOnce = true
          throw CocoaError(.fileWriteNoPermission)
        }
        try FileManager.default.removeItem(at: target)
      })
    let store = EncryptedStore(key: SymmetricKey(size: .bits256), url: url, io: io)
    let persistence = SessionPersistence()
    _ = try persistence.attach(store, identitySeed: Data(repeating: 5, count: 32))
    XCTAssertTrue(store.save(PersistedState(myName: "Before")))
    XCTAssertTrue(store.companion(suffix: ".crypto").save(PersistedCrypto()))

    XCTAssertFalse(persistence.wipeAll())
    XCTAssertTrue(persistence.wipeAll())

    XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
    XCTAssertFalse(FileManager.default.fileExists(atPath: url.path + ".crypto"))
  }

  func testSessionCleanSlateStopsTransportWipesStateAndRotatesIdentity() async throws {
    let keyStore = CleanSlateKeyStore(seed: Data(repeating: 7, count: 32))
    let identity = try IdentityManager(store: keyStore)
    let transport = CleanSlateTransport()
    let manager = SessionManager(identity: identity, mesh: MeshService(transport: transport))
    let oldIdentity = manager.myID
    let url = FileManager.default.temporaryDirectory
      .appendingPathComponent("pigeon-clean-slate-manager-\(UUID().uuidString).store")
    let key = SymmetricKey(size: .bits256)
    let store = EncryptedStore(key: key, url: url)
    defer {
      store.wipe()
      store.companion(suffix: ".crypto").wipe()
      store.companion(suffix: ".transaction").wipe()
    }
    try manager.attachStore(store)
    manager.setMyName("Before")

    try await manager.prepareCleanSlate(
      identitySeed: Data(repeating: 8, count: 32), replaceVault: {})

    XCTAssertEqual(transport.enabledValues, [false])
    XCTAssertNotEqual(manager.myID, oldIdentity)
    XCTAssertNil(try store.load(PersistedState.self))
    XCTAssertNil(try store.companion(suffix: ".crypto").load(PersistedCrypto.self))
  }

  func testFailedSessionWipeLeavesTransportDisabledAndIdentityUnchanged() async throws {
    let keyStore = CleanSlateKeyStore(seed: Data(repeating: 9, count: 32))
    let identity = try IdentityManager(store: keyStore)
    let transport = CleanSlateTransport()
    let manager = SessionManager(identity: identity, mesh: MeshService(transport: transport))
    let oldIdentity = manager.myID
    let url = FileManager.default.temporaryDirectory
      .appendingPathComponent("pigeon-clean-slate-failure-\(UUID().uuidString).store")
    let io = EncryptedStoreIO(
      write: { try $0.write(to: $1, options: $2) },
      remove: { _ in throw CocoaError(.fileWriteNoPermission) })
    let store = EncryptedStore(key: SymmetricKey(size: .bits256), url: url, io: io)
    try manager.attachStore(store)
    manager.setMyName("Must trigger deletion")

    do {
      try await manager.prepareCleanSlate(
        identitySeed: Data(repeating: 8, count: 32), replaceVault: {})
      XCTFail("Expected wipe failure")
    } catch {
      XCTAssertEqual(error as? CleanSlateError, .wipeFailed)
    }

    XCTAssertEqual(transport.enabledValues, [false])
    XCTAssertEqual(manager.myID, oldIdentity)
  }

  func testRecoveryIntentPersistsUntilFinished() throws {
    let url = FileManager.default.temporaryDirectory
      .appendingPathComponent("pigeon-clean-slate-marker-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: url) }
    let identityStage = CleanSlateStageStore()
    let vaultStage = CleanSlateStageStore()
    let recovery = CleanSlateRecovery(
      url: url, identityStage: identityStage, vaultStage: vaultStage)

    try recovery.begin()
    let targets = try recovery.targets()
    try recovery.begin()
    let resumedTargets = try recovery.targets()
    XCTAssertTrue(
      CleanSlateRecovery(
        url: url, identityStage: identityStage, vaultStage: vaultStage
      ).isPending)
    XCTAssertEqual(targets.identitySeed.count, 32)
    XCTAssertEqual(targets.vaultKey.count, 32)
    XCTAssertEqual(resumedTargets.identitySeed, targets.identitySeed)
    XCTAssertEqual(resumedTargets.vaultKey, targets.vaultKey)

    try recovery.finish()
    XCTAssertFalse(recovery.isPending)
    XCTAssertNil(try identityStage.get())
    XCTAssertNil(try vaultStage.get())
  }

  func testFailedStagingCleanupKeepsDurableRecoveryMarker() throws {
    let url = FileManager.default.temporaryDirectory
      .appendingPathComponent("pigeon-clean-slate-cleanup-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: url) }
    let identityStage = CleanSlateStageStore()
    let vaultStage = CleanSlateStageStore()
    vaultStage.failDeleteOnCall = 2
    let recovery = CleanSlateRecovery(
      url: url, identityStage: identityStage, vaultStage: vaultStage)
    try recovery.begin()

    XCTAssertThrowsError(try recovery.finish())
    XCTAssertTrue(recovery.isPending)
    XCTAssertNotNil(try vaultStage.get())

    vaultStage.failDeleteOnCall = nil
    XCTAssertTrue(try recovery.finishCleanupIfNeeded())
    XCTAssertFalse(recovery.isPending)
    XCTAssertNil(try vaultStage.get())
  }
}

private enum CleanSlateTestError: Error {
  case injected
}

private final class CleanSlateStageStore: KeyStore {
  var data: Data?
  var failDeleteOnCall: Int?
  private var deleteCalls = 0

  func get() throws -> Data? { data }
  func set(_ data: Data, accessibility _: KeychainAccessibility) throws { self.data = data }
  func setAccessibility(_: KeychainAccessibility) throws {}
  func delete() throws {
    deleteCalls += 1
    if deleteCalls == failDeleteOnCall { throw CleanSlateTestError.injected }
    data = nil
  }
}

private final class CleanSlateKeyStore: KeyStore {
  var seed: Data

  init(seed: Data) {
    self.seed = seed
  }

  func get() throws -> Data? { seed }
  func set(_ data: Data, accessibility _: KeychainAccessibility) throws { seed = data }
  func setAccessibility(_: KeychainAccessibility) throws {}
  func delete() throws {}
}

@MainActor
private final class CleanSlateTransport: Transport {
  var status: TransportStatus = .idle
  var connectedPeerCount = 0
  var log: [String] = []
  var onMessage: ((Data, String) -> TransportMessageDisposition)?
  var onConnectivity: (() -> Void)?
  private(set) var enabledValues: [Bool] = []

  func broadcast(_: Data, to _: Data?) {}
  func setEnabled(_ enabled: Bool) { enabledValues.append(enabled) }
}
