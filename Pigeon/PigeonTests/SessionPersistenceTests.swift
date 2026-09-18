import CryptoKit
import XCTest

@testable import Pigeon

@MainActor
final class SessionPersistenceTests: XCTestCase {
  private enum ExportFailure: Error {
    case injected
  }

  func testCorruptBulkStoreFailsInsteadOfStartingEmpty() throws {
    let url = FileManager.default.temporaryDirectory
      .appendingPathComponent("pigeon-corrupt-\(UUID().uuidString).store")
    defer { try? FileManager.default.removeItem(at: url) }
    try Data("not an encrypted store".utf8).write(to: url)
    let store = EncryptedStore(key: SymmetricKey(size: .bits256), url: url)

    XCTAssertThrowsError(try SessionPersistence().attach(store))
  }

  func testWrongKeyFailsInsteadOfReplacingStoredState() throws {
    let url = FileManager.default.temporaryDirectory
      .appendingPathComponent("pigeon-wrong-key-\(UUID().uuidString).store")
    defer { try? FileManager.default.removeItem(at: url) }
    let original = EncryptedStore(key: SymmetricKey(size: .bits256), url: url)
    XCTAssertTrue(original.save(PersistedState(myName: "Existing account")))

    XCTAssertThrowsError(
      try SessionPersistence().attach(
        EncryptedStore(key: SymmetricKey(size: .bits256), url: url)))
  }

  func testLegacyPairwiseBytesAreExposedAsOneOpaqueMigration() throws {
    let store = freshStore()
    var crypto = PersistedCrypto()
    crypto.olmAccountPickle = Data("account".utf8)
    crypto.olmFallbackKey = Data(repeating: 3, count: 32)
    let peer = Data(repeating: 4, count: 32)
    crypto.sessions[peer.base64EncodedString()] = PersistedSession(
      pickle: Data("session".utf8), pendingInitiation: nil,
      lastInitiationIn: nil, acceptedInitiationDigests: [])
    XCTAssertTrue(store.companion(suffix: ".crypto").save(crypto))

    let loaded = try SessionPersistence().attach(store)
    let migration = try XCTUnwrap(loaded.legacyPairwiseMigration)

    XCTAssertEqual(migration.accountState, Data("account".utf8))
    XCTAssertEqual(migration.fallbackKey, Data(repeating: 3, count: 32))
    XCTAssertEqual(migration.sessions.first?.remoteIdentity, peer)
    XCTAssertEqual(migration.sessions.first?.state, Data("session".utf8))
  }

  func testFirstCoreOwnedSaveRetiresLegacyPairwiseBlob() throws {
    let store = freshStore()
    var crypto = PersistedCrypto()
    crypto.olmAccountPickle = Data("account".utf8)
    crypto.olmFallbackKey = Data(repeating: 3, count: 32)
    XCTAssertTrue(store.companion(suffix: ".crypto").save(crypto))
    let persistence = SessionPersistence()
    _ = try persistence.attach(store)

    XCTAssertTrue(persistence.save(snapshot(name: "Alice")))

    let retired = try XCTUnwrap(
      store.companion(suffix: ".crypto").load(PersistedCrypto.self))
    XCTAssertNil(retired.olmAccountPickle)
    XCTAssertNil(retired.olmFallbackKey)
    XCTAssertTrue(retired.sessions.isEmpty)
    XCTAssertEqual(try SessionPersistence().attach(store).myName, "Alice")
  }

  func testBulkWriteFailureRecoversJournaledGeneration() throws {
    let url = FileManager.default.temporaryDirectory
      .appendingPathComponent("pigeon-transaction-\(UUID().uuidString).store")
    let key = SymmetricKey(size: .bits256)
    var failBulkWrite = false
    let io = EncryptedStoreIO(
      write: { data, destination, options in
        if failBulkWrite, destination == url { throw ExportFailure.injected }
        try data.write(to: destination, options: options)
      },
      remove: { try FileManager.default.removeItem(at: $0) })
    let faultingStore = EncryptedStore(key: key, url: url, io: io)
    defer { wipe(EncryptedStore(key: key, url: url)) }
    let persistence = SessionPersistence()
    _ = try persistence.attach(faultingStore)
    XCTAssertTrue(persistence.save(snapshot(name: "before")))

    failBulkWrite = true
    XCTAssertFalse(persistence.save(snapshot(name: "after")))
    failBulkWrite = false

    let recovered = try SessionPersistence().attach(EncryptedStore(key: key, url: url))
    XCTAssertEqual(recovered.myName, "after")
    XCTAssertNil(
      try EncryptedStore(key: key, url: url)
        .companion(suffix: ".transaction")
        .load(PersistedStateTransaction.self))
  }

  private func snapshot(name: String) -> SessionPersistence.Snapshot {
    SessionPersistence.Snapshot(
      contacts: [], conversations: [:], ephemeralContactIDs: [],
      bluetoothChatIDs: [], myName: name)
  }

  private func freshStore() -> EncryptedStore {
    let store = EncryptedStore(key: SymmetricKey(size: .bits256))
    wipe(store)
    return store
  }

  private func wipe(_ store: EncryptedStore) {
    store.wipe()
    store.companion(suffix: ".crypto").wipe()
    store.companion(suffix: ".transaction").wipe()
    store.companion(suffix: CoreCheckpointStore.companionSuffix).wipe()
  }
}
