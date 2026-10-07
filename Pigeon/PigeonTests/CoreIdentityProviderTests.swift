import CryptoKit
import Foundation
import PigeonFFI
import XCTest

@testable import Pigeon

private final class MemoryScopedKeyStore: KeyStore {
  private enum StoreError: Error {
    case unavailable
  }

  var data: Data?
  var isUnavailable = false
  var accessibility: KeychainAccessibility?

  func get() throws -> Data? {
    guard !isUnavailable else { throw StoreError.unavailable }
    return data
  }

  func set(_ data: Data, accessibility: KeychainAccessibility) throws {
    guard !isUnavailable else { throw StoreError.unavailable }
    self.data = data
    self.accessibility = accessibility
  }

  func setAccessibility(_ accessibility: KeychainAccessibility) throws {
    guard !isUnavailable else { throw StoreError.unavailable }
    self.accessibility = accessibility
  }

  func delete() throws {
    guard !isUnavailable else { throw StoreError.unavailable }
    data = nil
  }
}

private final class MemoryScopedKeyStoreFactory: IdentityKeyStoreFactory {
  private var stores: [String: MemoryScopedKeyStore] = [:]

  func makeStore(account: String) -> any KeyStore {
    if let store = stores[account] { return store }
    let store = MemoryScopedKeyStore()
    stores[account] = store
    return store
  }

  func store(account: String) -> MemoryScopedKeyStore? {
    stores[account]
  }
}

final class CoreIdentityProviderTests: XCTestCase {

  func testScopedKeyCleanupSelectsOnlyCorePurposeKeys() {
    XCTAssertTrue(CoreIdentityProvider.isScopedIdentityAccount("identity.mls.ed25519.private"))
    XCTAssertTrue(
      CoreIdentityProvider.isScopedIdentityAccount(
        "identity.group.abcdef.capability.ed25519.private"))
    XCTAssertTrue(
      CoreIdentityProvider.isScopedIdentityAccount(
        "identity.group.abcdef.recovery.ed25519.private"))
    XCTAssertFalse(
      CoreIdentityProvider.isScopedIdentityAccount("identity.ed25519.private"))
    XCTAssertFalse(
      CoreIdentityProvider.isScopedIdentityAccount("clean-slate.identity.target"))
  }
  private func request(_ kind: IdentityPurposeKind, group: UInt8? = nil)
    -> IdentityPurposeRequest
  {
    IdentityPurposeRequest(
      kind: kind,
      groupId: group.map { Data(repeating: $0, count: 32) } ?? Data())
  }

  func testPurposeKeysAreStableAndCryptographicallySeparated() throws {
    let root = try IdentityManager(store: InMemoryKeyStore(seed: Data(repeating: 1, count: 32)))
    let factory = MemoryScopedKeyStoreFactory()
    let provider = CoreIdentityProvider(rootIdentity: root, storeFactory: factory)

    let rootKey = try provider.ensurePublicKey(purpose: request(.root))
    let relayKey = try provider.ensurePublicKey(purpose: request(.relay))
    let mlsKey = try provider.ensurePublicKey(purpose: request(.mls))
    let capabilityA = try provider.ensurePublicKey(
      purpose: request(.groupCapability, group: 2))
    let capabilityB = try provider.ensurePublicKey(
      purpose: request(.groupCapability, group: 3))
    let recoveryA = try provider.ensurePublicKey(purpose: request(.groupRecovery, group: 2))

    XCTAssertEqual(rootKey, root.publicKey.rawRepresentation)
    XCTAssertEqual(relayKey, rootKey)
    XCTAssertNotEqual(mlsKey, rootKey)
    XCTAssertNotEqual(capabilityA, capabilityB)
    XCTAssertNotEqual(capabilityA, recoveryA)

    let restored = CoreIdentityProvider(rootIdentity: root, storeFactory: factory)
    XCTAssertEqual(
      try restored.ensurePublicKey(purpose: request(.mls)),
      mlsKey)
    XCTAssertEqual(
      try restored.ensurePublicKey(purpose: request(.groupCapability, group: 2)),
      capabilityA)
  }

  func testScopedKeysUseUnlockedOnlyKeychainAccessibility() throws {
    let root = try IdentityManager(store: InMemoryKeyStore(seed: Data(repeating: 7, count: 32)))
    let factory = MemoryScopedKeyStoreFactory()
    let provider = CoreIdentityProvider(rootIdentity: root, storeFactory: factory)

    _ = try provider.ensurePublicKey(purpose: request(.mls))
    _ = try provider.ensurePublicKey(purpose: request(.groupCapability, group: 2))
    _ = try provider.ensurePublicKey(purpose: request(.groupRecovery, group: 2))

    XCTAssertEqual(
      factory.store(account: "identity.mls.ed25519.private")?.accessibility,
      .whenUnlocked)
    let group = String(repeating: "02", count: 32)
    XCTAssertEqual(
      factory.store(account: "identity.group.\(group).capability.ed25519.private")?.accessibility,
      .whenUnlocked)
    XCTAssertEqual(
      factory.store(account: "identity.group.\(group).recovery.ed25519.private")?.accessibility,
      .whenUnlocked)
  }

  func testSignaturesVerifyUnderTheRequestedPurposeOnly() throws {
    let root = try IdentityManager(store: InMemoryKeyStore(seed: Data(repeating: 4, count: 32)))
    let provider = CoreIdentityProvider(
      rootIdentity: root, storeFactory: MemoryScopedKeyStoreFactory())
    let purpose = request(.groupCapability, group: 5)
    let message = Data("authenticated group control".utf8)
    let publicKey = try Curve25519.Signing.PublicKey(
      rawRepresentation: provider.ensurePublicKey(purpose: purpose))
    let signature = try provider.sign(purpose: purpose, message: message)

    XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
    XCTAssertFalse(root.publicKey.isValidSignature(signature, for: message))
  }

  func testGroupScopedPurposesRequireAnExactGroupID() throws {
    let root = try IdentityManager(store: InMemoryKeyStore(seed: Data(repeating: 6, count: 32)))
    let provider = CoreIdentityProvider(
      rootIdentity: root, storeFactory: MemoryScopedKeyStoreFactory())

    XCTAssertThrowsError(
      try provider.ensurePublicKey(
        purpose: IdentityPurposeRequest(kind: .groupRecovery, groupId: Data([1]))))
  }
}
