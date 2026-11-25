//
//  CoreIdentityProvider.swift
//  Pigeon
//
//  Platform-backed identity implementation for pigeon-core. Private keys stay
//  in ThisDeviceOnly Keychain slots and only public-key/sign operations cross
//  the FFI boundary.
//

import CryptoKit
import Foundation
import PigeonFFI
import Security

protocol IdentityKeyStoreFactory {
  func makeStore(account: String) -> any KeyStore
}

private struct KeychainIdentityKeyStoreFactory: IdentityKeyStoreFactory {
  func makeStore(account: String) -> any KeyStore {
    KeychainStore(account: account)
  }
}

final class CoreIdentityProvider: PlatformIdentity, @unchecked Sendable {
  private static let mlsAccount = "identity.mls.ed25519.private"

  static func isScopedIdentityAccount(_ account: String) -> Bool {
    account == mlsAccount
      || (account.hasPrefix("identity.group.")
        && (account.hasSuffix(".capability.ed25519.private")
          || account.hasSuffix(".recovery.ed25519.private")))
  }

  /// Removes purpose-scoped keys when the matching core checkpoint is erased.
  /// A reset must never leave old group signing material in the Keychain.
  static func deleteStoredScopedKeys() throws {
    for account in try storedScopedAccounts() {
      try KeychainStore(account: account).delete()
    }
  }

  static func exportStoredScopedKeys() throws -> [String: Data] {
    var seeds: [String: Data] = [:]
    for account in try storedScopedAccounts() {
      guard let seed = try KeychainStore(account: account).get(), seed.count == 32 else {
        throw PlatformError.InvalidOutput
      }
      seeds[account] = seed
    }
    return seeds
  }

  private static func storedScopedAccounts() throws -> [String] {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: KeychainStore.service,
      kSecReturnAttributes as String: true,
      kSecMatchLimit as String: kSecMatchLimitAll,
    ]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound { return [] }
    guard status == errSecSuccess, let items = result as? [[String: Any]] else {
      throw KeychainError.unexpectedStatus(status)
    }
    return items.compactMap { item in
      guard let account = item[kSecAttrAccount as String] as? String,
        isScopedIdentityAccount(account)
      else { return nil }
      return account
    }.sorted()
  }

  private let rootIdentity: IdentityManager
  private let storeFactory: any IdentityKeyStoreFactory
  private let lock = NSLock()
  private var scopedKeys: [String: Curve25519.Signing.PrivateKey] = [:]

  convenience init(rootIdentity: IdentityManager) {
    self.init(rootIdentity: rootIdentity, storeFactory: KeychainIdentityKeyStoreFactory())
  }

  init(rootIdentity: IdentityManager, storeFactory: any IdentityKeyStoreFactory) {
    self.rootIdentity = rootIdentity
    self.storeFactory = storeFactory
  }

  func ensurePublicKey(purpose: IdentityPurposeRequest) throws -> Data {
    switch purpose.kind {
    case .root, .relay:
      guard purpose.groupId.isEmpty else { throw PlatformError.InvalidOutput }
      return lock.withLock { rootIdentity.publicKey.rawRepresentation }
    case .mls, .groupCapability, .groupRecovery:
      return try scopedKey(for: purpose).publicKey.rawRepresentation
    }
  }

  func sign(purpose: IdentityPurposeRequest, message: Data) throws -> Data {
    switch purpose.kind {
    case .root, .relay:
      guard purpose.groupId.isEmpty else { throw PlatformError.InvalidOutput }
      return try lock.withLock { try rootIdentity.sign(message) }
    case .mls, .groupCapability, .groupRecovery:
      return try scopedKey(for: purpose).signature(for: message)
    }
  }

  private func scopedKey(
    for purpose: IdentityPurposeRequest
  ) throws -> Curve25519.Signing.PrivateKey {
    let account = try account(for: purpose)
    return try lock.withLock {
      if let existing = scopedKeys[account] { return existing }
      let store = storeFactory.makeStore(account: account)
      let key: Curve25519.Signing.PrivateKey
      do {
        if let stored = try store.get() {
          guard stored.count == 32 else { throw PlatformError.InvalidOutput }
          try store.setAccessibility(.whenUnlocked)
          key = try Curve25519.Signing.PrivateKey(rawRepresentation: stored)
        } else {
          let generated = Curve25519.Signing.PrivateKey()
          try store.set(
            generated.rawRepresentation,
            accessibility: .whenUnlocked)
          guard try store.get() == generated.rawRepresentation else {
            throw PlatformError.Unavailable
          }
          key = generated
        }
      } catch let error as PlatformError {
        throw error
      } catch {
        throw PlatformError.Unavailable
      }
      scopedKeys[account] = key
      return key
    }
  }

  /// Loads already-stored scoped keys for `groupIDs` (and the MLS key) into
  /// memory while the device is unlocked, so a session that keeps running
  /// after the screen locks can still sign for its groups. The keys stay
  /// `whenUnlocked` at rest; this never generates a key.
  func preloadScopedKeys(groupIDs: [Data]) {
    var accounts = [Self.mlsAccount]
    for groupID in groupIDs where groupID.count == 32 {
      accounts.append(Self.groupAccount(groupID, suffix: "capability"))
      accounts.append(Self.groupAccount(groupID, suffix: "recovery"))
    }
    lock.withLock {
      for account in accounts where scopedKeys[account] == nil {
        let store = storeFactory.makeStore(account: account)
        guard let stored = try? store.get(), stored.count == 32,
          (try? store.setAccessibility(.whenUnlocked)) != nil,
          let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: stored)
        else { continue }
        scopedKeys[account] = key
      }
    }
  }

  private static func groupAccount(_ groupID: Data, suffix: String) -> String {
    let group = groupID.map { String(format: "%02x", $0) }.joined()
    return "identity.group.\(group).\(suffix).ed25519.private"
  }

  private func account(for purpose: IdentityPurposeRequest) throws -> String {
    switch purpose.kind {
    case .mls:
      guard purpose.groupId.isEmpty else { throw PlatformError.InvalidOutput }
      return Self.mlsAccount
    case .groupCapability, .groupRecovery:
      guard purpose.groupId.count == 32 else { throw PlatformError.InvalidOutput }
      let suffix = purpose.kind == .groupCapability ? "capability" : "recovery"
      return Self.groupAccount(purpose.groupId, suffix: suffix)
    case .root, .relay:
      throw PlatformError.InvalidOutput
    }
  }
}
