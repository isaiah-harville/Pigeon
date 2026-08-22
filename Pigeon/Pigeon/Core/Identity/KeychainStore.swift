//
//  KeychainStore.swift
//  Pigeon
//
//  Thin wrapper around the iOS/macOS Keychain for storing raw secret bytes.
//  Used to persist the device's long-term identity private key.
//

import Foundation
import Security

/// Errors surfaced by `KeychainStore`.
enum KeychainError: Error, Equatable {
  case unexpectedStatus(OSStatus)
  case dataConversionFailed
}

/// How readable a stored secret is relative to the device lock state. Both
/// options are `ThisDeviceOnly` — never synced to iCloud, never restored onto a
/// different device — and differ only in the lock-state window:
enum KeychainAccessibility {
  /// Readable only while the device is unlocked (strictest). Blocks access from
  /// a locked background launch.
  case whenUnlocked
  /// Readable after the first unlock following boot, including while later
  /// locked (until reboot). Needed for background work while the device is
  /// locked; a wider window for forensic extraction of a powered-on device.
  case afterFirstUnlock

  var secValue: CFString {
    switch self {
    case .whenUnlocked: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    case .afterFirstUnlock: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    }
  }
}

/// A persistent slot for one secret, abstracting the Keychain so identity code
/// can be unit-tested against an in-memory double. `KeychainStore` is the only
/// production implementation; it must never be backed by anything that leaves
/// the device (see the type's note on `…ThisDeviceOnly`).
protocol KeyStore {
  /// Returns the stored bytes, or `nil` if nothing is stored.
  func get() throws -> Data?
  /// Stores `data`, replacing any existing value, with the given accessibility.
  func set(_ data: Data, accessibility: KeychainAccessibility) throws
  /// Rewrites the stored item under a new accessibility class (no-op if empty).
  func setAccessibility(_ accessibility: KeychainAccessibility) throws
  /// Removes the stored item if present.
  func delete() throws
}

/// Injectable boundary around Security.framework. Keeping status-code handling
/// in `KeychainStore` lets tests prove replacements never delete the old item.
protocol KeychainClient {
  func copyMatching(_ query: [String: Any]) -> (OSStatus, Data?)
  func add(_ attributes: [String: Any]) -> OSStatus
  func update(_ query: [String: Any], attributes: [String: Any]) -> OSStatus
  func delete(_ query: [String: Any]) -> OSStatus
}

private struct SystemKeychainClient: KeychainClient {
  func copyMatching(_ query: [String: Any]) -> (OSStatus, Data?) {
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    return (status, result as? Data)
  }

  func add(_ attributes: [String: Any]) -> OSStatus {
    SecItemAdd(attributes as CFDictionary, nil)
  }

  func update(_ query: [String: Any], attributes: [String: Any]) -> OSStatus {
    SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
  }

  func delete(_ query: [String: Any]) -> OSStatus {
    SecItemDelete(query as CFDictionary)
  }
}

/// Stores small secrets (key material) in the Keychain as generic passwords.
///
/// Items are always `…ThisDeviceOnly`: they never leave the device, are not
/// included in backups, and never sync to iCloud. The caller chooses the
/// lock-state accessibility (`KeychainAccessibility`) per write. Identity keys
/// are the root of the app's security, so they must not migrate to new devices.
struct KeychainStore: KeyStore {

  /// The keychain service namespace for all Pigeon items.
  static let service = "com.isaiah-harville.Pigeon.keys"

  let account: String
  private let client: any KeychainClient

  init(account: String) {
    self.account = account
    self.client = SystemKeychainClient()
  }

  init(account: String, client: any KeychainClient) {
    self.account = account
    self.client = client
  }

  private var baseQuery: [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: Self.service,
      kSecAttrAccount as String: account,
    ]
  }

  /// Stores `data` with the given accessibility, replacing any existing value
  /// for this account.
  func set(_ data: Data, accessibility: KeychainAccessibility) throws {
    let replacement: [String: Any] = [
      kSecValueData as String: data,
      kSecAttrAccessible as String: accessibility.secValue,
    ]
    let updateStatus = client.update(baseQuery, attributes: replacement)
    if updateStatus == errSecSuccess { return }
    guard updateStatus == errSecItemNotFound else {
      throw KeychainError.unexpectedStatus(updateStatus)
    }

    var query = baseQuery
    for (key, value) in replacement { query[key] = value }

    let status = client.add(query)
    guard status == errSecSuccess else {
      throw KeychainError.unexpectedStatus(status)
    }
  }

  /// Rewrites the stored item under a new accessibility class. Requires the item
  /// to be readable now (i.e. the device unlocked); a no-op if nothing is stored.
  func setAccessibility(_ accessibility: KeychainAccessibility) throws {
    let status = client.update(
      baseQuery,
      attributes: [kSecAttrAccessible as String: accessibility.secValue])
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw KeychainError.unexpectedStatus(status)
    }
  }

  /// Returns the stored bytes, or `nil` if no item exists.
  func get() throws -> Data? {
    var query = baseQuery
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne

    let (status, result) = client.copyMatching(query)

    switch status {
    case errSecSuccess:
      guard let result else {
        throw KeychainError.dataConversionFailed
      }
      return result
    case errSecItemNotFound:
      return nil
    default:
      throw KeychainError.unexpectedStatus(status)
    }
  }

  /// Removes the stored item if present. Used for identity reset / wipe.
  func delete() throws {
    let status = client.delete(baseQuery)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw KeychainError.unexpectedStatus(status)
    }
  }
}
