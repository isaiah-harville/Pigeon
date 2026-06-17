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

/// Stores small secrets (key material) in the Keychain as generic passwords.
///
/// Items are always `…ThisDeviceOnly`: they never leave the device, are not
/// included in backups, and never sync to iCloud. The caller chooses the
/// lock-state accessibility (`KeychainAccessibility`) per write. Identity keys
/// are the root of the app's security, so they must not migrate to new devices.
struct KeychainStore {

  /// The keychain service namespace for all Pigeon items.
  static let service = "com.isaiah-harville.Pigeon.keys"

  let account: String

  init(account: String) {
    self.account = account
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
    // Delete first so we don't have to branch on add-vs-update.
    SecItemDelete(baseQuery as CFDictionary)

    var query = baseQuery
    query[kSecValueData as String] = data
    query[kSecAttrAccessible as String] = accessibility.secValue

    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else {
      throw KeychainError.unexpectedStatus(status)
    }
  }

  /// Rewrites the stored item under a new accessibility class. Requires the item
  /// to be readable now (i.e. the device unlocked); a no-op if nothing is stored.
  func setAccessibility(_ accessibility: KeychainAccessibility) throws {
    guard let data = try get() else { return }
    try set(data, accessibility: accessibility)
  }

  /// Returns the stored bytes, or `nil` if no item exists.
  func get() throws -> Data? {
    var query = baseQuery
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne

    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)

    switch status {
    case errSecSuccess:
      guard let data = result as? Data else {
        throw KeychainError.dataConversionFailed
      }
      return data
    case errSecItemNotFound:
      return nil
    default:
      throw KeychainError.unexpectedStatus(status)
    }
  }

  /// Removes the stored item if present. Used for identity reset / wipe.
  func delete() throws {
    let status = SecItemDelete(baseQuery as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw KeychainError.unexpectedStatus(status)
    }
  }
}
