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

/// Stores small secrets (key material) in the Keychain as generic passwords.
///
/// Items are written with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`:
/// they never leave the device, are not included in backups, and are only
/// readable while the device is unlocked. Identity keys are the root of the
/// app's security, so they must not sync to iCloud or migrate to new devices.
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

  /// Stores `data`, replacing any existing value for this account.
  func set(_ data: Data) throws {
    // Delete first so we don't have to branch on add-vs-update.
    SecItemDelete(baseQuery as CFDictionary)

    var query = baseQuery
    query[kSecValueData as String] = data
    query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly

    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else {
      throw KeychainError.unexpectedStatus(status)
    }
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
