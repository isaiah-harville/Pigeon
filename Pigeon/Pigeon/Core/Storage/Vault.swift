//
//  Vault.swift
//  Pigeon
//
//  Holds the at-rest data-encryption key (DEK) behind a biometric / passcode
//  gate. The DEK is a random 256-bit key stored in the Keychain with an access
//  control that requires user presence to read; we unlock once per launch and
//  keep the key in memory for the session.
//

import CryptoKit
import Foundation
import LocalAuthentication
import Security

enum VaultError: Error {
  case accessControlFailed
  case keychainFailed(OSStatus)
  case authenticationFailed
}

/// Manages the on-device storage key. Call `unlock()` once (prompts Face ID /
/// Touch ID); afterwards `key` is available for the `EncryptedStore`.
@MainActor
@Observable
final class Vault {

  nonisolated private static let service = "com.isaiah-harville.Pigeon.vault"
  nonisolated private static let account = "vault.dek"

  private(set) var isUnlocked = false
  private(set) var key: SymmetricKey?

  /// Loads (or, on first launch, creates) the DEK. May present a biometric
  /// prompt. Safe to call repeatedly; a no-op once unlocked.
  func unlock() async throws {
    try await unlock(reason: "Unlock your Pigeon messages")
  }

  func unlock(reason: String) async throws {
    if isUnlocked { return }
    let keyData = try await Self.loadOrCreateKey(reason: reason)
    self.key = SymmetricKey(data: keyData)
    self.isUnlocked = true
  }

  // Keychain work runs off the main actor because reading a presence-gated
  // item blocks while the system auth UI is shown.
  nonisolated private static func loadOrCreateKey(reason: String) async throws -> Data {
    try await withCheckedThrowingContinuation { continuation in
      DispatchQueue.global(qos: .userInitiated).async {
        do {
          continuation.resume(returning: try loadOrCreateKeySync(reason: reason))
        } catch {
          continuation.resume(throwing: error)
        }
      }
    }
  }

  nonisolated private static func loadOrCreateKeySync(reason: String) throws -> Data {
    // Authentication context drives the biometric/passcode prompt.
    let context = LAContext()
    context.localizedReason = reason

    // Try to read an existing key (this triggers the auth prompt).
    let readQuery: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecReturnData as String: true,
      kSecMatchLimit as String: kSecMatchLimitOne,
      kSecUseAuthenticationContext as String: context,
    ]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(readQuery as CFDictionary, &result)
    switch status {
    case errSecSuccess:
      guard let data = result as? Data else { throw VaultError.keychainFailed(status) }
      return data
    case errSecItemNotFound:
      return try createKey()
    case errSecUserCanceled, errSecAuthFailed:
      throw VaultError.authenticationFailed
    default:
      throw VaultError.keychainFailed(status)
    }
  }

  nonisolated private static func createKey() throws -> Data {
    let keyData = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }

    // Prefer a presence-gated item; fall back to device-unlock-only if the
    // device has no biometrics/passcode (e.g. a dev Mac), so the app still works.
    if let access = SecAccessControlCreateWithFlags(
      nil,
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      .userPresence, nil)
    {
      let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecValueData as String: keyData,
        kSecAttrAccessControl as String: access,
      ]
      if SecItemAdd(query as CFDictionary, nil) == errSecSuccess { return keyData }
    }

    let fallback: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecValueData as String: keyData,
      kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    ]
    let status = SecItemAdd(fallback as CFDictionary, nil)
    guard status == errSecSuccess else { throw VaultError.keychainFailed(status) }
    return keyData
  }
}
