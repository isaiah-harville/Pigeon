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

    // Only a device with no biometrics *and* no passcode may store the DEK
    // ungated (e.g. a dev Mac) — otherwise the app couldn't run at all there.
    // Everywhere else the presence gate is mandatory: a failure to apply it is
    // surfaced, never silently downgraded to an item any process running as this
    // app could read whenever the device is unlocked.
    return try store(keyData, presenceGated: canGateOnPresence)
  }

  /// Whether this device can enforce a user-presence gate at all — false only
  /// when neither biometrics nor a passcode is enrolled.
  nonisolated private static var canGateOnPresence: Bool {
    LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
  }

  nonisolated private static func store(_ keyData: Data, presenceGated: Bool) throws -> Data {
    var query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecValueData as String: keyData,
    ]
    if presenceGated {
      guard
        let access = SecAccessControlCreateWithFlags(
          nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .userPresence, nil)
      else { throw VaultError.accessControlFailed }
      query[kSecAttrAccessControl as String] = access
    } else {
      query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    }
    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else { throw VaultError.keychainFailed(status) }
    return keyData
  }
}
