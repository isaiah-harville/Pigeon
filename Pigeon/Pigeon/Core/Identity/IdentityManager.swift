//
//  IdentityManager.swift
//  Pigeon
//
//  Owns the device's long-term Ed25519 identity key — the root of trust, the
//  basis of the fingerprint and safety number, and the key used to authenticate
//  to relays.
//

import CryptoKit
import Foundation

/// Creates and holds the device's long-term **Ed25519 identity key**, stored in
/// the Keychain (never leaving the device).
///
/// This is deliberately the *only* long-term key the app manages directly: the
/// Olm account (its Curve25519 identity key, one-time keys, and fallback key)
/// lives in `pigeon-core`'s `PigeonAccount`, which `SessionManager` builds from
/// this identity's seed after unlock and persists (sealed) in the vault. Keeping
/// the Ed25519 seed here lets locked-time work — the relay-auth signature and
/// the device's public id — run via CryptoKit without needing the Olm account
/// (which requires the unlocked vault).
///
/// Curve25519 (rather than Secure Enclave's P-256) is deliberate: it is the
/// curve the Olm stack requires, and the same 32-byte seed yields the same
/// Ed25519 keys in CryptoKit here and in `ed25519-dalek` inside pigeon-core, so
/// the identity (and safety number) is byte-stable across that boundary.
@Observable
final class IdentityManager {

  private static let identityAccount = "identity.ed25519.private"

  private let store: any KeyStore
  private var privateKey: Curve25519.Signing.PrivateKey

  /// The public identity safe to share with peers (Ed25519).
  var publicKey: IdentityPublicKey {
    IdentityPublicKey(signingKey: privateKey.publicKey)
  }

  /// The 32-byte private identity seed, used only in-process to build the Olm
  /// `PigeonAccount` bound to this identity. Secret — never logged or persisted
  /// outside the Keychain.
  var identitySeed: Data { privateKey.rawRepresentation }

  /// Loads the existing identity key, generating and persisting one if missing.
  convenience init() throws {
    try self.init(store: KeychainStore(account: IdentityManager.identityAccount))
  }

  init(store: any KeyStore) throws {
    self.store = store

    // A new key adopts the accessibility implied by the background-delivery
    // preference (default: readable in a locked background launch).
    let accessibility = BackgroundDelivery.accessibility

    if let existing = try store.get() {
      self.privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: existing)
    } else {
      let fresh = Curve25519.Signing.PrivateKey()
      try store.set(fresh.rawRepresentation, accessibility: accessibility)
      self.privateKey = fresh
    }
  }

  /// Rewrites the identity key under a new keychain accessibility class. Must be
  /// called while the device is unlocked (the key has to be readable to rewrite
  /// it). Used when the user toggles background delivery.
  func applyKeychainAccessibility(_ accessibility: KeychainAccessibility) throws {
    try store.setAccessibility(accessibility)
  }

  /// Signs `data` with the identity key (used for relay-mailbox authentication).
  func sign(_ data: Data) throws -> Data {
    try privateKey.signature(for: data)
  }

  /// Destroys the current identity and generates a fresh one. Irreversible: all
  /// existing trust relationships become invalid. The caller must also rebuild
  /// the Olm `PigeonAccount` (which is bound to this identity) from the new seed.
  func resetIdentity() throws {
    let accessibility = BackgroundDelivery.accessibility
    let fresh = Curve25519.Signing.PrivateKey()
    try store.set(fresh.rawRepresentation, accessibility: accessibility)
    self.privateKey = fresh
  }
}
