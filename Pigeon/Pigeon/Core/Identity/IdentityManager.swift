//
//  IdentityManager.swift
//  Pigeon
//
//  Owns the device's long-term identity: the Ed25519 identity key and the
//  X25519 Noise static key bound to it.
//

import CryptoKit
import Foundation
import PigeonCrypto

/// Creates and holds the device's long-term keys.
///
/// Two long-term keys, both generated on first launch and stored in the
/// Keychain (never leaving the device):
/// - an **Ed25519 identity key** — the root of trust, basis of the fingerprint
///   and safety number;
/// - an **X25519 Noise static key** — used by the handshake — whose public half
///   is **signed by the identity key** so the two are cryptographically bound.
///
/// Curve25519 (rather than Secure Enclave's P-256) is deliberate: it is the
/// curve the Noise + Double Ratchet stack requires.
@Observable
final class IdentityManager {

  private static let identityAccount = "identity.ed25519.private"
  private static let staticAccount = "noise.static.x25519.private"

  private let store: KeychainStore
  private let staticStore: KeychainStore
  private var privateKey: Curve25519.Signing.PrivateKey
  private var staticKeyPair: DHKeyPair

  /// The public identity safe to share with peers (Ed25519).
  var publicKey: IdentityPublicKey {
    IdentityPublicKey(signingKey: privateKey.publicKey)
  }

  /// The X25519 Noise static key pair used to establish encrypted sessions.
  var noiseStaticKey: DHKeyPair { staticKeyPair }

  /// The signed, shareable identity bundle (Ed25519 identity ‖ X25519 static ‖
  /// signature). This is what we encode into our QR code.
  var identityBundle: IdentityBundle {
    let staticPub = staticKeyPair.publicKey.rawRepresentation
    // Signing our own static key cannot fail with a valid identity key.
    let signature = (try? privateKey.signature(for: staticPub)) ?? Data()
    return IdentityBundle(
      identityKey: privateKey.publicKey.rawRepresentation,
      staticKey: staticPub,
      signature: signature)
  }

  /// Loads existing keys, generating and persisting any that are missing.
  convenience init() throws {
    try self.init(
      store: KeychainStore(account: IdentityManager.identityAccount),
      staticStore: KeychainStore(account: IdentityManager.staticAccount))
  }

  init(
    store: KeychainStore,
    staticStore: KeychainStore
  ) throws {
    self.store = store
    self.staticStore = staticStore

    // New keys adopt the accessibility implied by the background-delivery
    // preference (default: readable in a locked background launch).
    let accessibility = BackgroundDelivery.accessibility

    if let existing = try store.get() {
      self.privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: existing)
    } else {
      let fresh = Curve25519.Signing.PrivateKey()
      try store.set(fresh.rawRepresentation, accessibility: accessibility)
      self.privateKey = fresh
    }

    if let existingStatic = try staticStore.get() {
      let key = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: existingStatic)
      self.staticKeyPair = DHKeyPair(privateKey: key)
    } else {
      let fresh = DHKeyPair()
      try staticStore.set(fresh.privateKey.rawRepresentation, accessibility: accessibility)
      self.staticKeyPair = fresh
    }
  }

  /// Rewrites both long-term keys under a new keychain accessibility class.
  /// Must be called while the device is unlocked (the keys have to be readable
  /// to rewrite them). Used when the user toggles background delivery.
  func applyKeychainAccessibility(_ accessibility: KeychainAccessibility) throws {
    try store.setAccessibility(accessibility)
    try staticStore.setAccessibility(accessibility)
  }

  /// Signs `data` with the identity key.
  func sign(_ data: Data) throws -> Data {
    try privateKey.signature(for: data)
  }

  /// Destroys the current identity and static key and generates fresh ones.
  /// Irreversible: all existing trust relationships become invalid.
  func resetIdentity() throws {
    let accessibility = BackgroundDelivery.accessibility
    let fresh = Curve25519.Signing.PrivateKey()
    try store.set(fresh.rawRepresentation, accessibility: accessibility)
    self.privateKey = fresh

    let freshStatic = DHKeyPair()
    try staticStore.set(freshStatic.privateKey.rawRepresentation, accessibility: accessibility)
    self.staticKeyPair = freshStatic
  }
}
