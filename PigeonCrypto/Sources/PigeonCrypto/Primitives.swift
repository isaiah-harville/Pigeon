//
//  Primitives.swift
//  PigeonCrypto
//
//  The low-level cryptographic operations the Double Ratchet and Noise layers
//  are composed from. Every primitive here delegates the actual math to Apple
//  CryptoKit (constant-time, audited); this file only wires them together in
//  the shapes the protocols require.
//

import CryptoKit
import Foundation

/// Errors thrown by the crypto layer.
public enum CryptoError: Error, Equatable {
  /// AEAD authentication failed — ciphertext was tampered with or the wrong key was used.
  case authenticationFailed
  /// A key or input had an unexpected length.
  case invalidLength
}

/// A Curve25519 key-agreement (X25519) key pair, the unit the ratchet's
/// Diffie-Hellman steps operate on.
public struct DHKeyPair: Sendable {
  public let privateKey: Curve25519.KeyAgreement.PrivateKey
  public var publicKey: Curve25519.KeyAgreement.PublicKey { privateKey.publicKey }

  /// Generates a fresh ephemeral key pair.
  public init() {
    self.privateKey = Curve25519.KeyAgreement.PrivateKey()
  }

  public init(privateKey: Curve25519.KeyAgreement.PrivateKey) {
    self.privateKey = privateKey
  }

  /// X25519 shared secret with `peerPublicKey`, returned as raw 32 bytes.
  public func sharedSecret(with peerPublicKey: Curve25519.KeyAgreement.PublicKey) throws -> Data {
    let secret = try privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey)
    return secret.withUnsafeBytes { Data($0) }
  }
}

/// Namespace for the keyed-derivation and AEAD primitives. The function shapes
/// (`kdfRootKey`, `kdfChainKey`, `encrypt`/`decrypt`) mirror the Double Ratchet
/// specification's `KDF_RK`, `KDF_CK`, and `ENCRYPT`/`DECRYPT`.
public enum Primitives {

  /// Domain-separation string mixed into every root-key derivation, so keys
  /// derived by Pigeon can never collide with another protocol reusing the spec.
  static let rootInfo = Data("Pigeon.DoubleRatchet.RootKey".utf8)

  // MARK: - KDF_RK

  /// Root KDF: given the current root key and a fresh DH output, derives the
  /// next root key and a new sending/receiving chain key.
  ///
  /// `HKDF-SHA256(salt: rootKey, ikm: dhOutput, info: rootInfo, L: 64)`,
  /// split into two 32-byte halves.
  public static func kdfRootKey(rootKey: Data, dhOutput: Data) -> (rootKey: Data, chainKey: Data) {
    let derived = HKDF<SHA256>.deriveKey(
      inputKeyMaterial: SymmetricKey(data: dhOutput),
      salt: rootKey,
      info: rootInfo,
      outputByteCount: 64
    )
    var bytes = derived.withUnsafeBytes { Data($0) }
    // Return fresh copies of the two halves, then wipe the combined buffer.
    // `Data(_:)` copies into new storage, so `bytes` stays the sole owner and
    // zeroing it below cannot corrupt the returned values.
    defer { SecureMemory.zero(&bytes) }
    return (rootKey: Data(bytes.prefix(32)), chainKey: Data(bytes.suffix(32)))
  }

  // MARK: - KDF_CK

  /// Constants distinguishing the two HMAC outputs of the symmetric-key ratchet.
  private static let messageKeyConstant = Data([0x01])
  private static let chainKeyConstant = Data([0x02])

  /// Chain KDF: ratchets a chain key forward, producing the next chain key and
  /// the message key for the current step.
  ///
  /// `messageKey = HMAC-SHA256(key: chainKey, data: 0x01)`
  /// `nextChainKey = HMAC-SHA256(key: chainKey, data: 0x02)`
  ///
  /// Because it is one-way, an attacker who compromises a chain key cannot
  /// recover earlier message keys (forward secrecy within the chain).
  public static func kdfChainKey(chainKey: Data) -> (chainKey: Data, messageKey: Data) {
    let key = SymmetricKey(data: chainKey)
    let messageKey = HMAC<SHA256>.authenticationCode(for: messageKeyConstant, using: key)
    let nextChainKey = HMAC<SHA256>.authenticationCode(for: chainKeyConstant, using: key)
    return (chainKey: Data(nextChainKey), messageKey: Data(messageKey))
  }

  // MARK: - AEAD

  static let aeadInfo = Data("Pigeon.DoubleRatchet.MessageKey".utf8)

  /// Expands a one-time 32-byte message key into an AES-256-GCM key and a
  /// deterministic 12-byte nonce. Safe because each message key is used for
  /// exactly one encryption, so the (key, nonce) pair never repeats.
  private static func deriveAEAD(messageKey: Data) throws -> (
    key: SymmetricKey, nonce: AES.GCM.Nonce
  ) {
    guard messageKey.count == 32 else { throw CryptoError.invalidLength }
    var material = HKDF<SHA256>.deriveKey(
      inputKeyMaterial: SymmetricKey(data: messageKey),
      info: aeadInfo,
      outputByteCount: 44  // 32-byte key + 12-byte nonce
    ).withUnsafeBytes { Data($0) }
    // `SymmetricKey`/`Nonce` copy their inputs into their own storage, so we can
    // wipe the derived buffer once they're built without affecting them.
    defer { SecureMemory.zero(&material) }
    let key = SymmetricKey(data: material.prefix(32))
    let nonce = try AES.GCM.Nonce(data: material.suffix(12))
    return (key, nonce)
  }

  /// Authenticated encryption of `plaintext` under a one-time message key,
  /// binding `associatedData` (e.g. the ratchet header) into the auth tag.
  /// Returns the combined ciphertext+tag.
  public static func encrypt(plaintext: Data, messageKey: Data, associatedData: Data) throws -> Data
  {
    let (key, nonce) = try deriveAEAD(messageKey: messageKey)
    let sealed = try AES.GCM.seal(
      plaintext, using: key, nonce: nonce, authenticating: associatedData)
    // Nonce is deterministic and recomputed on decrypt, so omit it; ship ct+tag.
    guard let combined = sealed.combined else { throw CryptoError.authenticationFailed }
    return combined.suffix(from: combined.startIndex + 12)  // drop the 12-byte nonce prefix
  }

  /// Reverses `encrypt`. Throws `authenticationFailed` if the ciphertext or
  /// associated data was tampered with.
  public static func decrypt(ciphertext: Data, messageKey: Data, associatedData: Data) throws
    -> Data
  {
    let (key, nonce) = try deriveAEAD(messageKey: messageKey)
    do {
      let box = try AES.GCM.SealedBox(combined: Data(nonce) + ciphertext)
      return try AES.GCM.open(box, using: key, authenticating: associatedData)
    } catch {
      throw CryptoError.authenticationFailed
    }
  }
}
