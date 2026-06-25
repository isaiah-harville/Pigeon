//
//  SecretBox.swift
//  Pigeon
//
//  Symmetric authenticated encryption for data at rest (the on-device message
//  store and the Olm account pickle), under a key the app holds in the Keychain.
//
//  This is at-rest storage encryption — a platform concern that belongs in the
//  app, not in the pairwise messaging core (pigeon-core). It uses a fresh random
//  nonce per seal (shipped with the ciphertext) since one long-lived key
//  encrypts many records, unlike the ratchet's deterministic per-message nonces.
//
//  Relocated from the (now-removed) Swift PigeonCrypto package during the
//  pigeon-core cutover.
//

import CryptoKit
import Foundation

enum SecretBoxError: Error, Equatable {
  case sealFailed
  case openFailed
}

/// AES-256-GCM seal/open with a random nonce, suitable for encrypting many
/// records under one long-lived key.
enum SecretBox {

  /// Encrypts `plaintext` under `key`. The returned blob is the GCM combined
  /// form (`nonce ‖ ciphertext ‖ tag`) and is self-describing for `open`.
  static func seal(_ plaintext: Data, key: SymmetricKey) throws -> Data {
    let sealed = try AES.GCM.seal(plaintext, using: key)
    guard let combined = sealed.combined else { throw SecretBoxError.sealFailed }
    return combined
  }

  /// Decrypts a blob produced by `seal`. Throws `openFailed` if the key is wrong
  /// or the blob was tampered with.
  static func open(_ box: Data, key: SymmetricKey) throws -> Data {
    do {
      let sealedBox = try AES.GCM.SealedBox(combined: box)
      return try AES.GCM.open(sealedBox, using: key)
    } catch {
      throw SecretBoxError.openFailed
    }
  }
}
