//
//  SecretBox.swift
//  PigeonCrypto
//
//  Symmetric authenticated encryption for data at rest (e.g. the on-device
//  message store), under a key the app holds in the Keychain.
//
//  Unlike the ratchet's per-message AEAD (which derives a deterministic nonce
//  from a one-time key), a SecretBox generates a fresh random nonce per seal and
//  ships it with the ciphertext, since the same long-lived key encrypts many
//  records.
//

import Foundation
import CryptoKit

public enum SecretBoxError: Error, Equatable {
    case sealFailed
    case openFailed
}

/// AES-256-GCM seal/open with a random nonce, suitable for encrypting many
/// records under one long-lived key.
public enum SecretBox {

    /// Encrypts `plaintext` under `key`. The returned blob is the GCM combined
    /// form (`nonce ‖ ciphertext ‖ tag`) and is self-describing for `open`.
    public static func seal(_ plaintext: Data, key: SymmetricKey) throws -> Data {
        let sealed = try AES.GCM.seal(plaintext, using: key)
        guard let combined = sealed.combined else { throw SecretBoxError.sealFailed }
        return combined
    }

    /// Decrypts a blob produced by `seal`. Throws `openFailed` if the key is
    /// wrong or the blob was tampered with.
    public static func open(_ box: Data, key: SymmetricKey) throws -> Data {
        do {
            let sealedBox = try AES.GCM.SealedBox(combined: box)
            return try AES.GCM.open(sealedBox, using: key)
        } catch {
            throw SecretBoxError.openFailed
        }
    }
}
