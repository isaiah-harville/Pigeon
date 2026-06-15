//
//  EncryptedStore.swift
//  Pigeon
//
//  Persists app state (contacts, conversations) to disk, encrypted at rest
//  with the Vault's key via SecretBox. The on-disk file is opaque ciphertext.
//

import Foundation
import CryptoKit
import PigeonCrypto

/// A contact in persisted form (the IdentityBundle stored as its 128-byte encoding).
struct PersistedContact: Codable {
    var name: String
    var bundle: Data
}

/// The complete persisted app state. Conversation keys are contact identity
/// keys, hex-encoded for use as dictionary keys in JSON.
struct PersistedState: Codable {
    var contacts: [PersistedContact] = []
    var conversations: [String: [ChatMessage]] = [:]
    /// Base64 identity ids of contacts whose chat is ephemeral.
    var ephemeralContactIDs: [String] = []
    /// The local user's own display name, shared in their QR card.
    var myName: String = ""
}

/// Reads and writes `PersistedState` as an encrypted blob in Application Support.
struct EncryptedStore {
    private let key: SymmetricKey
    private let url: URL

    init(key: SymmetricKey) {
        self.key = key
        let base = (try? FileManager.default.url(for: .applicationSupportDirectory,
                                                 in: .userDomainMask,
                                                 appropriateFor: nil,
                                                 create: true)) ?? FileManager.default.temporaryDirectory
        self.url = base.appendingPathComponent("pigeon.store")
    }

    /// Decrypts and decodes the stored state, or returns empty state if there is
    /// nothing stored yet (or it can't be read with this key).
    func load() -> PersistedState {
        guard let blob = try? Data(contentsOf: url),
              let plaintext = try? SecretBox.open(blob, key: key),
              let state = try? JSONDecoder().decode(PersistedState.self, from: plaintext) else {
            return PersistedState()
        }
        return state
    }

    /// Encodes, encrypts, and writes the state atomically with file protection.
    func save(_ state: PersistedState) {
        guard let plaintext = try? JSONEncoder().encode(state),
              let blob = try? SecretBox.seal(plaintext, key: key) else { return }
        try? blob.write(to: url, options: [.atomic, .completeFileProtection])
    }

    /// Removes the on-disk store (used when switching to ephemeral mode / wipe).
    func wipe() {
        try? FileManager.default.removeItem(at: url)
    }
}
