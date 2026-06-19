//
//  EncryptedStore.swift
//  Pigeon
//
//  Persists app state (contacts, conversations) to disk, encrypted at rest
//  with the Vault's key via SecretBox. The on-disk file is opaque ciphertext.
//

import CryptoKit
import Foundation

/// A contact in persisted form (the identity bundle stored as its protobuf encoding).
struct PersistedContact: Codable {
  var name: String
  var bundle: Data
  /// Advertised relay endpoints (absolute URL strings). Defaults empty so
  /// stores written before relay support still decode.
  var relayURLs: [String] = []
  /// The relay the user prefers for this conversation (absolute URL string), or
  /// `nil` for automatic. Defaults nil so older stores still decode (#18).
  var preferredRelayURL: String?
  /// The contact's published Olm prekey bundle, as its wire encoding. `nil` for
  /// contacts / cards without prekeys. Defaults nil so older stores decode.
  var prekeyBundle: Data?
  /// Whether the contact was verified in person (scanned vs pasted). Defaults
  /// true so contacts saved before this field read as verified (§5.7 trust UX).
  var verifiedInPerson: Bool = true
}

/// The complete persisted app state. Conversation keys are contact identity
/// keys, hex-encoded for use as dictionary keys in JSON.
struct PersistedState: Codable {
  var contacts: [PersistedContact] = []
  var conversations: [String: [ChatMessage]] = [:]
  /// Base64 identity ids of contacts whose chat is ephemeral.
  var ephemeralContactIDs: [String] = []
  /// Base64 identity ids of contacts whose chat uses Bluetooth instead of the
  /// relay (relay is the default). Defaults empty so older stores still decode.
  var bluetoothContactIDs: [String] = []
  /// The local user's own display name, shared in their QR card.
  var myName: String = ""
  /// The Olm account pickle (secret), sealed at rest with everything else here.
  /// Persisted so the device's Olm identity/fallback prekey (advertised in the
  /// QR) survives relaunch. `nil` before the account is first built.
  var olmAccountPickle: Data?
  /// The Olm account's current fallback public key (public), needed to rebuild
  /// the account since Olm cannot report it after publishing.
  var olmFallbackKey: Data?
}

/// Reads and writes `PersistedState` as an encrypted blob in Application Support.
struct EncryptedStore {
  private let key: SymmetricKey
  private let url: URL

  init(key: SymmetricKey) {
    self.key = key
    let base =
      (try? FileManager.default.url(
        for: .applicationSupportDirectory,
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
      let state = try? JSONDecoder().decode(PersistedState.self, from: plaintext)
    else {
      return PersistedState()
    }
    return state
  }

  /// Encodes, encrypts, and writes the state atomically with file protection.
  func save(_ state: PersistedState) {
    guard let plaintext = try? JSONEncoder().encode(state),
      let blob = try? SecretBox.seal(plaintext, key: key)
    else { return }
    try? blob.write(to: url, options: [.atomic, .completeFileProtection])
  }

  /// Removes the on-disk store (used when switching to ephemeral mode / wipe).
  func wipe() {
    try? FileManager.default.removeItem(at: url)
  }
}
