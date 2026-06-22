//
//  EncryptedStore.swift
//  Pigeon
//
//  Persists app state to disk, encrypted at rest with the Vault's key via
//  SecretBox. The on-disk files are opaque ciphertext.
//
//  State is split across two sealed blobs under the same key so the small, hot
//  crypto state (the Olm account + per-contact ratchet pickles, which change on
//  *every* encrypt/decrypt and must be durable promptly) is written without
//  re-encoding the bulky conversation history each time:
//    • `pigeon.store`  — contacts, conversations, per-chat flags, display name.
//    • `pigeon.crypto` — Olm account pickle + fallback + per-contact session
//                        pickles and in-flight initiation blobs.
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

/// The bulky, slow-changing app state: contacts and conversation history.
/// Conversation keys are contact identity keys, hex/base64-encoded for JSON.
struct PersistedState: Codable {
  var contacts: [PersistedContact] = []
  var conversations: [String: [ChatMessage]] = [:]
  /// Base64 identity ids of contacts whose chat is ephemeral.
  var ephemeralContactIDs: [String] = []
  /// Base64 identity ids of contacts whose chat uses Bluetooth instead of the
  /// relay (relay is the default). Defaults empty so older stores still decode.
  var bluetoothContactIDs: [String] = []
  /// Base64 identity ids of contacts that have an open conversation (a chat that
  /// shows on the home list). A contact can exist in the book without one — see
  /// the contacts/messaging split. Defaults empty.
  var activeConversationIDs: [String] = []
  /// The local user's own display name, shared in their QR card.
  var myName: String = ""
  /// Legacy crypto fields — read only to migrate stores written before the
  /// crypto/bulk split, never written again (they live in `PersistedCrypto` now).
  var olmAccountPickle: Data?
  var olmFallbackKey: Data?
}

/// One contact's persisted Olm session state (secret — only ever written sealed).
struct PersistedSession: Codable {
  /// The live ratchet pickle, so the conversation survives relaunch without a
  /// fresh handshake. `nil` when no session is established yet.
  var pickle: Data?
  /// The initiation we sent but haven't seen acked, resent after relaunch until
  /// the peer stands up its side. `nil` once acked.
  var pendingInitiation: Data?
  /// The last initiation we processed (responder-side dedup), so a retransmit
  /// after relaunch doesn't rebuild a second session. `nil` until we accept one.
  var lastInitiationIn: Data?

  var isEmpty: Bool { pickle == nil && pendingInitiation == nil && lastInitiationIn == nil }
}

/// The small, frequently-rewritten crypto state, sealed apart from the bulk so a
/// ratchet advance doesn't re-encode conversation history.
struct PersistedCrypto: Codable {
  /// The Olm account pickle (secret); the device's Olm identity/fallback prekey.
  var olmAccountPickle: Data?
  /// The account's current fallback public key (public), needed to rebuild it
  /// since Olm cannot report it after publishing.
  var olmFallbackKey: Data?
  /// Unix-time seconds of the last signed-prekey (fallback) rotation; `nil` until
  /// first stamped. Drives periodic rotation (bounds the no-one-time-key window).
  var fallbackRotatedAt: Double?
  /// Per-contact session state, keyed by base64 contact identity id.
  var sessions: [String: PersistedSession] = [:]

  /// Reconstructs crypto state from a legacy single-file `PersistedState` for
  /// stores written before the split (only the account pickle + fallback ever
  /// shipped that way; per-contact sessions were never persisted pre-split).
  init(migratingFrom legacy: PersistedState) {
    olmAccountPickle = legacy.olmAccountPickle
    olmFallbackKey = legacy.olmFallbackKey
  }

  init() {}
}

/// Reads and writes a single sealed `Codable` blob in Application Support.
struct EncryptedStore {
  private let key: SymmetricKey
  private let url: URL

  /// The default bulk store.
  init(key: SymmetricKey) {
    self.init(key: key, fileName: "pigeon.store")
  }

  init(key: SymmetricKey, fileName: String) {
    self.key = key
    let base =
      (try? FileManager.default.url(
        for: .applicationSupportDirectory,
        in: .userDomainMask,
        appropriateFor: nil,
        create: true)) ?? FileManager.default.temporaryDirectory
    self.url = base.appendingPathComponent(fileName)
  }

  /// A companion store under the same key and directory whose file name is this
  /// store's name plus `suffix` — for a separate sealed blob (e.g. the crypto
  /// state kept apart from the bulk). Deriving from this store's own name keeps
  /// companions distinct when several stores coexist (e.g. multiple identities).
  func companion(suffix: String) -> EncryptedStore {
    EncryptedStore(key: key, fileName: url.lastPathComponent + suffix)
  }

  /// Decrypts and decodes the stored blob, or `nil` if there is nothing stored
  /// yet (or it can't be read/decoded with this key).
  func load<T: Decodable>(_: T.Type) -> T? {
    guard let blob = try? Data(contentsOf: url),
      let plaintext = try? SecretBox.open(blob, key: key),
      let value = try? JSONDecoder().decode(T.self, from: plaintext)
    else {
      return nil
    }
    return value
  }

  /// Encodes, encrypts, and writes the blob atomically with file protection.
  func save<T: Encodable>(_ value: T) {
    guard let plaintext = try? JSONEncoder().encode(value),
      let blob = try? SecretBox.seal(plaintext, key: key)
    else { return }
    try? blob.write(to: url, options: [.atomic, .completeFileProtection])
  }

  /// Removes this on-disk blob (used when switching to ephemeral mode / wipe).
  func wipe() {
    try? FileManager.default.removeItem(at: url)
  }
}
