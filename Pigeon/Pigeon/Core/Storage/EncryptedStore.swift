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

enum EncryptedStoreError: Error {
  case locationUnavailable
  case unreadable
  case authenticationFailed
  case invalidPayload
}

/// A contact in persisted form (the identity bundle stored as its protobuf encoding).
struct PersistedContact: Codable {
  var name: String
  var bundle: Data
  /// Advertised relay endpoints (absolute URL strings). Defaults empty so
  /// stores written before relay support still decode.
  var relayURLs: [String] = []
  /// The relay the user prefers for this conversation (absolute URL string), or
  /// `nil` for automatic. Defaults nil so older stores still decode.
  var preferredRelayURL: String?
  /// The contact's published Olm prekey bundle, as its wire encoding. `nil` for
  /// contacts / cards without prekeys. Defaults nil so older stores decode.
  var prekeyBundle: Data?
  /// Whether the contact was verified in person (scanned vs pasted). Defaults
  /// true so contacts saved before this field read as verified (§5.7 trust UX).
  var verifiedInPerson: Bool = true
  /// Missing for pre-1.3 stores, which decode as a normal contact.
  var requestState: ContactRequestState?
  /// Optional so stores created before message requests remain decodable.
  var introductionSent: Int?
  var introductionReceived: Int?
  var requestCreatedAt: TimeInterval?
}

struct PersistedBlockedContact: Codable {
  var id: Data
  var name: String
}

/// The bulky, slow-changing app state: contacts and conversation history.
/// Conversation keys are contact identity keys, hex/base64-encoded for JSON.
struct PersistedState: Codable {
  var contacts: [PersistedContact] = []
  var conversations: [String: [ChatMessage]] = [:]
  /// Group histories keyed by the base64-encoded authenticated group id.
  var groupConversations: [String: GroupConversation] = [:]
  /// Base64 identity ids of contacts whose chat is ephemeral.
  var ephemeralContactIDs: [String] = []
  /// Base64 identity ids of contacts whose chat uses Bluetooth instead of the
  /// relay (relay is the default). Defaults empty so older stores still decode.
  var bluetoothContactIDs: [String] = []
  /// Base64 identity ids of contacts that have an open conversation (a chat that
  /// shows on the home list). A contact can exist in the book without one — see
  /// the contacts/messaging split. Defaults empty.
  var activeConversationIDs: [String] = []
  /// Optional for compatibility with stores written before message requests.
  var blockedContacts: [PersistedBlockedContact] = []
  /// The local user's own display name, shared in their QR card.
  var myName: String = ""
  /// Legacy crypto fields — read only to migrate stores written before the
  /// crypto/bulk split, never written again (they live in `PersistedCrypto` now).
  var olmAccountPickle: Data?
  var olmFallbackKey: Data?

}

extension PersistedState {
  private enum CodingKeys: String, CodingKey {
    case contacts, conversations, groupConversations, ephemeralContactIDs, bluetoothContactIDs
    case activeConversationIDs, blockedContacts, myName, olmAccountPickle, olmFallbackKey
  }

  init(from decoder: Decoder) throws {
    let values = try decoder.container(keyedBy: CodingKeys.self)
    contacts = try values.decodeIfPresent([PersistedContact].self, forKey: .contacts) ?? []
    conversations =
      try values.decodeIfPresent([String: [ChatMessage]].self, forKey: .conversations) ?? [:]
    groupConversations =
      try values.decodeIfPresent([String: GroupConversation].self, forKey: .groupConversations)
      ?? [:]
    ephemeralContactIDs =
      try values.decodeIfPresent([String].self, forKey: .ephemeralContactIDs) ?? []
    bluetoothContactIDs =
      try values.decodeIfPresent([String].self, forKey: .bluetoothContactIDs) ?? []
    activeConversationIDs =
      try values.decodeIfPresent([String].self, forKey: .activeConversationIDs) ?? []
    blockedContacts =
      try values.decodeIfPresent([PersistedBlockedContact].self, forKey: .blockedContacts) ?? []
    myName = try values.decodeIfPresent(String.self, forKey: .myName) ?? ""
    olmAccountPickle = try values.decodeIfPresent(Data.self, forKey: .olmAccountPickle)
    olmFallbackKey = try values.decodeIfPresent(Data.self, forKey: .olmFallbackKey)
  }
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
  /// SHA-256 digests of every initiation accepted for this contact.
  var acceptedInitiationDigests: [Data]

  var isEmpty: Bool {
    pickle == nil && pendingInitiation == nil && lastInitiationIn == nil
      && acceptedInitiationDigests.isEmpty
  }

  init(
    pickle: Data?, pendingInitiation: Data?, lastInitiationIn: Data?,
    acceptedInitiationDigests: [Data]
  ) {
    self.pickle = pickle
    self.pendingInitiation = pendingInitiation
    self.lastInitiationIn = lastInitiationIn
    self.acceptedInitiationDigests = acceptedInitiationDigests
  }

  private enum CodingKeys: String, CodingKey {
    case pickle, pendingInitiation, lastInitiationIn, acceptedInitiationDigests
  }

  init(from decoder: Decoder) throws {
    let values = try decoder.container(keyedBy: CodingKeys.self)
    pickle = try values.decodeIfPresent(Data.self, forKey: .pickle)
    pendingInitiation = try values.decodeIfPresent(Data.self, forKey: .pendingInitiation)
    lastInitiationIn = try values.decodeIfPresent(Data.self, forKey: .lastInitiationIn)
    acceptedInitiationDigests =
      try values.decodeIfPresent([Data].self, forKey: .acceptedInitiationDigests) ?? []
  }
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

/// One recoverable full-state generation. This record is sealed before either
/// split destination is replaced, so startup can finish an interrupted commit
/// without combining conversation state and ratchets from different saves.
struct PersistedStateTransaction: Codable {
  let bulk: PersistedState
  let crypto: PersistedCrypto
}

/// Narrow file-system seam used to inject deterministic atomic-write failures.
/// Production still uses `Data.write(.atomic)` and `FileManager.removeItem`.
struct EncryptedStoreIO {
  let write: (Data, URL, Data.WritingOptions) throws -> Void
  let remove: (URL) throws -> Void

  static func live() -> EncryptedStoreIO {
    EncryptedStoreIO(
      write: { try $0.write(to: $1, options: $2) },
      remove: { try FileManager.default.removeItem(at: $0) })
  }
}

/// Reads and writes a single sealed `Codable` blob in Application Support.
struct EncryptedStore {
  private let key: SymmetricKey
  private let url: URL?
  private let io: EncryptedStoreIO

  /// The default bulk store.
  init(key: SymmetricKey) {
    self.init(key: key, fileName: "pigeon.store")
  }

  init(key: SymmetricKey, fileName: String) {
    self.key = key
    let base = try? FileManager.default.url(
      for: .applicationSupportDirectory,
      in: .userDomainMask,
      appropriateFor: nil,
      create: true)
    self.url = base?.appendingPathComponent(fileName)
    self.io = .live()
  }

  /// Explicit location injection for deterministic recovery tests.
  init(key: SymmetricKey, url: URL) {
    self.init(key: key, optionalURL: url, io: .live())
  }

  init(key: SymmetricKey, url: URL, io: EncryptedStoreIO) {
    self.init(key: key, optionalURL: url, io: io)
  }

  private init(key: SymmetricKey, optionalURL: URL?, io: EncryptedStoreIO) {
    self.key = key
    self.url = optionalURL
    self.io = io
  }

  /// A companion store under the same key and directory whose file name is this
  /// store's name plus `suffix` — for a separate sealed blob (e.g. the crypto
  /// state kept apart from the bulk). Deriving from this store's own name keeps
  /// companions distinct when several stores coexist (e.g. multiple identities).
  func companion(suffix: String) -> EncryptedStore {
    let companionURL = url.map { storeURL in
      storeURL.deletingLastPathComponent()
        .appendingPathComponent(storeURL.lastPathComponent + suffix)
    }
    return EncryptedStore(
      key: key,
      optionalURL: companionURL,
      io: io)
  }

  /// Returns `nil` only when no store exists. An inaccessible, unauthentic, or
  /// malformed blob is an explicit error so callers never mistake data loss or
  /// a wrong key for first launch.
  func load<T: Decodable>(_: T.Type) throws -> T? {
    guard let url else { throw EncryptedStoreError.locationUnavailable }
    guard FileManager.default.fileExists(atPath: url.path) else { return nil }
    let blob: Data
    do {
      blob = try Data(contentsOf: url)
    } catch {
      throw EncryptedStoreError.unreadable
    }
    let plaintext: Data
    do {
      plaintext = try SecretBox.open(blob, key: key)
    } catch {
      throw EncryptedStoreError.authenticationFailed
    }
    do {
      return try JSONDecoder().decode(T.self, from: plaintext)
    } catch {
      throw EncryptedStoreError.invalidPayload
    }
  }

  /// Encodes, encrypts, and writes the blob atomically. Returns whether the write
  /// landed, so a caller that just advanced the ratchet can tell that its state
  /// did *not* reach disk rather than assuming it did.
  ///
  /// File protection is deliberately `untilFirstUserAuthentication` rather than
  /// `complete`. Pigeon keeps working while the *device* is locked — that is what
  /// background delivery is — and a `complete` file cannot be written in that
  /// state, so every save during a locked-screen session failed silently. That
  /// lost received messages and, worse, left the sealed Olm session pickle
  /// lagging the live ratchet, which reuses message indices after a relaunch.
  /// The blob's real protection is its own encryption: it is sealed under the
  /// vault DEK, which lives in the Keychain behind a user-presence gate, so the
  /// file-system class is defence in depth, not the boundary.
  @discardableResult
  func save<T: Encodable>(_ value: T) -> Bool {
    guard let url,
      let plaintext = try? JSONEncoder().encode(value),
      let blob = try? SecretBox.seal(plaintext, key: key)
    else { return false }
    do {
      try io.write(
        blob, url, [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
      return true
    } catch {
      return false
    }
  }

  /// Removes this on-disk blob (used when switching to ephemeral mode / wipe).
  @discardableResult
  func wipe() -> Bool {
    guard let url else { return false }
    guard FileManager.default.fileExists(atPath: url.path) else { return true }
    do {
      try io.remove(url)
      return true
    } catch {
      return false
    }
  }
}
