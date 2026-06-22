//
//  SessionPersistence.swift
//  Pigeon
//
//  The persistence/account slice of the session coordinator: owns the encrypted
//  stores, builds (or restores) the device's Olm account from the identity seed +
//  persisted pickle, and translates between the live domain objects and the
//  on-disk state. Extracted from SessionManager so the codec and the store
//  handles live in one focused type, leaving the coordinator to own only the
//  orchestration (unlock, establishment, draining the locked inbox).
//
//  State is split across two sealed blobs (see `EncryptedStore`): the bulky
//  conversation/contact state and the small, hot crypto state (account + per-
//  contact ratchet pickles). The crypto blob can be re-sealed on its own via
//  `saveCrypto` after a ratchet advance, so a send/ack no longer re-encodes the
//  whole conversation history.
//
//  This type owns no live state of its own — it reads a `Snapshot` to seal and
//  returns a `Loaded` to apply. The establishment/ratchet logic is untouched: the
//  account it returns is mutated in place by SessionManager's messaging code and
//  handed back here on the next save.
//

import Foundation
import PigeonFFI

/// Reads and writes the coordinator's durable state through `EncryptedStore`,
/// including building the bound Olm account. Not `@Observable`: persistence is a
/// side effect, not observable UI state.
@MainActor
final class SessionPersistence {

  /// The bulk store (contacts + conversations), set at unlock. `nil` (and every
  /// save a no-op) until `attach` runs.
  private var store: EncryptedStore?
  /// The crypto store (account + per-contact session state), a sibling of `store`
  /// under the same key. Re-sealed on its own via `saveCrypto`.
  private var cryptoStore: EncryptedStore?

  /// Suffix for the crypto companion blob (appended to the bulk store's name).
  private static let cryptoSuffix = ".crypto"

  /// Everything restored from disk at unlock, ready for the coordinator to apply.
  struct Loaded {
    var account: PigeonAccount?
    var contacts: [Contact]
    var conversations: [Data: [ChatMessage]]
    var ephemeralContactIDs: Set<Data>
    var bluetoothChatIDs: Set<Data>
    var activeConversationIDs: Set<Data>
    var myName: String
    /// Restored live Olm sessions, keyed by contact id. A contact appearing here
    /// is (re)established without a fresh handshake.
    var sessions: [Data: PigeonSession]
    var pendingInitiation: [Data: Data]
    var lastInitiationIn: [Data: Data]
    /// When the signed-prekey (fallback) was last rotated; `nil` if never stamped.
    var fallbackRotatedAt: Date?
  }

  /// The live state the coordinator hands over to be sealed at rest.
  struct Snapshot {
    var contacts: [Contact]
    var conversations: [Data: [ChatMessage]]
    var ephemeralContactIDs: Set<Data>
    var bluetoothChatIDs: Set<Data>
    var activeConversationIDs: Set<Data> = []
    var myName: String
    var account: PigeonAccount?
    /// Live per-contact session state to seal alongside the account. Keyed by
    /// contact id.
    var sessions: [Data: PigeonSession]
    var pendingInitiation: [Data: Data]
    var lastInitiationIn: [Data: Data]
    var fallbackRotatedAt: Date?
  }

  /// Attaches the stores and decodes persisted state, (re)building the Olm account
  /// bound to `identitySeed`. First launch yields a fresh account under the
  /// existing identity; thereafter the persisted pickle is imported so the
  /// published fallback prekey stays stable. Stores written before the crypto/bulk
  /// split are migrated transparently (their crypto fields move to the sibling on
  /// the next save).
  func attach(_ store: EncryptedStore, identitySeed: Data) -> Loaded {
    self.store = store
    let cryptoStore = store.companion(suffix: Self.cryptoSuffix)
    self.cryptoStore = cryptoStore

    let bulk = store.load(PersistedState.self) ?? PersistedState()
    let crypto = cryptoStore.load(PersistedCrypto.self) ?? PersistedCrypto(migratingFrom: bulk)
    let sessionState = Self.decodeSessionState(crypto.sessions)
    return Loaded(
      account: Self.buildAccount(seed: identitySeed, crypto: crypto),
      contacts: Self.decodeContacts(bulk.contacts),
      conversations: Self.decodeConversations(bulk.conversations),
      ephemeralContactIDs: Self.decodeIDs(bulk.ephemeralContactIDs),
      bluetoothChatIDs: Self.decodeIDs(bulk.bluetoothContactIDs),
      activeConversationIDs: Self.decodeIDs(bulk.activeConversationIDs),
      myName: bulk.myName,
      sessions: sessionState.sessions,
      pendingInitiation: sessionState.pending,
      lastInitiationIn: sessionState.lastIn,
      fallbackRotatedAt: crypto.fallbackRotatedAt.map { Date(timeIntervalSince1970: $0) })
  }

  /// Writes the full state: the bulk blob (contacts + conversations + flags) and
  /// the crypto blob (account + per-contact session state). No-op before `attach`.
  func save(_ snapshot: Snapshot) {
    guard let store else { return }
    var conversationsByKey: [String: [ChatMessage]] = [:]
    for (id, messages) in snapshot.conversations {
      conversationsByKey[id.base64EncodedString()] = messages
    }
    store.save(
      PersistedState(
        contacts: snapshot.contacts.map(Self.encodeContact),
        conversations: conversationsByKey,
        ephemeralContactIDs: snapshot.ephemeralContactIDs.map { $0.base64EncodedString() },
        bluetoothContactIDs: snapshot.bluetoothChatIDs.map { $0.base64EncodedString() },
        activeConversationIDs: snapshot.activeConversationIDs.map { $0.base64EncodedString() },
        myName: snapshot.myName,
        olmAccountPickle: nil,  // crypto lives in the sibling blob now
        olmFallbackKey: nil))
    saveCrypto(snapshot)
  }

  /// Re-seals only the crypto blob (account + per-contact session state). Cheap
  /// fast-path for the hot ratchet-advance path, where the bulk conversation
  /// history is unchanged and need not be re-encoded. No-op before `attach`.
  func saveCrypto(_ snapshot: Snapshot) {
    guard let cryptoStore else { return }
    // The session pickle is re-exported here so the sealed ratchet state never
    // lags the live one (a stale pickle would reuse Olm message indices). Secret
    // — only ever written sealed.
    var sessions: [String: PersistedSession] = [:]
    let ids = Set(snapshot.sessions.keys)
      .union(snapshot.pendingInitiation.keys)
      .union(snapshot.lastInitiationIn.keys)
    for id in ids {
      let entry = PersistedSession(
        pickle: try? snapshot.sessions[id]?.exportPickle(),
        pendingInitiation: snapshot.pendingInitiation[id],
        lastInitiationIn: snapshot.lastInitiationIn[id])
      if !entry.isEmpty { sessions[id.base64EncodedString()] = entry }
    }
    var crypto = PersistedCrypto()
    crypto.olmAccountPickle = snapshot.account.flatMap { try? $0.exportOlmPickle() }
    crypto.olmFallbackKey = snapshot.account?.exportFallbackKey()
    crypto.fallbackRotatedAt = snapshot.fallbackRotatedAt?.timeIntervalSince1970
    crypto.sessions = sessions
    cryptoStore.save(crypto)
  }

  // MARK: - Account

  private static func buildAccount(seed: Data, crypto: PersistedCrypto) -> PigeonAccount? {
    if let pickle = crypto.olmAccountPickle, let fallback = crypto.olmFallbackKey,
      let restored = try? PigeonAccount.`import`(
        seed: seed, olmPickle: pickle, fallbackKey: fallback)
    {
      return restored
    }
    return try? PigeonAccount.fromIdentitySeed(seed: seed)
  }

  // MARK: - Codec

  private static func encodeContact(_ contact: Contact) -> PersistedContact {
    PersistedContact(
      name: contact.displayName, bundle: contact.bundle.encoded,
      relayURLs: contact.relayURLs.map(\.absoluteString),
      preferredRelayURL: contact.preferredRelayURL?.absoluteString,
      prekeyBundle: contact.prekeyBundle?.encoded,
      verifiedInPerson: contact.verifiedInPerson)
  }

  private static func decodeContacts(_ persisted: [PersistedContact]) -> [Contact] {
    persisted.compactMap { persisted in
      // Decoding a PigeonIdentityBundle verifies its binding signature; an
      // invalid one yields nil and the contact is dropped.
      guard let bundle = try? PigeonIdentityBundle(decoding: persisted.bundle) else {
        return nil
      }
      // Honour a stored prekey bundle only if it verifies and is bound to this
      // identity (the same guard the QR scanner applies).
      let prekeyBundle = persisted.prekeyBundle
        .flatMap { try? PigeonPrekeyBundle(decoding: $0) }
        .flatMap { $0.identityKey == bundle.identityKey ? $0 : nil }
      return Contact(
        bundle: bundle, displayName: persisted.name,
        relayURLs: persisted.relayURLs.compactMap { URL(string: $0) },
        preferredRelayURL: persisted.preferredRelayURL.flatMap { URL(string: $0) },
        prekeyBundle: prekeyBundle,
        verifiedInPerson: persisted.verifiedInPerson)
    }
  }

  /// Rebuilds the live session state from the persisted crypto blob: the restored
  /// Olm sessions plus the two initiation blobs that drive async establishment,
  /// keyed by contact id. A session whose pickle no longer decodes is simply
  /// skipped (it re-establishes on next contact), never crashing the unlock.
  private static func decodeSessionState(_ persisted: [String: PersistedSession]) -> (
    sessions: [Data: PigeonSession], pending: [Data: Data], lastIn: [Data: Data]
  ) {
    var sessions: [Data: PigeonSession] = [:]
    var pending: [Data: Data] = [:]
    var lastIn: [Data: Data] = [:]
    for (key, entry) in persisted {
      guard let id = Data(base64Encoded: key) else { continue }
      // The contact id is the verified Ed25519 identity key the session was
      // stored under; restoring re-attaches it to the ratchet.
      if let pickle = entry.pickle,
        let session = try? PigeonSession.import(pickle: pickle, remoteIdentityKey: id)
      {
        sessions[id] = session
      }
      if let initiation = entry.pendingInitiation { pending[id] = initiation }
      if let initiation = entry.lastInitiationIn { lastIn[id] = initiation }
    }
    return (sessions, pending, lastIn)
  }

  private static func decodeConversations(_ stored: [String: [ChatMessage]]) -> [Data:
    [ChatMessage]]
  {
    var loaded: [Data: [ChatMessage]] = [:]
    for (key, messages) in stored {
      if let id = Data(base64Encoded: key) { loaded[id] = messages }
    }
    return loaded
  }

  private static func decodeIDs(_ stored: [String]) -> Set<Data> {
    Set(stored.compactMap { Data(base64Encoded: $0) })
  }
}
