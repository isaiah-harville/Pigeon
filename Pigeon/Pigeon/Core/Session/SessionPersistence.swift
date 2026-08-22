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

import CryptoKit
import Foundation
import PigeonFFI

enum SessionPersistenceError: Error {
  case unreadableStore
  case invalidCryptoState
}

struct SessionCryptoExporter {
  let exportAccount: (PigeonAccount) throws -> Data
  let exportSession: (PigeonSession) throws -> Data
}

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
  /// Durable intent for a full two-file generation. It exists only while a
  /// recoverable full-state commit still needs to be applied or cleaned up.
  private var transactionStore: EncryptedStore?
  private let cryptoExporter: SessionCryptoExporter

  /// Suffix for the crypto companion blob (appended to the bulk store's name).
  private static let cryptoSuffix = ".crypto"
  private static let transactionSuffix = ".transaction"

  init(cryptoExporter: SessionCryptoExporter) {
    self.cryptoExporter = cryptoExporter
  }

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
    var acceptedInitiationDigests: [Data: Set<Data>]
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
    var acceptedInitiationDigests: [Data: Set<Data>] = [:]
    var fallbackRotatedAt: Date?
  }

  /// Attaches the stores and decodes persisted state, (re)building the Olm account
  /// bound to `identitySeed`. First launch yields a fresh account under the
  /// existing identity; thereafter the persisted pickle is imported so the
  /// published fallback prekey stays stable. Stores written before the crypto/bulk
  /// split are migrated transparently (their crypto fields move to the sibling on
  /// the next save).
  func attach(_ store: EncryptedStore, identitySeed: Data) throws -> Loaded {
    let cryptoStore = store.companion(suffix: Self.cryptoSuffix)
    let transactionStore = store.companion(suffix: Self.transactionSuffix)
    let bulk: PersistedState
    let crypto: PersistedCrypto
    do {
      if let pending = try transactionStore.load(PersistedStateTransaction.self) {
        let bulkRecovered = store.save(pending.bulk)
        let cryptoRecovered = cryptoStore.save(pending.crypto)
        guard bulkRecovered, cryptoRecovered, transactionStore.wipe() else {
          throw SessionPersistenceError.unreadableStore
        }
      }
      bulk = try store.load(PersistedState.self) ?? PersistedState()
      crypto = try cryptoStore.load(PersistedCrypto.self) ?? PersistedCrypto(migratingFrom: bulk)
    } catch {
      throw SessionPersistenceError.unreadableStore
    }
    let sessionState = try Self.decodeSessionState(crypto.sessions)
    let loaded = try Loaded(
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
      acceptedInitiationDigests: sessionState.acceptedDigests,
      fallbackRotatedAt: crypto.fallbackRotatedAt.map { Date(timeIntervalSince1970: $0) })
    self.store = store
    self.cryptoStore = cryptoStore
    self.transactionStore = transactionStore
    return loaded
  }

  // MARK: - Account

  private static func buildAccount(seed: Data, crypto: PersistedCrypto) throws -> PigeonAccount? {
    if let pickle = crypto.olmAccountPickle, let fallback = crypto.olmFallbackKey,
      let restored = try? PigeonAccount.`import`(
        seed: seed, olmPickle: pickle, fallbackKey: fallback)
    {
      return restored
    }
    guard crypto.olmAccountPickle == nil, crypto.olmFallbackKey == nil,
      let account = try? PigeonAccount.fromIdentitySeed(seed: seed)
    else { throw SessionPersistenceError.invalidCryptoState }
    return account
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

  private static func decodeContacts(_ persisted: [PersistedContact]) throws -> [Contact] {
    try persisted.map { persisted in
      // Decoding a PigeonIdentityBundle verifies its binding signature; an
      // invalid one yields nil and the contact is dropped.
      guard let bundle = try? PigeonIdentityBundle(decoding: persisted.bundle) else {
        throw SessionPersistenceError.unreadableStore
      }
      // Honour a stored prekey bundle only if it verifies and is bound to this
      // identity (the same guard the QR scanner applies).
      let prekeyBundle: PigeonPrekeyBundle?
      if let encoded = persisted.prekeyBundle {
        guard let decoded = try? PigeonPrekeyBundle(decoding: encoded),
          decoded.identityKey == bundle.identityKey
        else { throw SessionPersistenceError.unreadableStore }
        prekeyBundle = decoded
      } else {
        prekeyBundle = nil
      }
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
  private static func decodeSessionState(_ persisted: [String: PersistedSession]) throws -> (
    sessions: [Data: PigeonSession], pending: [Data: Data], lastIn: [Data: Data],
    acceptedDigests: [Data: Set<Data>]
  ) {
    var sessions: [Data: PigeonSession] = [:]
    var pending: [Data: Data] = [:]
    var lastIn: [Data: Data] = [:]
    var acceptedDigests: [Data: Set<Data>] = [:]
    for (key, entry) in persisted {
      guard let id = Data(base64Encoded: key) else {
        throw SessionPersistenceError.invalidCryptoState
      }
      // The contact id is the verified Ed25519 identity key the session was
      // stored under; restoring re-attaches it to the ratchet.
      if let pickle = entry.pickle {
        guard let session = try? PigeonSession.import(pickle: pickle, remoteIdentityKey: id) else {
          throw SessionPersistenceError.invalidCryptoState
        }
        sessions[id] = session
      }
      if let initiation = entry.pendingInitiation { pending[id] = initiation }
      if let initiation = entry.lastInitiationIn { lastIn[id] = initiation }
      var digests = Set(entry.acceptedInitiationDigests)
      if let initiation = entry.lastInitiationIn {
        digests.insert(InitiationReplayLedger.digest(initiation))
      }
      if !digests.isEmpty { acceptedDigests[id] = digests }
    }
    return (sessions, pending, lastIn, acceptedDigests)
  }

  private static func decodeConversations(_ stored: [String: [ChatMessage]]) throws -> [Data:
    [ChatMessage]]
  {
    var loaded: [Data: [ChatMessage]] = [:]
    for (key, messages) in stored {
      guard let id = Data(base64Encoded: key) else {
        throw SessionPersistenceError.unreadableStore
      }
      loaded[id] = messages
    }
    return loaded
  }

  private static func decodeIDs(_ stored: [String]) throws -> Set<Data> {
    var ids: Set<Data> = []
    for encoded in stored {
      guard let id = Data(base64Encoded: encoded) else {
        throw SessionPersistenceError.unreadableStore
      }
      ids.insert(id)
    }
    return ids
  }
}

extension SessionPersistence {
  /// Completes a pending Clean Slate before a service graph exists. Store
  /// deletion does not require the old DEK; the random key is never used to
  /// decrypt and exists only because `EncryptedStore` owns its location.
  static func wipeDefaultStoreFamily() -> Bool {
    let store = EncryptedStore(key: SymmetricKey(size: .bits256))
    let cryptoStore = store.companion(suffix: Self.cryptoSuffix)
    let transactionStore = store.companion(suffix: Self.transactionSuffix)
    return wipe(store: store, cryptoStore: cryptoStore, transactionStore: transactionStore)
  }

  /// Irreversibly removes bulk history, cryptographic state, and any pending
  /// transaction journal. Every deletion is attempted even if another fails.
  @discardableResult
  func wipeAll() -> Bool {
    guard let store, let cryptoStore, let transactionStore else { return false }
    let wiped = Self.wipe(
      store: store, cryptoStore: cryptoStore, transactionStore: transactionStore)
    if wiped {
      self.store = nil
      self.cryptoStore = nil
      self.transactionStore = nil
    }
    return wiped
  }

  private static func wipe(
    store: EncryptedStore,
    cryptoStore: EncryptedStore,
    transactionStore: EncryptedStore
  ) -> Bool {
    // Do not short-circuit: every path must be attempted on each recovery pass.
    let bulkWiped = store.wipe()
    let cryptoWiped = cryptoStore.wipe()
    let transactionWiped = transactionStore.wipe()
    return bulkWiped && cryptoWiped && transactionWiped
  }

  /// Writes one recoverable full generation. The journal becomes durable before
  /// either split destination changes and is removed only after both land.
  @discardableResult
  func save(_ snapshot: Snapshot) -> Bool {
    guard let store, let cryptoStore, let transactionStore,
      let crypto = encodeCrypto(snapshot)
    else { return false }
    var conversationsByKey: [String: [ChatMessage]] = [:]
    for (id, messages) in snapshot.conversations {
      conversationsByKey[id.base64EncodedString()] = messages
    }
    let bulk = PersistedState(
      contacts: snapshot.contacts.map(Self.encodeContact),
      conversations: conversationsByKey,
      ephemeralContactIDs: snapshot.ephemeralContactIDs.map { $0.base64EncodedString() },
      bluetoothContactIDs: snapshot.bluetoothChatIDs.map { $0.base64EncodedString() },
      activeConversationIDs: snapshot.activeConversationIDs.map { $0.base64EncodedString() },
      myName: snapshot.myName,
      olmAccountPickle: nil,
      olmFallbackKey: nil)
    guard transactionStore.save(PersistedStateTransaction(bulk: bulk, crypto: crypto)) else {
      return false
    }
    let bulkSaved = store.save(bulk)
    let cryptoSaved = cryptoStore.save(crypto)
    guard bulkSaved, cryptoSaved else { return false }
    return transactionStore.wipe()
  }

  /// Re-seals only the crypto blob after a ratchet advance. Export completes
  /// before the previous generation is replaced.
  @discardableResult
  func saveCrypto(_ snapshot: Snapshot) -> Bool {
    guard transactionIsClear(), let cryptoStore, let crypto = encodeCrypto(snapshot) else {
      return false
    }
    return cryptoStore.save(crypto)
  }

  private func transactionIsClear() -> Bool {
    guard let transactionStore else { return false }
    do {
      return try transactionStore.load(PersistedStateTransaction.self) == nil
    } catch {
      return false
    }
  }

  private func encodeCrypto(_ snapshot: Snapshot) -> PersistedCrypto? {
    do {
      var sessions: [String: PersistedSession] = [:]
      let ids = Set(snapshot.sessions.keys)
        .union(snapshot.pendingInitiation.keys)
        .union(snapshot.lastInitiationIn.keys)
        .union(snapshot.acceptedInitiationDigests.keys)
      for id in ids {
        let pickle = try snapshot.sessions[id].map(cryptoExporter.exportSession)
        let sortedDigests =
          snapshot.acceptedInitiationDigests[id]?.sorted { first, second in
            first.lexicographicallyPrecedes(second)
          } ?? []
        let entry = PersistedSession(
          pickle: pickle,
          pendingInitiation: snapshot.pendingInitiation[id],
          lastInitiationIn: snapshot.lastInitiationIn[id],
          acceptedInitiationDigests: sortedDigests)
        if !entry.isEmpty { sessions[id.base64EncodedString()] = entry }
      }
      var exported = PersistedCrypto()
      if let account = snapshot.account {
        exported.olmAccountPickle = try cryptoExporter.exportAccount(account)
      }
      exported.olmFallbackKey = snapshot.account?.exportFallbackKey()
      exported.fallbackRotatedAt = snapshot.fallbackRotatedAt?.timeIntervalSince1970
      exported.sessions = sessions
      return exported
    } catch {
      return nil
    }
  }

  convenience init() {
    self.init(
      cryptoExporter: SessionCryptoExporter(
        exportAccount: { try $0.exportOlmPickle() },
        exportSession: { try $0.exportPickle() }))
  }

}
