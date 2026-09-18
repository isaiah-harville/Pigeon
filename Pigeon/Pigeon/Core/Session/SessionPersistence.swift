//
//  SessionPersistence.swift
//  Pigeon
//
//  The app-state persistence slice of the session coordinator. Pairwise and MLS
//  cryptographic state lives exclusively in pigeon-core's checkpoint store.
//
//  The legacy crypto companion is read only as a one-time migration source. The
//  first successful 1.4 save atomically persists promoted contacts and clears it.
//

import CryptoKit
import Foundation
import PigeonFFI

enum SessionPersistenceError: Error {
  case unreadableStore
  case invalidCryptoState
}

/// Reads and writes the coordinator's durable state through `EncryptedStore`,
/// with a compatibility reader for pre-1.4 pairwise state.
@MainActor
// Contact and crypto codecs intentionally remain colocated with their store boundary.
final class SessionPersistence {

  /// The bulk store (contacts + conversations), set at unlock. `nil` (and every
  /// save a no-op) until `attach` runs.
  private var store: EncryptedStore?
  /// The pre-1.4 crypto store, retained only until its opaque account/session
  /// bytes have been imported into pigeon-core and a replacement save succeeds.
  private var cryptoStore: EncryptedStore?
  /// Durable intent for a full two-file generation. It exists only while a
  /// recoverable full-state commit still needs to be applied or cleaned up.
  private var transactionStore: EncryptedStore?

  /// Suffix for the crypto companion blob (appended to the bulk store's name).
  private static let cryptoSuffix = ".crypto"
  private static let transactionSuffix = ".transaction"

  /// Everything restored from disk at unlock, ready for the coordinator to apply.
  struct Loaded {
    var contacts: [Contact]
    var conversations: [Data: [ChatMessage]]
    var groupConversations: [Data: GroupConversation]
    var ephemeralContactIDs: Set<Data>
    var bluetoothChatIDs: Set<Data>
    var activeConversationIDs: Set<Data>
    var blockedContacts: [BlockedContact]
    var myName: String
    var legacyPairwiseMigration: PigeonLegacyPairwiseMigration?
  }

  /// The live state the coordinator hands over to be sealed at rest.
  struct Snapshot {
    var contacts: [Contact]
    var conversations: [Data: [ChatMessage]]
    var groupConversations: [Data: GroupConversation] = [:]
    var ephemeralContactIDs: Set<Data>
    var bluetoothChatIDs: Set<Data>
    var activeConversationIDs: Set<Data> = []
    var blockedContacts: [BlockedContact] = []
    var myName: String
  }

  /// Attaches the stores and decodes app state. Pre-1.4 crypto fields are returned
  /// as one opaque migration payload; Swift never decodes or advances them.
  func attach(_ store: EncryptedStore) throws -> Loaded {
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
    let loaded = try Loaded(
      contacts: Self.decodeContacts(bulk.contacts),
      conversations: Self.decodeConversations(bulk.conversations),
      groupConversations: try Self.decodeGroupConversations(bulk.groupConversations),
      ephemeralContactIDs: Self.decodeIDs(bulk.ephemeralContactIDs),
      bluetoothChatIDs: Self.decodeIDs(bulk.bluetoothContactIDs),
      activeConversationIDs: Self.decodeIDs(bulk.activeConversationIDs),
      blockedContacts: bulk.blockedContacts.map { blocked in
        BlockedContact(id: blocked.id, displayName: blocked.name)
      },
      myName: bulk.myName,
      legacyPairwiseMigration: try Self.legacyPairwiseMigration(crypto))
    self.store = store
    self.cryptoStore = cryptoStore
    self.transactionStore = transactionStore
    return loaded
  }

  // MARK: - Codec

  private static func encodeContact(_ contact: Contact) -> PersistedContact {
    PersistedContact(
      name: contact.displayName, bundle: contact.bundle.encoded,
      relayURLs: contact.relayURLs.map(\.absoluteString),
      preferredRelayURL: contact.preferredRelayURL?.absoluteString,
      prekeyBundle: contact.prekeyBundle?.encoded,
      pairwiseControlPrekeyBundle: contact.pairwiseControlPrekeyBundle?.encoded,
      verifiedInPerson: contact.verifiedInPerson,
      requestState: contact.requestState,
      introductionSent: contact.introductionSent ? 1 : 0,
      introductionReceived: contact.introductionReceived ? 1 : 0,
      requestCreatedAt: contact.requestCreatedAt?.timeIntervalSince1970)
  }

  private static func decodeContacts(_ persisted: [PersistedContact]) throws -> [Contact] {
    // Each contact validates the identity plus two independently signed prekey bundles.
    // swiftlint:disable:next closure_body_length
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
      let pairwiseControlPrekeyBundle: PigeonPrekeyBundle?
      if let encoded = persisted.pairwiseControlPrekeyBundle {
        guard let decoded = try? PigeonPrekeyBundle(decoding: encoded),
          decoded.identityKey == bundle.identityKey
        else { throw SessionPersistenceError.unreadableStore }
        pairwiseControlPrekeyBundle = decoded
      } else {
        pairwiseControlPrekeyBundle = nil
      }
      return Contact(
        bundle: bundle, displayName: persisted.name,
        relayURLs: persisted.relayURLs.compactMap { URL(string: $0) },
        preferredRelayURL: persisted.preferredRelayURL.flatMap { URL(string: $0) },
        prekeyBundle: prekeyBundle,
        pairwiseControlPrekeyBundle: pairwiseControlPrekeyBundle,
        verifiedInPerson: persisted.verifiedInPerson,
        requestState: persisted.requestState ?? .none,
        introductionSent: persisted.introductionSent == 1,
        introductionReceived: persisted.introductionReceived == 1,
        requestCreatedAt: persisted.requestCreatedAt.map(Date.init(timeIntervalSince1970:)))
    }
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

  private static func decodeGroupConversations(
    _ stored: [String: GroupConversation]
  ) throws -> [Data: GroupConversation] {
    var loaded: [Data: GroupConversation] = [:]
    for (key, conversation) in stored {
      guard let id = Data(base64Encoded: key), id == conversation.id else {
        throw SessionPersistenceError.unreadableStore
      }
      loaded[id] = conversation
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
    let coreStore = store.companion(suffix: CoreCheckpointStore.companionSuffix)
    return wipe(
      store: store,
      cryptoStore: cryptoStore,
      transactionStore: transactionStore,
      coreStore: coreStore)
  }

  /// Irreversibly removes bulk history, cryptographic state, and any pending
  /// transaction journal. Every deletion is attempted even if another fails.
  @discardableResult
  func wipeAll() -> Bool {
    guard let store, let cryptoStore, let transactionStore else { return false }
    let wiped = Self.wipe(
      store: store,
      cryptoStore: cryptoStore,
      transactionStore: transactionStore,
      coreStore: store.companion(suffix: CoreCheckpointStore.companionSuffix))
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
    transactionStore: EncryptedStore,
    coreStore: EncryptedStore
  ) -> Bool {
    // Do not short-circuit: every path must be attempted on each recovery pass.
    let bulkWiped = store.wipe()
    let cryptoWiped = cryptoStore.wipe()
    let transactionWiped = transactionStore.wipe()
    let coreWiped = coreStore.wipe()
    return bulkWiped && cryptoWiped && transactionWiped && coreWiped
  }

  /// Writes one recoverable full generation. The journal becomes durable before
  /// either split destination changes and is removed only after both land.
  @discardableResult
  func save(_ snapshot: Snapshot) -> Bool {
    guard let store, let cryptoStore, let transactionStore,
      transactionIsClear()
    else { return false }
    let crypto = PersistedCrypto()
    var conversationsByKey: [String: [ChatMessage]] = [:]
    for (id, messages) in snapshot.conversations {
      conversationsByKey[id.base64EncodedString()] = messages
    }
    var groupConversationsByKey: [String: GroupConversation] = [:]
    for (id, conversation) in snapshot.groupConversations {
      guard id == conversation.id else { return false }
      groupConversationsByKey[id.base64EncodedString()] = conversation
    }
    let bulk = PersistedState(
      contacts: snapshot.contacts.map(Self.encodeContact),
      conversations: conversationsByKey,
      groupConversations: groupConversationsByKey,
      ephemeralContactIDs: snapshot.ephemeralContactIDs.map { $0.base64EncodedString() },
      bluetoothContactIDs: snapshot.bluetoothChatIDs.map { $0.base64EncodedString() },
      activeConversationIDs: snapshot.activeConversationIDs.map { $0.base64EncodedString() },
      blockedContacts: snapshot.blockedContacts.map { blocked in
        PersistedBlockedContact(id: blocked.id, name: blocked.displayName)
      },
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

  private func transactionIsClear() -> Bool {
    guard let transactionStore else { return false }
    do {
      return try transactionStore.load(PersistedStateTransaction.self) == nil
    } catch {
      return false
    }
  }

}
