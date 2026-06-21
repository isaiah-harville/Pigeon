//
//  SessionPersistence.swift
//  Pigeon
//
//  The persistence/account slice of the session coordinator: owns the encrypted
//  store, builds (or restores) the device's Olm account from the identity seed +
//  persisted pickle, and translates between the live domain objects and the
//  on-disk `PersistedState`. Extracted from SessionManager so the codec and the
//  store handle live in one focused type, leaving the coordinator to own only the
//  orchestration (unlock, establishment, draining the locked inbox).
//
//  This type owns no live state of its own — it reads a `Snapshot` to seal and
//  returns a `Loaded` to apply. The establishment/ratchet logic is untouched: the
//  account it returns is mutated in place by SessionManager's messaging code and
//  handed back here on the next `save`.
//

import Foundation
import PigeonCore

/// Reads and writes the coordinator's durable state through `EncryptedStore`,
/// including building the bound Olm account. Not `@Observable`: persistence is a
/// side effect, not observable UI state.
@MainActor
final class SessionPersistence {

  /// The encrypted store, set at unlock. `nil` (and every `save` a no-op) until
  /// `attach` runs, mirroring the old `guard let store` behaviour.
  private var store: EncryptedStore?

  /// Everything restored from disk at unlock, ready for the coordinator to apply.
  struct Loaded {
    var account: PigeonAccount?
    var contacts: [Contact]
    var conversations: [Data: [ChatMessage]]
    var ephemeralContactIDs: Set<Data>
    var bluetoothChatIDs: Set<Data>
    var myName: String
  }

  /// The live state the coordinator hands over to be sealed at rest.
  struct Snapshot {
    var contacts: [Contact]
    var conversations: [Data: [ChatMessage]]
    var ephemeralContactIDs: Set<Data>
    var bluetoothChatIDs: Set<Data>
    var myName: String
    var account: PigeonAccount?
  }

  /// Attaches the store and decodes persisted state, (re)building the Olm account
  /// bound to `identitySeed`. First launch yields a fresh account under the
  /// existing identity; thereafter the persisted pickle is imported so the
  /// published fallback prekey stays stable.
  func attach(_ store: EncryptedStore, identitySeed: Data) -> Loaded {
    self.store = store
    let state = store.load()
    return Loaded(
      account: Self.buildAccount(seed: identitySeed, state: state),
      contacts: Self.decodeContacts(state.contacts),
      conversations: Self.decodeConversations(state.conversations),
      ephemeralContactIDs: Self.decodeIDs(state.ephemeralContactIDs),
      bluetoothChatIDs: Self.decodeIDs(state.bluetoothContactIDs),
      myName: state.myName)
  }

  /// Writes contacts, the conversation mirror, ephemeral/Bluetooth flags, and the
  /// re-sealed Olm account to the encrypted store (no-op before `attach`).
  func save(_ snapshot: Snapshot) {
    guard let store else { return }
    var conversationsByKey: [String: [ChatMessage]] = [:]
    for (id, messages) in snapshot.conversations {
      conversationsByKey[id.base64EncodedString()] = messages
    }
    // Re-seal the Olm account alongside the rest of the state. Inbound
    // establishment and prekey rotation/replenish mutate the account, so its
    // pickle is exported on every persist; the fallback public key rides along
    // because Olm can't report it again after publishing.
    let olmPickle = snapshot.account.flatMap { try? $0.exportOlmPickle() }
    let olmFallbackKey = snapshot.account?.exportFallbackKey()
    store.save(
      PersistedState(
        contacts: snapshot.contacts.map(Self.encodeContact),
        conversations: conversationsByKey,
        ephemeralContactIDs: snapshot.ephemeralContactIDs.map { $0.base64EncodedString() },
        bluetoothContactIDs: snapshot.bluetoothChatIDs.map { $0.base64EncodedString() },
        myName: snapshot.myName,
        olmAccountPickle: olmPickle,
        olmFallbackKey: olmFallbackKey))
  }

  // MARK: - Account

  private static func buildAccount(seed: Data, state: PersistedState) -> PigeonAccount? {
    if let pickle = state.olmAccountPickle, let fallback = state.olmFallbackKey,
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
