//
//  SessionManager.swift
//  Pigeon
//
//  Orchestrates end-to-end-encrypted messaging with verified contacts over the
//  mesh: one SecureSession per contact, Noise handshakes routed through
//  SessionEnvelopes, and the binding check that ties the handshake to a
//  verified identity.
//

import Foundation
import PigeonCrypto
import PigeonMesh

/// Owns encrypted sessions with contacts and bridges them to the mesh.
///
/// Role assignment is deterministic so both ends agree without negotiation:
/// the device whose identity key sorts first is the Noise **initiator**, the
/// other is the **responder**. A periodic retry re-drives stalled handshakes,
/// since either device may add the contact (scan the QR) at a different moment.
@MainActor
@Observable
final class SessionManager {

  let identity: IdentityManager
  let mesh: MeshService
  /// The internet relay transport, kept so the UI can configure endpoints and
  /// read link state. `nil` when a mesh was injected (e.g. in tests).
  let relay: RelayTransport?

  var contacts: [Contact] = []
  /// Identity ids of contacts with a fully established, verified session.
  var establishedContactIDs: Set<Data> = []
  /// What the UI shows: every message this session, persisted or not.
  var conversations: [Data: [ChatMessage]] = [:]
  /// Contacts whose chat is ephemeral — new messages are kept in memory only.
  var ephemeralContactIDs: Set<Data> = []
  /// The local user's own display name, shared in their QR card.
  var myName: String = ""
  var log: [String] = []

  /// Called to surface a local notification when a message arrives while the
  /// app is backgrounded.
  var onIncomingNotification: (() -> Void)?
  /// A transient in-app banner shown when a message arrives in the foreground
  /// and the user isn't already viewing that chat.
  var banner: InAppBanner?
  /// The chat currently on screen (its notifications are suppressed while active).
  var activeChatID: Data?
  var isAppActive = true
  /// Whether we've already posted the "you have messages, unlock" notification
  /// during the current locked session (reset on unlock).
  var notifiedWhileLocked = false

  func setAppActive(_ active: Bool) { isAppActive = active }
  func dismissBanner() { banner = nil }

  struct InAppBanner: Equatable, Identifiable {
    let id = UUID()
    let title: String
    let body: String
  }

  var sessions: [Data: SecureSession] = [:]
  /// The initiator's first handshake message, kept so retries resend the
  /// *same* message (stable ephemeral) rather than starting over.
  var pendingMsg1: [Data: Data] = [:]
  /// Last handshake message received / sent per contact, for stop-and-wait
  /// retransmission (resend our reply when the peer repeats its message).
  var lastHandshakeIn: [Data: Data] = [:]
  var lastHandshakeOut: [Data: Data] = [:]
  /// The on-disk mirror of conversations (excludes ephemeral-era messages).
  var persistedConversations: [Data: [ChatMessage]] = [:]
  var retryTimer: Timer?

  var myID: Data { identity.publicKey.rawRepresentation }

  /// Locked until the vault is unlocked with Face ID / Touch ID.
  private(set) var isUnlocked = false
  var store: EncryptedStore?

  /// Configured relay endpoints, mirrored here so the value is observable —
  /// changing it refreshes anything that depends on it (e.g. the QR card, which
  /// advertises these relays). Persisted via `RelaySettings`.
  private(set) var relayURLs: [URL] = RelaySettings.urls()

  convenience init(identity: IdentityManager) {
    self.init(identity: identity, mesh: nil)
  }

  init(identity: IdentityManager, mesh: MeshService?) {
    self.identity = identity
    if let mesh {
      self.mesh = mesh
      self.relay = nil
    } else {
      // Run the mesh over BLE and an internet relay concurrently. The relay is
      // inert until the user configures an endpoint.
      let mailboxHex = identity.publicKey.rawRepresentation
        .map { String(format: "%02x", $0) }.joined()
      let relay = RelayTransport(
        mailboxHex: mailboxHex
      ) { [identity] nonce in try? identity.sign(nonce) }
      self.mesh = MeshService(transport: CompositeTransport([PeerTransport(), relay]))
      self.relay = relay
    }
    // `self` is fully initialized here, so closures may capture it.
    if let relay {
      relay.recipients = { [weak self] in self?.contacts.map(\.id) ?? [] }
      relay.relaysForRecipient = { [weak self] key in
        self?.contacts.first { $0.id == key }?.relayURLs ?? []
      }
      relay.reconfigure(RelaySettings.urls())
    }
    // Contacts/history load after the vault is unlocked; BLE runs regardless.
    self.mesh.onMessage = { [weak self] data in self?.handleInbound(data) }
    startRetryLoop()
  }

  /// Attaches the encrypted store after unlock: load persisted state and begin
  /// establishing sessions for known contacts.
  func attachStore(_ store: EncryptedStore) {
    self.store = store
    let state = store.load()
    contacts = state.contacts.compactMap { persisted in
      guard let bundle = try? IdentityBundle(decoding: persisted.bundle), bundle.isValid() else {
        return nil
      }
      return Contact(
        bundle: bundle, displayName: persisted.name,
        relayURLs: persisted.relayURLs.compactMap { URL(string: $0) })
    }
    var loaded: [Data: [ChatMessage]] = [:]
    for (key, messages) in state.conversations {
      if let id = Data(base64Encoded: key) { loaded[id] = messages }
    }
    persistedConversations = loaded
    conversations = loaded  // start the in-memory view from what's on disk
    ephemeralContactIDs = Set(state.ephemeralContactIDs.compactMap { Data(base64Encoded: $0) })
    myName = state.myName
    isUnlocked = true
    notifiedWhileLocked = false
    refreshRelay()  // pick up loaded contacts' relays
    for contact in contacts { ensureEstablishing(contactID: contact.id) }
  }

  /// Recomputes the relay connection pool (our relays plus every contact's).
  func refreshRelay() {
    relay?.reconfigure(RelaySettings.urls())
  }

  /// Persists and applies a new set of our relay endpoints. Updates the
  /// observable `relayURLs` so dependent UI (the QR card) refreshes live.
  func setRelayURLs(_ urls: [URL]) {
    RelaySettings.setURLs(urls)
    relayURLs = urls
    relay?.reconfigure(urls)
  }

  /// Whether `contact`'s chat is in ephemeral (don't-persist-new-messages) mode.
  func isEphemeral(_ contact: Contact) -> Bool { ephemeralContactIDs.contains(contact.id) }

  /// Toggles ephemeral mode for one chat. Affects only future messages;
  /// already-saved history is left on disk untouched. The change is mirrored
  /// to the peer so both sides of the chat go ephemeral together.
  func setEphemeral(_ on: Bool, for contact: Contact) {
    applyEphemeral(on, for: contact.id, announce: true)
    sendEphemeralState(to: contact)
  }

  /// Applies an ephemeral change locally and adds a system notice in the chat.
  func applyEphemeral(_ on: Bool, for contactID: Data, announce: Bool) {
    let changed = ephemeralContactIDs.contains(contactID) != on
    if on { ephemeralContactIDs.insert(contactID) } else { ephemeralContactIDs.remove(contactID) }
    if changed && announce {
      record(
        ChatMessage(
          mine: false, text: on ? "Ephemeral enabled" : "Ephemeral disabled", system: true),
        for: contactID)
    }
    persist()
  }

  /// Sends our current ephemeral state for this chat to the peer (encrypted).
  func sendEphemeralState(to contact: Contact) {
    guard let session = sessions[contact.id], establishedContactIDs.contains(contact.id) else {
      return
    }
    let byte: UInt8 = ephemeralContactIDs.contains(contact.id) ? 1 : 0
    let command = Data([0x01, byte])  // 0x01 = ephemeral cmd
    guard let ciphertext = try? session.encrypt(command) else { return }
    sendEnvelope(.control, payload: ciphertext, to: contact)
  }

  func handleControl(_ payload: Data, from contact: Contact) {
    guard let session = sessions[contact.id],
      let plaintext = try? session.decrypt(payload),
      plaintext.count == 2, plaintext.first == 0x01
    else { return }
    applyEphemeral(
      plaintext[plaintext.index(after: plaintext.startIndex)] == 1,
      for: contact.id, announce: true)
  }

  // MARK: - Contacts

  /// Verifies and stores a scanned contact bundle, then begins establishing a
  /// session. `relayURLs` are the contact's advertised relay endpoints from
  /// their QR card (where we deposit ciphertext for them off-Bluetooth).
  @discardableResult
  func addContact(_ bundle: IdentityBundle, name: String) -> Bool {
    addContact(bundle, name: name, relayURLs: [])
  }

  @discardableResult
  func addContact(_ bundle: IdentityBundle, name: String, relayURLs: [URL]) -> Bool {
    guard bundle.isValid() else {
      note("Rejected contact \"\(name)\": invalid identity binding")
      return false
    }
    guard bundle.identityKey != myID else {
      note("That QR is your own identity")
      return false
    }
    if let index = contacts.firstIndex(where: { $0.id == bundle.identityKey }) {
      // Refresh the full bundle (e.g. a rotated static key), not just the name.
      contacts[index] = Contact(bundle: bundle, displayName: name, relayURLs: relayURLs)
    } else {
      contacts.append(Contact(bundle: bundle, displayName: name, relayURLs: relayURLs))
    }
    persist()
    refreshRelay()  // open a publish connection to the new contact's relays
    note("Added contact \"\(name)\"")
    // Re-scanning forces a fresh handshake (manual recovery if one stalled).
    resetSession(for: bundle.identityKey)
    establishIfNeeded(contactID: bundle.identityKey)
    return true
  }

  func resetSession(for contactID: Data) {
    sessions[contactID] = nil
    pendingMsg1[contactID] = nil
    lastHandshakeIn[contactID] = nil
    lastHandshakeOut[contactID] = nil
    establishedContactIDs.remove(contactID)
  }

  // MARK: - Sending

  /// Sends `text` to `contact`. The message stays *pending* until the peer
  /// acknowledges it; it is (re)sent on each tick while a session exists and
  /// queued otherwise, so it is never silently dropped on a disconnect.
  func send(_ text: String, to contact: Contact) {
    let message = ChatMessage(mine: true, text: text, pending: true)
    record(message, for: contact.id)
    if establishedContactIDs.contains(contact.id) {
      transmit(message, to: contact)
    } else {
      note("Queued message for \"\(contact.displayName)\" (will send when connected)")
      ensureEstablishing(contactID: contact.id)
    }
  }

  /// Encrypts and sends one app message (id + text) over the session.
  func transmit(_ message: ChatMessage, to contact: Contact) {
    guard let session = sessions[contact.id],
      let ciphertext = try? session.encrypt(Self.encodeMessage(id: message.id, text: message.text))
    else { return }
    sendEnvelope(.message, payload: ciphertext, to: contact)
  }

  /// App message wire form (inside the ratchet): UUID string (36 bytes) ‖ text.
  static func encodeMessage(id: UUID, text: String) -> Data {
    Data(id.uuidString.utf8) + Data(text.utf8)
  }

  static func decodeMessage(_ data: Data) -> (id: UUID, text: String)? {
    guard data.count >= 36,
      let idString = String(bytes: data.prefix(36), encoding: .utf8),
      let id = UUID(uuidString: idString),
      let text = String(bytes: data.dropFirst(36), encoding: .utf8)
    else { return nil }
    return (id, text)
  }

  /// Conversation history with `contact`.
  func messages(with contact: Contact) -> [ChatMessage] {
    conversations[contact.id] ?? []
  }

  /// The most recent non-system message with `contact`, for list previews.
  func lastMessage(with contact: Contact) -> ChatMessage? {
    conversations[contact.id]?.last { !$0.system }
  }

}
