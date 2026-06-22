//
//  SessionManager.swift
//  Pigeon
//
//  Orchestrates end-to-end-encrypted messaging with verified contacts over the
//  mesh: one Olm session per contact, async-first establishment routed through
//  SessionEnvelopes, and the binding check that ties a session to a verified
//  identity.
//

import Foundation
import PigeonFFI

/// Owns encrypted sessions with contacts and bridges them to the mesh.
///
/// Role assignment is deterministic so both ends agree without negotiation:
/// the device whose identity key sorts first is the **initiator** (it opens the
/// Olm session against the peer's published prekey), the other is the
/// **responder**. Establishment and pending sends are re-driven by concrete
/// connectivity events (a link coming up — #82), since either device may add the
/// contact (scan the QR) or come online at a different moment.
@MainActor
@Observable
final class SessionManager {

  let identity: IdentityManager
  let mesh: MeshService
  /// The internet relay transport, kept so the UI can configure endpoints and
  /// read link state. `nil` when a mesh was injected (e.g. in tests).
  let relay: RelayTransport?

  var contacts: [Contact] = []
  /// Conversation history and per-message edits (the in-memory view + disk mirror).
  let conversationStore = ConversationStore()
  /// Contacts whose chat is ephemeral — new messages are kept in memory only.
  var ephemeralContactIDs: Set<Data> = []
  /// Contacts whose chat uses Bluetooth instead of the relay. Relay is the
  /// default for every chat; Bluetooth is the opt-in "second option". Mirrored
  /// to the peer (like ephemeral) so both ends of a chat agree on the link, and
  /// persisted so the choice survives relaunch.
  var bluetoothChatIDs: Set<Data> = []
  /// Contacts that have an open conversation (a chat shown on the home list). A
  /// contact lives in the book (`contacts`) whether or not it has one; deleting a
  /// conversation removes the id here while keeping the contact and its session.
  var activeConversationIDs: Set<Data> = []
  /// The local user's own display name, shared in their QR card.
  var myName: String = ""
  var log: [String] = []

  /// Banners, the backgrounded-notification hook, and active-chat bookkeeping.
  let presenter = ChatPresenter()

  // Facade passthroughs so the app/views keep a stable surface over `presenter`.
  typealias InAppBanner = ChatPresenter.InAppBanner
  var banner: InAppBanner? { presenter.banner }
  var isAppActive: Bool { presenter.isAppActive }
  var activeChatID: Data? {
    get { presenter.activeChatID }
    set { presenter.activeChatID = newValue }
  }
  var onIncomingNotification: (() -> Void)? {
    get { presenter.onIncomingNotification }
    set { presenter.onIncomingNotification = newValue }
  }
  func setAppActive(_ active: Bool) { presenter.setAppActive(active) }
  func dismissBanner() { presenter.dismissBanner() }

  /// This device's Olm account (Ed25519 identity + Olm keys), bound to the
  /// long-term identity in `IdentityManager`. Built from the identity seed plus
  /// the persisted Olm pickle in `attachStore` (so it is `nil` until unlock),
  /// and re-sealed to the vault whenever it mutates.
  var account: PigeonAccount?

  /// Per-contact Olm session state (sessions, established set, initiations),
  /// surfaced through the facade in the extension below.
  let sessionRegistry = SessionRegistry()

  /// When the device's signed-prekey (Olm fallback) was last rotated, restored
  /// from and persisted to the crypto store. Drives periodic rotation to bound
  /// the exposure window of the no-one-time-key async-first-contact path.
  var fallbackRotatedAt: Date?
  /// How often the signed prekey is rotated. Olm keeps the previous fallback
  /// valid for one rotation, so a contact's stored QR card stays usable for first
  /// contact for up to two intervals before they need a fresh code.
  static let fallbackRotationInterval: TimeInterval = 7 * 24 * 3600

  /// Envelopes received while locked (we can't decrypt or persist yet), replayed
  /// once unlocked. See `LockedInbox`.
  var lockedInbox = LockedInbox()

  var myID: Data { identity.publicKey.rawRepresentation }

  /// Locked until the vault is unlocked with Face ID / Touch ID.
  private(set) var isUnlocked = false
  /// Owns the encrypted store and the codec between the live state and disk
  /// (including building the bound Olm account). See `SessionPersistence`.
  let persistence = SessionPersistence()

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
      relay.preferredRelayForRecipient = { [weak self] key in
        self?.contacts.first { $0.id == key }?.preferredRelayURL
      }
      // Only ack relay envelopes once unlocked; while locked we buffer and let
      // the relay retain its copy (see `handleInbound`).
      relay.canConsume = { [weak self] in self?.isUnlocked ?? false }
      relay.reconfigure(RelaySettings.urls())
    }
    // Contacts/history load after the vault is unlocked; BLE runs regardless.
    self.mesh.onMessage = { [weak self] data, channel in
      self?.handleInbound(data, channel: channel)
    }
    // Event-driven delivery (#82): a link coming up re-drives establishment and
    // flushes pending sends, replacing the old 3s polling timer.
    self.mesh.onConnectivity = { [weak self] in self?.flushOnConnectivity() }
  }

  /// Attaches the encrypted store after unlock: load persisted state and begin
  /// establishing sessions for known contacts.
  func attachStore(_ store: EncryptedStore) {
    // Decode persisted state and (re)build the bound Olm account off the identity
    // seed. The codec/account logic lives in `SessionPersistence`; here we just
    // apply the result to the live state and run the post-unlock orchestration.
    let loaded = persistence.attach(store, identitySeed: identity.identitySeed)
    account = loaded.account
    contacts = loaded.contacts
    conversationStore.load(loaded.conversations)  // in-memory view starts from disk
    ephemeralContactIDs = loaded.ephemeralContactIDs
    bluetoothChatIDs = loaded.bluetoothChatIDs
    activeConversationIDs = loaded.activeConversationIDs
    myName = loaded.myName
    // Restore established sessions so a relaunch continues the conversation
    // instead of re-handshaking. A contact with a restored session is, by
    // definition, established (the two are kept in lockstep everywhere else).
    sessions = loaded.sessions
    establishedContactIDs = Set(loaded.sessions.keys)
    pendingInitiation = loaded.pendingInitiation
    lastInitiationIn = loaded.lastInitiationIn
    fallbackRotatedAt = loaded.fallbackRotatedAt
    isUnlocked = true
    lockedInbox.reset()
    refreshRelay()  // pick up loaded contacts' relays
    // Drain anything buffered while locked *before* re-driving establishment, so
    // a buffered initiation/rehandshake stands up the session itself and the
    // `ensureEstablishing` pass below then no-ops — rather than both firing and
    // racing into two competing initiations (the relaunch handshake bug).
    // If anything was buffered while locked, re-subscribe our own relays: those
    // envelopes were surfaced but not acked (we couldn't consume them locked),
    // so the relay still holds them — pull them again now that we can ack.
    if drainLockedInbox() { relay?.resubscribeOwnRelays() }
    for contact in contacts { ensureEstablishing(contactID: contact.id) }
    maybeRotateFallbackKey()
  }

  /// Recomputes the relay connection pool (our relays plus every contact's).
  func refreshRelay() {
    relay?.reconfigure(RelaySettings.urls())
  }

  /// Rotates the signed (fallback) prekey if it's older than the rotation
  /// interval, bounding the exposure window of the no-one-time-key first-contact
  /// path (the only prekey path the QR card uses). A fresh account is stamped
  /// without rotating — its fallback is already new. Called on unlock. No key
  /// material is logged. Rotating changes our QR card's advertised prekey; Olm
  /// keeps the previous fallback valid for one rotation so recently shared cards
  /// still work for first contact.
  func maybeRotateFallbackKey() {
    guard let account else { return }
    let now = Date()
    guard let lastRotated = fallbackRotatedAt else {
      fallbackRotatedAt = now  // first launch: stamp the already-fresh fallback
      persist()
      return
    }
    guard now.timeIntervalSince(lastRotated) >= Self.fallbackRotationInterval else { return }
    account.rotateFallbackKey()
    fallbackRotatedAt = now
    note("Rotated signed prekey")
    persist()
  }

  /// Persists and applies the full relay list (endpoints + enabled flags).
  /// Updates the observable `relayURLs` (the *enabled* subset we advertise) so
  /// dependent UI (the QR card) refreshes live.
  func setRelayEntries(_ entries: [RelayEntry]) {
    RelaySettings.setEntries(entries)
    relayURLs = RelaySettings.urls()
    relay?.reconfigure(relayURLs)
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
    guard let ciphertext = try? session.encrypt(plaintext: command) else { return }
    sendEnvelope(.control, payload: ciphertext, to: contact)
  }

  // MARK: - Contacts

  /// Verifies and stores a scanned contact bundle, then begins establishing a
  /// session. `relayURLs` are the contact's advertised relay endpoints from
  /// their QR card (where we deposit ciphertext for them off-Bluetooth).
  /// `prekeyBundle` (from the scanned/pasted card) enables async first contact;
  /// `verifiedInPerson` records whether the safety number was exchanged face to
  /// face (scan) versus a code shared out of band (paste).
  @discardableResult
  func addContact(
    _ bundle: PigeonIdentityBundle, name: String, relayURLs: [URL],
    prekeyBundle: PigeonPrekeyBundle?, verifiedInPerson: Bool
  ) -> Bool {
    // The bundle's binding was already verified when it was decoded; here we only
    // refuse our own identity.
    guard bundle.identityKey != myID else {
      note("That QR is your own identity")
      return false
    }
    // A prekey bundle is honoured only if bound to this same identity.
    let prekeys = prekeyBundle.flatMap { $0.identityKey == bundle.identityKey ? $0 : nil }
    let contact = Contact(
      bundle: bundle, displayName: name, relayURLs: relayURLs,
      prekeyBundle: prekeys, verifiedInPerson: verifiedInPerson)
    if let index = contacts.firstIndex(where: { $0.id == bundle.identityKey }) {
      // Refresh the full bundle (e.g. a rotated static key), not just the name.
      contacts[index] = contact
    } else {
      contacts.append(contact)
    }
    // Adding a contact opens its conversation, so it shows on the home list (the
    // book lets the user re-open it later if the chat is deleted).
    activeConversationIDs.insert(bundle.identityKey)
    persist()
    refreshRelay()  // open a publish connection to the new contact's relays
    note("Added contact \"\(name)\"")
    // Re-scanning forces a fresh handshake (manual recovery if one stalled).
    resetSession(for: bundle.identityKey)
    establishIfNeeded(contactID: bundle.identityKey)
    return true
  }

  func resetSession(for contactID: Data) {
    sessionRegistry.reset(contactID)
  }

  // MARK: - Sending

  /// Sends `text` to `contact`. The message stays *pending* until the peer
  /// acknowledges it; it is sent at once when a session exists and queued
  /// otherwise, then resent on the next connectivity event (#82), so it is never
  /// silently dropped on a disconnect.
  func send(_ text: String, to contact: Contact) {
    send(text, replySnippet: nil, to: contact)
  }

  func send(_ text: String, replySnippet: String?, to contact: Contact) {
    var message = ChatMessage(mine: true, text: text, pending: true)
    message.replySnippet = replySnippet
    message.transport = outboundChannel(for: contact)
    record(message, for: contact.id)
    if establishedContactIDs.contains(contact.id) {
      transmit(message, to: contact)
    } else {
      note("Queued message for \"\(contact.displayName)\" (will send when connected)")
      ensureEstablishing(contactID: contact.id)
    }
  }

  /// Encrypts and sends one app message (id + text) over the session. Re-tags the
  /// message with the link it's going out on now, so a pending message resent
  /// after a transport switch reflects reality in its long-press detail.
  func transmit(_ message: ChatMessage, to contact: Contact) {
    guard let session = sessions[contact.id],
      let payload = Self.encodeMessage(message),
      let ciphertext = try? session.encrypt(plaintext: payload)
    else { return }
    let channel = outboundChannel(for: contact)
    if message.transport != channel {
      setTransport(channel, messageID: message.id, contactID: contact.id)
    }
    sendEnvelope(.message, payload: ciphertext, to: contact)
  }

}

// MARK: - Session-state facade

/// Stable property surface over `sessionRegistry`, so the establishment and
/// messaging code is unchanged by the registry extraction. In an extension so it
/// doesn't count against the coordinator's type-body length.
extension SessionManager {
  var sessions: [Data: PigeonSession] {
    get { sessionRegistry.sessions }
    set { sessionRegistry.sessions = newValue }
  }
  var establishedContactIDs: Set<Data> {
    get { sessionRegistry.established }
    set { sessionRegistry.established = newValue }
  }
  var pendingInitiation: [Data: Data] {
    get { sessionRegistry.pendingInitiation }
    set { sessionRegistry.pendingInitiation = newValue }
  }
  var lastInitiationIn: [Data: Data] {
    get { sessionRegistry.lastInitiationIn }
    set { sessionRegistry.lastInitiationIn = newValue }
  }
}
