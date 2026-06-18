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
  /// Contacts whose chat uses Bluetooth instead of the relay. Relay is the
  /// default for every chat; Bluetooth is the opt-in "second option". Mirrored
  /// to the peer (like ephemeral) so both ends of a chat agree on the link, and
  /// persisted so the choice survives relaunch.
  var bluetoothChatIDs: Set<Data> = []
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
  /// The X3DH initiation header we sent per contact (async first contact),
  /// retained so it can be resent until the peer drains it — analogous to
  /// `pendingMsg1`. Cleared once the peer acks (proof it has the session).
  var pendingX3DHInit: [Data: Data] = [:]
  /// The last X3DH initiation header we processed as responder, to ignore
  /// retransmits (re-running `X3DH.respond` would reset an advanced ratchet);
  /// a *different* header signals a genuine peer restart.
  var lastX3DHIn: [Data: Data] = [:]
  /// The on-disk mirror of conversations (excludes ephemeral-era messages).
  var persistedConversations: [Data: [ChatMessage]] = [:]
  var retryTimer: Timer?
  /// Per-contact backoff gating *retries* of unacked messages. Each retry
  /// re-encrypts (advancing the ratchet), so retrying every tick while a peer is
  /// offline could, over a long outage, outrun the ratchet's skip limit. New
  /// sends and (re)establishment still flush immediately; only timed retries back
  /// off. Cleared when the queue drains or the session is reset.
  var resendGate: [Data: ResendGate] = [:]

  /// Envelopes received while locked (we can't decrypt or persist yet). Held in
  /// memory only — never written to disk — and replayed once unlocked. The relay
  /// also retains its copies (we don't ack while locked), so nothing is lost if
  /// we're killed before unlock. Bounded to blunt flooding.
  var lockedInbox: [(data: Data, channel: TransportChannel)] = []

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
      // Honour a stored prekey bundle only if still valid and bound to this
      // identity (the same guard the QR scanner applies).
      let prekeyBundle = persisted.prekeyBundle
        .flatMap { try? X3DHPrekeyBundle(decoding: $0) }
        .flatMap { $0.isValid() && $0.identity.identityKey == bundle.identityKey ? $0 : nil }
      return Contact(
        bundle: bundle, displayName: persisted.name,
        relayURLs: persisted.relayURLs.compactMap { URL(string: $0) },
        preferredRelayURL: persisted.preferredRelayURL.flatMap { URL(string: $0) },
        prekeyBundle: prekeyBundle,
        verifiedInPerson: persisted.verifiedInPerson)
    }
    var loaded: [Data: [ChatMessage]] = [:]
    for (key, messages) in state.conversations {
      if let id = Data(base64Encoded: key) { loaded[id] = messages }
    }
    persistedConversations = loaded
    conversations = loaded  // start the in-memory view from what's on disk
    ephemeralContactIDs = Set(state.ephemeralContactIDs.compactMap { Data(base64Encoded: $0) })
    bluetoothChatIDs = Set(state.bluetoothContactIDs.compactMap { Data(base64Encoded: $0) })
    myName = state.myName
    isUnlocked = true
    notifiedWhileLocked = false
    refreshRelay()  // pick up loaded contacts' relays
    for contact in contacts { ensureEstablishing(contactID: contact.id) }
    drainLockedInbox()  // process anything that arrived while locked
  }

  /// Recomputes the relay connection pool (our relays plus every contact's).
  func refreshRelay() {
    relay?.reconfigure(RelaySettings.urls())
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
    guard let ciphertext = try? session.encrypt(command) else { return }
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
    _ bundle: IdentityBundle, name: String, relayURLs: [URL],
    prekeyBundle: X3DHPrekeyBundle?, verifiedInPerson: Bool
  ) -> Bool {
    guard bundle.isValid() else {
      note("Rejected contact \"\(name)\": invalid identity binding")
      return false
    }
    guard bundle.identityKey != myID else {
      note("That QR is your own identity")
      return false
    }
    // A prekey bundle is honoured only if bound to this same identity.
    let prekeys = prekeyBundle.flatMap { $0.identity.identityKey == bundle.identityKey ? $0 : nil }
    let contact = Contact(
      bundle: bundle, displayName: name, relayURLs: relayURLs,
      prekeyBundle: prekeys, verifiedInPerson: verifiedInPerson)
    if let index = contacts.firstIndex(where: { $0.id == bundle.identityKey }) {
      // Refresh the full bundle (e.g. a rotated static key), not just the name.
      contacts[index] = contact
    } else {
      contacts.append(contact)
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
    pendingX3DHInit[contactID] = nil
    lastX3DHIn[contactID] = nil
    resendGate[contactID] = nil  // a fresh session should flush pending promptly
    establishedContactIDs.remove(contactID)
  }

  // MARK: - Sending

  /// Sends `text` to `contact`. The message stays *pending* until the peer
  /// acknowledges it; it is (re)sent on each tick while a session exists and
  /// queued otherwise, so it is never silently dropped on a disconnect.
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
      let ciphertext = try? session.encrypt(payload)
    else { return }
    let channel = outboundChannel(for: contact)
    if message.transport != channel {
      setTransport(channel, messageID: message.id, contactID: contact.id)
    }
    sendEnvelope(.message, payload: ciphertext, to: contact)
  }

}
