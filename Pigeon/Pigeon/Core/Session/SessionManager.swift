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
/// connectivity events (a link coming up), since either device may add the
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
  /// Identities explicitly blocked by the user. These are checked before any
  /// unknown-sender session work and remain available in Settings for undo.
  var blockedContacts: [BlockedContact] = []
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

  /// Throttles re-handshakes that *network* input can trigger, so a spoofed or
  /// replayed `.rehandshakeRequest` (or a flood of undecryptable `.message`
  /// envelopes) can't force endless session resets. User-initiated resets
  /// bypass it. See `RehandshakeGate`.
  var rehandshakeGate = RehandshakeGate(cooldown: RehandshakeGate.defaultCooldown)

  var myID: Data { identity.publicKey.rawRepresentation }

  /// Locked until the vault is unlocked with Face ID / Touch ID.
  private(set) var isUnlocked = false

  func markUnlockedAfterRestore() {
    isUnlocked = true
  }
  /// False after any persistence failure. Processing stays frozen for the rest
  /// of the run so the live ratchet can never advance farther than sealed state.
  var isPersistenceHealthy = true
  /// Whether we've already reported that writes to the encrypted store are
  /// failing, so a run of failures logs once rather than per save.
  var didWarnAboutSaveFailure = false
  /// Owns the encrypted store and the codec between the live state and disk
  /// (including building the bound Olm account). See `SessionPersistence`.
  let persistence: SessionPersistence

  /// Transactional application core. The host supplies signing and encrypted
  /// checkpoint callbacks; pairwise/MLS internals remain behind this API.
  private(set) var coreClient: PigeonCoreClient?
  private var coreIdentityProvider: CoreIdentityProvider?
  private var coreCheckpointStore: CoreCheckpointStore?
  @ObservationIgnored private(set) lazy var groupRelay = makeGroupRelay()
  @ObservationIgnored private(set) lazy var pairwiseRelay = makePairwiseRelay()
  @ObservationIgnored var resolveGroupCoordinatorKey = GroupRelayCoordinatorKey.resolve
  /// Authenticated group projection rebuilt from the Rust checkpoint. It is
  /// never persisted separately, so it cannot drift across a crash boundary.
  var groups: [PigeonGroupState] = []
  var groupConversations: [Data: GroupConversation] = [:]
  var coreSnapshotGeneration: UInt64 = 0
  /// Group relay effects already copied onto the best-effort local mesh during
  /// this process. The relay effect remains pending until the relay confirms it.
  var meshedCoreOutboundIDs: Set<String> = []

  /// Configured relay endpoints, mirrored here so the value is observable —
  /// changing it refreshes anything that depends on it (e.g. the QR card, which
  /// advertises these relays). Persisted via `RelaySettings`.
  var relayURLs: [URL] = RelaySettings.urls()

  convenience init(identity: IdentityManager) {
    self.init(identity: identity, mesh: nil)
  }

  convenience init(identity: IdentityManager, mesh: MeshService?) {
    self.init(identity: identity, mesh: mesh, persistence: SessionPersistence())
  }

  init(
    identity: IdentityManager, mesh: MeshService?, persistence: SessionPersistence
  ) {
    self.identity = identity
    self.persistence = persistence
    if let mesh {
      self.mesh = mesh
      self.relay = nil
    } else {
      let connectivityEnabled = ConnectivitySettings.isEnabled
      // Run the mesh over BLE and an internet relay concurrently. The relay is
      // inert until the user configures an endpoint.
      let mailboxHex = identity.publicKey.rawRepresentation
        .map { String(format: "%02x", $0) }.joined()
      let relay = RelayTransport(
        mailboxHex: mailboxHex, enabled: connectivityEnabled
      ) { [identity] nonce in try? identity.sign(nonce) }
      // Local delivery runs over both BLE and same-network Wi-Fi; the relay
      // reaches peers out of local range. The mesh dedups across all three.
      self.mesh = MeshService(
        transport: CompositeTransport([
          PeerTransport(enabled: connectivityEnabled),
          LocalWiFiTransport(enabled: connectivityEnabled),
          relay,
        ]))
      self.relay = relay
      self.mesh.setConnectivityEnabled(connectivityEnabled)
    }
    // `self` is fully initialized here, so closures may capture it.
    if let relay {
      relay.recipients = { [weak self] in self?.relayEligibleContactIDs ?? [] }
      relay.relaysForRecipient = { [weak self] key in
        self?.relayEligibleContact(key)?.relayURLs ?? []
      }
      relay.preferredRelayForRecipient = { [weak self] key in
        self?.relayEligibleContact(key)?.preferredRelayURL
      }
      relay.onCompatibilityChange = { [weak self] incompatible in
        self?.relayURLs = RelayTransport.advertisedRelays(
          configured: RelaySettings.urls(), excluding: incompatible)
      }
      relay.reconfigure(RelaySettings.urls())
    }
    // Contacts/history load after the vault is unlocked; BLE runs regardless.
    self.mesh.onMessage = { [weak self] data, channel in
      self?.handleInbound(data, channel: channel) ?? .retryAfterRestart
    }
    // Event-driven delivery: a link coming up re-drives establishment and
    // flushes pending sends, replacing the old 3s polling timer.
    self.mesh.onConnectivity = { [weak self] in self?.flushOnConnectivity() }
  }

  /// Attaches the encrypted store after unlock: load persisted state and begin
  /// establishing sessions for known contacts.
  func attachStore(_ store: EncryptedStore) throws {
    // Decode persisted state and (re)build the bound Olm account off the identity
    // seed. The codec/account logic lives in `SessionPersistence`; here we just
    // apply the result to the live state and run the post-unlock orchestration.
    let loaded = try persistence.attach(store, identitySeed: identity.identitySeed)
    let coreIdentityProvider = CoreIdentityProvider(rootIdentity: identity)
    let coreCheckpointStore = CoreCheckpointStore(appStore: store)
    let coreClient = try PigeonCoreClient(
      identity: coreIdentityProvider,
      store: coreCheckpointStore)
    _ = try coreClient.execute(
      PigeonCoreCommand(
        id: "ensure-pairwise-account-v1",
        body: .ensurePairwiseAccount))
    let coreSnapshot = try coreClient.stateSnapshot()
    self.coreIdentityProvider = coreIdentityProvider
    self.coreCheckpointStore = coreCheckpointStore
    self.coreClient = coreClient
    applyCoreSnapshot(coreSnapshot)
    restoreLoadedState(loaded)
    try registerPairwiseContacts()
    guard purgeExpiredIncomingRequests(now: Date()) else {
      throw SessionPersistenceError.unreadableStore
    }
    try absorbCoreEvents(coreSnapshot.pendingEvents)
    let refreshedCoreSnapshot = try coreClient.stateSnapshot()
    groupRelay.reconfigure(snapshot: refreshedCoreSnapshot)
    fanOutGroupMesh(snapshot: refreshedCoreSnapshot)
    if relay != nil { pairwiseRelay.reconfigure(snapshot: refreshedCoreSnapshot) }
    refreshRelay()  // pick up loaded contacts' relays
    // Drain anything buffered while locked *before* re-driving establishment, so
    // a buffered initiation/rehandshake stands up the session itself and the
    // `ensureEstablishing` pass below then no-ops — rather than both firing and
    // racing into two competing initiations (the relaunch handshake bug).
    // If anything was buffered while locked, re-subscribe our own relays: those
    // envelopes were surfaced but not acked (we couldn't consume them locked),
    // so the relay still holds them — pull them again now that we can ack.
    if drainLockedInbox() { relay?.resubscribeOwnRelays() }
    for contact in contacts where contact.requestState != .incoming {
      ensureEstablishing(contactID: contact.id)
    }
    // Purge queue entries that outlived the retention window while the app was
    // closed, then re-arm/settle the deadlines lost to the relaunch so a
    // message killed mid-send doesn't read "Sending…" forever.
    expireStaleDeliveries(now: Date())
    reconcileDeliveryStatuses(now: Date())
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
    note(.signedPrekeyRotated)
    persist()
  }

  // MARK: - Sending

  /// Sends `text` to `contact`. The message stays *pending* until the peer
  /// acknowledges it; it is sent at once when a session exists and queued
  /// otherwise, then resent on the next connectivity event, so it is never
  /// silently dropped on a disconnect.
  func send(_ text: String, to contact: Contact) {
    send(text, replySnippet: nil, to: contact)
  }

  func send(_ text: String, replySnippet: String?, to contact: Contact) {
    guard canSendMessage(to: contact) else { return }
    guard let contactIndex = contacts.firstIndex(where: { $0.id == contact.id }) else { return }
    if contacts[contactIndex].requestState == .outgoing {
      contacts[contactIndex].introductionSent = true
    }
    var message = ChatMessage(mine: true, text: text, pending: true)
    message.replySnippet = replySnippet
    message.transport = outboundChannel(for: contact)
    guard record(message, for: contact.id) else { return }
    // Arm the confidence deadline now: if it can't reach a transport within the
    // window the status drops to "Not delivered" with a resend. A
    // successful transmit below moves it to `.sent`, which the deadline ignores.
    armDeliveryDeadline(messageID: message.id, contactID: contact.id)
    if establishedContactIDs.contains(contact.id) {
      transmit(message, to: contact)
    } else {
      note(.messageQueued)
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
    guard sendEnvelope(.message, payload: ciphertext, to: contact) else { return }
    // Encrypted and handed to the mesh — it's on its way (store-and-forward keeps
    // it moving). Move it to `.sent` unless the peer's ack already made it
    // `.delivered`, so a late resend can't clobber a confirmed delivery.
    if conversationStore.delivery(messageID: message.id, contactID: contact.id) != .delivered {
      setDelivery(.sent, messageID: message.id, contactID: contact.id)
      persist()
    }
  }

}

// MARK: - Session-state facade

/// Stable property surface over `sessionRegistry`, so the establishment and
/// messaging code is unchanged by the registry extraction. In an extension so it
/// doesn't count against the coordinator's type-body length.
extension SessionManager {
  func resetSession(for contactID: Data) {
    sessionRegistry.reset(contactID)
  }

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
  var acceptedInitiationDigests: [Data: Set<Data>] {
    get { sessionRegistry.acceptedInitiationDigests }
    set { sessionRegistry.acceptedInitiationDigests = newValue }
  }
}

// MARK: - Ephemeral chats

/// The ephemeral (don't-persist-new-messages) mode for one chat, mirrored to the
/// peer so both sides go ephemeral together. In an extension so it doesn't count
/// against the coordinator's type-body length.
extension SessionManager {

  /// Whether `contact`'s chat is in ephemeral (don't-persist-new-messages) mode.
  func isEphemeral(_ contact: Contact) -> Bool { ephemeralContactIDs.contains(contact.id) }

  /// Toggles ephemeral mode for one chat. Affects only future messages;
  /// already-saved history is left on disk untouched. The change is mirrored
  /// to the peer so both sides of the chat go ephemeral together.
  func setEphemeral(_ on: Bool, for contact: Contact) {
    guard let current = contacts.first(where: { $0.id == contact.id }),
      current.requestState == .none
    else { return }
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
}
