//
//  SessionManager+UI.swift
//  Pigeon
//

import Foundation
import PigeonFFI

extension SessionManager {

  // MARK: - UI passthroughs

  var status: TransportStatus { mesh.status }
  var connectedPeerCount: Int { mesh.connectedPeerCount }
  var meshLog: [String] { mesh.log }

  /// Relay (internet) link state for the UI; `.disabled` when none configured.
  var relayLinkState: RelayTransport.LinkState { relay?.linkState ?? .disabled }

  /// Hosts of our own relays we can currently receive on, for the chat header.
  var relayHosts: [String] { relay?.onlineRelayHosts ?? [] }

  /// Pull-to-refresh recovery for the chats screen: restart link discovery /
  /// relay sockets, then immediately drive handshakes and pending sends. The
  /// reconnect itself fires a connectivity event, but we also flush directly so
  /// the refresh acts even when no link state actually changed.
  func refreshChats() async {
    note("Refreshing chats")
    mesh.refreshConnections()
    flushOnConnectivity()
    try? await Task.sleep(for: .milliseconds(350))
    flushOnConnectivity()
  }

  /// Whether a relay is configured at all, so the UI can offer the relay option.
  var hasRelay: Bool { relayLinkState != .disabled }

  /// Whether `contact`'s chat sends over Bluetooth. Relay is the default for
  /// every chat (we encourage relays); Bluetooth is the opt-in second option.
  /// A chat falls back to Bluetooth when no relay is configured at all (#24).
  func usesBluetooth(_ contact: Contact) -> Bool {
    bluetoothChatIDs.contains(contact.id) || !hasRelay
  }

  /// The links an outbound app message to `contact` is dispatched over: just the
  /// chat's chosen link (relay by default, Bluetooth when opted in or when no
  /// relay is configured) — #24.
  func chatChannels(for contact: Contact) -> Set<TransportKind> {
    usesBluetooth(contact) ? [.bluetooth] : [.relay]
  }

  /// Live reachability of the link this chat is set to use, so the header can
  /// show whether a message can go out *right now* over the chosen transport
  /// (not just whether a session was ever established). A Bluetooth chat is
  /// reachable when a peer is connected; a relay chat when we hold a ready
  /// connection to one of the *contact's* advertised relays (the mailbox we'd
  /// deposit to) — not merely when one of our own relays is online, which says
  /// nothing about whether the recipient can be reached. Reads observable
  /// transport state, so it refreshes as links come and go.
  func chosenLinkReachable(for contact: Contact) -> Bool {
    if usesBluetooth(contact) { return connectedPeerCount > 0 }
    return relay?.canReach(recipientRelays: advertisedRelays(for: contact)) ?? false
  }

  /// The relay host this chat will use: its chosen relay if set, otherwise
  /// the first online relay, otherwise the first configured one. For the switch
  /// notice and the long-press message detail.
  func relayHost(for contactID: Data) -> String? {
    if let preferred = contacts.first(where: { $0.id == contactID })?.preferredRelayURL?.host {
      return preferred
    }
    return relayHosts.first ?? RelaySettings.urls().first?.host
  }

  /// The link to record on an outbound message, shown in its long-press detail.
  func outboundChannel(for contact: Contact) -> TransportChannel? {
    if usesBluetooth(contact) { return .bluetooth }
    return relayHost(for: contact.id).map { .relay(host: $0) }
  }

  /// The full configured relay list (endpoints + enabled flags) for the settings UI.
  var relayEntries: [RelayEntry] { RelaySettings.entries() }

  /// Whether APNs push wake-ups are enabled (on by default; the user can opt out).
  var pushEnabled: Bool { RelaySettings.pushEnabled }

  /// Opts into or out of push wake-ups: persists the choice and starts or stops
  /// APNs registration. Opting out clears the device token from our relays (the
  /// relay setter sees a nil token); opting in registers it once a token arrives.
  func setPushEnabled(_ enabled: Bool) {
    RelaySettings.pushEnabled = enabled
    #if os(iOS)
      if enabled {
        RemoteNotificationManager.shared.enable()
      } else {
        RemoteNotificationManager.shared.disable()
      }
    #endif
  }

  /// Whether Pigeon may receive messages while the device is locked. On by
  /// default; backed by the identity keys' keychain accessibility.
  var backgroundDeliveryEnabled: Bool { BackgroundDelivery.isEnabled }

  /// Applies a new background-delivery preference: rewrites the identity keys'
  /// keychain accessibility (must be unlocked) and persists the choice. Returns
  /// `false` and leaves the preference unchanged if the keychain update fails.
  @discardableResult
  func setBackgroundDeliveryEnabled(_ enabled: Bool) -> Bool {
    let accessibility: KeychainAccessibility = enabled ? .afterFirstUnlock : .whenUnlocked
    do {
      try identity.applyKeychainAccessibility(accessibility)
      BackgroundDelivery.isEnabled = enabled
      return true
    } catch {
      note("Couldn't update background-delivery setting")
      return false
    }
  }

  /// Our shareable card (identity bundle + display name + the relays we can be
  /// reached at) for the QR, so scanners learn where to deposit for us. The
  /// identity bundle and signed prekey come from the Olm `account`, which owns
  /// the Curve25519 identity key the binding signs; `nil` before unlock (the
  /// account isn't built yet, and the QR is only shown unlocked anyway).
  var myCard: ContactCard? {
    guard let account,
      let bundle = try? PigeonIdentityBundle(decoding: account.identityBundle()),
      let prekeyBundle = try? PigeonPrekeyBundle(decoding: account.signedPrekeyBundle())
    else { return nil }
    let relayURLs = RelaySettings.urls()
    let payload = ContactCard.relayPayload(relayURLs)
    let signature = (try? identity.sign(payload)) ?? Data()
    return ContactCard(
      name: myName,
      bundle: bundle,
      relayURLs: relayURLs,
      relaySignature: signature,
      prekeyBundle: prekeyBundle)  // enables async first contact
  }

  /// Whether `contact` was verified in person (QR scanned face to face) rather
  /// than added from a pasted code. Reads live state so the UI updates when the
  /// user marks the contact verified (§5.7 trust UX).
  func isVerifiedInPerson(_ contact: Contact) -> Bool {
    contacts.first { $0.id == contact.id }?.verifiedInPerson ?? contact.verifiedInPerson
  }

  /// Records that the user compared the safety number out of band and trusts
  /// this contact, clearing the "not verified in person" cue. Deliberate and
  /// user-initiated — we never flip trust silently.
  func markVerifiedInPerson(_ contact: Contact) {
    guard let index = contacts.firstIndex(where: { $0.id == contact.id }) else { return }
    contacts[index].verifiedInPerson = true
    persist()
  }

  var myFingerprint: String { identity.publicKey.fingerprint }

  /// Sets the local user's own display name (shared in their QR card).
  func setMyName(_ name: String) {
    myName = name.trimmingCharacters(in: .whitespacesAndNewlines)
    persist()
  }

  /// Renames a contact locally (does not affect their card).
  func renameContact(_ contact: Contact, to name: String) {
    guard let index = contacts.firstIndex(where: { $0.id == contact.id }) else { return }
    contacts[index].displayName = name.trimmingCharacters(in: .whitespacesAndNewlines)
    persist()
  }

  /// The relay preferred for this conversation (`nil` = automatic), and the
  /// contact's advertised relays the picker chooses from (#18).
  func preferredRelay(for contact: Contact) -> URL? {
    contacts.first { $0.id == contact.id }?.preferredRelayURL
  }

  func advertisedRelays(for contact: Contact) -> [URL] {
    contacts.first { $0.id == contact.id }?.relayURLs ?? []
  }

  /// Pins this conversation to a chosen relay (or `nil` for automatic) and
  /// reconnects so a connection to the chosen relay is open (#18).
  func setPreferredRelay(_ url: URL?, for contact: Contact) {
    guard let index = contacts.firstIndex(where: { $0.id == contact.id }) else { return }
    contacts[index].preferredRelayURL = url
    persist()
    refreshRelay()
  }

  /// Manually re-drives delivery to `contact`: (re)establish if needed and
  /// resend every unacked message now, for when the user doesn't want to wait
  /// for the next connectivity event (#82). Same work `flushOnConnectivity` does
  /// per link-up, scoped to one chat and triggered from the pending-message
  /// retry affordance.
  func retryDelivery(to contact: Contact) {
    if establishedContactIDs.contains(contact.id) {
      sendPending(to: contact)
    } else {
      ensureEstablishing(contactID: contact.id)
    }
    note("Manual retry for \"\(contact.displayName)\"")
  }

  // MARK: - Contacts book vs. conversations

  /// The contacts with an open conversation, for the home (chats) list — sorted
  /// most-recent first, with chats that have no message yet (just started or
  /// freshly added) floated to the top. The full book is `contacts`.
  var chatContacts: [Contact] {
    contacts
      .filter { activeConversationIDs.contains($0.id) }
      .sorted { lhs, rhs in
        let lhsDate = lastMessage(with: lhs)?.date ?? .distantFuture
        let rhsDate = lastMessage(with: rhs)?.date ?? .distantFuture
        return lhsDate > rhsDate
      }
  }

  /// Whether `contact` currently has an open conversation (shows on the home list).
  func hasConversation(_ contact: Contact) -> Bool {
    activeConversationIDs.contains(contact.id)
  }

  /// Opens (or re-opens) the conversation with `contact` so it shows on the home
  /// list, without touching its history. Used when starting a chat from the book.
  func startConversation(with contact: Contact) {
    guard !activeConversationIDs.contains(contact.id) else { return }
    activeConversationIDs.insert(contact.id)
    persist()
  }

  /// Deletes the conversation with `contact`: clears its message history (memory +
  /// disk mirror) and removes it from the home list. The contact stays in the
  /// book and its Olm session is untouched, so re-opening the chat continues
  /// without a re-handshake or re-scan. Per-chat transport/ephemeral preferences
  /// belong to the contact's session, so they are deliberately left intact.
  func deleteConversation(with contact: Contact) {
    conversationStore.clear(contactID: contact.id)
    activeConversationIDs.remove(contact.id)
    persist()
  }

  /// Fully forgets a contact: clears its conversation, drops it from the book, and
  /// resets its Olm session. Reaching this contact again requires re-scanning
  /// their QR (the deliberate, documented reset path). The opposite of
  /// `deleteConversation`, which keeps the contact.
  func removeContact(_ contact: Contact) {
    conversationStore.clear(contactID: contact.id)
    activeConversationIDs.remove(contact.id)
    contacts.removeAll { $0.id == contact.id }
    resetSession(for: contact.id)
    persist()
    refreshRelay()
  }

  /// Conversation history with `contact`.
  func messages(with contact: Contact) -> [ChatMessage] {
    conversationStore.messages(for: contact.id)
  }

  /// The most recent non-system message with `contact`, for list previews.
  func lastMessage(with contact: Contact) -> ChatMessage? {
    conversationStore.lastNonSystem(for: contact.id)
  }

  /// The safety number to compare in person with `contact`.
  func safetyNumber(with contact: Contact) -> String {
    guard let remote = try? IdentityPublicKey(rawRepresentation: contact.bundle.identityKey) else {
      return "—"
    }
    return SafetyNumber.compute(local: identity.publicKey, remote: remote)
  }
}
