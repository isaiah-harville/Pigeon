//
//  SessionManager+UI.swift
//  Pigeon
//

import Foundation
import PigeonCrypto
import PigeonMesh

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
  /// relay sockets, then immediately drive handshakes and pending sends instead
  /// of waiting for the retry timer's next tick.
  func refreshChats() async {
    note("Refreshing chats")
    mesh.refreshConnections()
    tick()
    try? await Task.sleep(for: .milliseconds(350))
    tick()
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

  /// Our own shareable identity bundle (for display as a QR code).
  var myBundle: IdentityBundle { identity.identityBundle }

  /// Our shareable card (identity bundle + display name + the relays we can be
  /// reached at) for the QR, so scanners learn where to deposit for us.
  var myCard: ContactCard {
    let relayURLs = RelaySettings.urls()
    let payload = ContactCard.relayPayload(relayURLs)
    let signature = (try? identity.sign(payload)) ?? Data()
    return ContactCard(
      name: myName,
      bundle: identity.identityBundle,
      relayURLs: relayURLs,
      relaySignature: signature,
      prekeyBundle: identity.publishedPrekeyBundle)  // enables async first contact
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

  /// Conversation history with `contact`.
  func messages(with contact: Contact) -> [ChatMessage] {
    conversations[contact.id] ?? []
  }

  /// The most recent non-system message with `contact`, for list previews.
  func lastMessage(with contact: Contact) -> ChatMessage? {
    conversations[contact.id]?.last { !$0.system }
  }

  /// The safety number to compare in person with `contact`.
  func safetyNumber(with contact: Contact) -> String {
    guard let remote = try? IdentityPublicKey(rawRepresentation: contact.bundle.identityKey) else {
      return "—"
    }
    return SafetyNumber.compute(local: identity.publicKey, remote: remote)
  }
}
