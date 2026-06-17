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

  /// The link an outbound message would currently travel over: local Bluetooth
  /// when peers are connected, otherwise the relay when it is online. `nil` when
  /// neither is available (the message is queued until a link comes up).
  var currentOutboundChannel: TransportChannel? {
    if connectedPeerCount > 0 { return .bluetooth }
    if let host = relayHosts.first { return .relay(host: host) }
    return nil
  }

  /// The link an outbound message to `contact` would travel over, honoring a
  /// relay-only switch for that chat (#24).
  func outboundChannel(for contact: Contact) -> TransportChannel? {
    if relayOnlyContactIDs.contains(contact.id) {
      return relayHosts.first.map { .relay(host: $0) }
    }
    return currentOutboundChannel
  }

  /// Whether this chat is pinned to the relay (Bluetooth skipped) — #24.
  func isRelayOnly(_ contact: Contact) -> Bool { relayOnlyContactIDs.contains(contact.id) }

  /// Whether a relay is configured at all, so the UI can hide the relay-only
  /// switch when there's nothing to switch to.
  var hasRelay: Bool { relayLinkState != .disabled }

  /// Pins/unpins a chat to the relay. Affects only how future messages for this
  /// contact are dispatched; nothing already sent changes.
  func setRelayOnly(_ on: Bool, for contact: Contact) {
    if on { relayOnlyContactIDs.insert(contact.id) } else { relayOnlyContactIDs.remove(contact.id) }
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
      relaySignature: signature)
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

  /// The safety number to compare in person with `contact`.
  func safetyNumber(with contact: Contact) -> String {
    guard let remote = try? IdentityPublicKey(rawRepresentation: contact.bundle.identityKey) else {
      return "—"
    }
    return SafetyNumber.compute(local: identity.publicKey, remote: remote)
  }
}
