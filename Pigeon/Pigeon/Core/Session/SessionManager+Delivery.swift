//
//  SessionManager+Delivery.swift
//  Pigeon
//
//  Delivery plumbing behind the messaging protocol in SessionManager+Messaging:
//  the establishment retry loop, locked-receipt buffering, store-and-forward
//  resend, and the encrypted on-disk persistence mirror.
//

import Foundation
import PigeonCrypto
import PigeonMesh

extension SessionManager {

  // MARK: - Retry

  func startRetryLoop() {
    retryTimer = Timer.scheduledTimer(withTimeInterval: 3.0, repeats: true) { [weak self] _ in
      guard let self else { return }
      Task { @MainActor in self.tick() }
    }
  }

  func tick() {
    let now = Date()
    for contact in contacts {
      if establishedContactIDs.contains(contact.id) {
        resendPendingIfDue(to: contact, now: now)
      } else {
        ensureEstablishing(contactID: contact.id)
      }
    }
  }

  /// Retries unacked messages to one contact on a per-contact exponential
  /// backoff. New sends and (re)establishment flush immediately by calling
  /// `sendPending` directly; only these timed retries back off, so a peer that
  /// stays offline for a long time doesn't make us re-encrypt every 3s (which
  /// advances the ratchet and could outrun its skip limit). The relay retains
  /// each deposited copy, so backing off the resend never costs delivery.
  private func resendPendingIfDue(to contact: Contact, now: Date) {
    let hasPending = conversations[contact.id]?.contains { $0.mine && $0.pending } ?? false
    guard hasPending else {
      resendGate[contact.id] = nil  // queue drained; the next message sends at once
      return
    }
    if let gate = resendGate[contact.id], now < gate.nextAttempt { return }
    sendPending(to: contact)
    let step = (resendGate[contact.id]?.step ?? 0) + 1
    resendGate[contact.id] = ResendGate(
      nextAttempt: now.addingTimeInterval(Self.resendBackoff(step: step)), step: step)
  }

  /// Exponential backoff (seconds) for the Nth consecutive retry, capped so a
  /// reconnect is still noticed within a bounded delay: 3, 6, 12, 24, 45, 45…
  static func resendBackoff(step: Int) -> TimeInterval {
    let factor = Double(1 << min(max(step - 1, 0), 8))
    return min(3 * factor, 45)
  }

  /// Per-contact retry backoff state (see `resendGate`).
  struct ResendGate {
    var nextAttempt: Date
    var step: Int
  }

  /// Drives (re)establishment for one contact according to our role: the
  /// initiator (re)sends msg1; the responder nudges the initiator to start.
  func ensureEstablishing(contactID: Data) {
    guard !establishedContactIDs.contains(contactID) else { return }
    if isInitiator(toward: contactID) {
      establishIfNeeded(contactID: contactID)
    } else if let contact = contacts.first(where: { $0.id == contactID }) {
      sendEnvelope(.rehandshakeRequest, payload: Data(), to: contact)
    }
  }

  // MARK: - Locked receipt

  /// Upper bound on envelopes buffered while locked (memory only).
  private static let maxLockedInbox = 256

  /// Buffers an envelope received while locked and prompts the user to unlock.
  /// The notification is content-free and fires once per locked session
  /// (coalesced) so a flood of deposits can't spam notifications.
  func bufferWhileLocked(_ data: Data, channel: TransportChannel) {
    lockedInbox.append((data, channel))
    if lockedInbox.count > Self.maxLockedInbox {
      lockedInbox.removeFirst(lockedInbox.count - Self.maxLockedInbox)
    }
    if !notifiedWhileLocked {
      notifiedWhileLocked = true
      onIncomingNotification?()
    }
  }

  /// Replays envelopes buffered while locked, now that we can decrypt and
  /// persist. Called from `attachStore` once the vault is open.
  func drainLockedInbox() {
    guard !lockedInbox.isEmpty else { return }
    let buffered = lockedInbox
    lockedInbox.removeAll()
    for (data, channel) in buffered { handleInbound(data, channel: channel) }
  }

  // MARK: - Store-and-forward

  /// (Re)sends every unacknowledged outbound message for a contact. Pending is
  /// cleared only when the peer ACKs, so a message survives disconnects and
  /// lost packets; duplicates are deduplicated by the recipient.
  func sendPending(to contact: Contact) {
    guard establishedContactIDs.contains(contact.id) else { return }
    // For an X3DH-initiated session not yet acknowledged, resend the initiation
    // header first so it always precedes the messages, even on reorder/loss.
    if let header = pendingX3DHInit[contact.id] {
      sendEnvelope(.x3dhInit, payload: header, to: contact)
    }
    let pending = (conversations[contact.id] ?? []).filter { $0.mine && $0.pending }
    for message in pending {
      transmit(message, to: contact)
    }
  }

  /// Flips a message's pending flag in both the in-memory view and the disk mirror.
  func setPending(_ pending: Bool, messageID: UUID, contactID: Data) {
    if let index = conversations[contactID]?.firstIndex(where: { $0.id == messageID }) {
      conversations[contactID]?[index].pending = pending
    }
    if let index = persistedConversations[contactID]?.firstIndex(where: { $0.id == messageID }) {
      persistedConversations[contactID]?[index].pending = pending
    }
  }

  /// Records the link a message is being dispatched over, in both the in-memory
  /// view and the disk mirror, so a pending message resent after a transport
  /// switch reflects the link it actually went out on (shown on long-press).
  func setTransport(_ channel: TransportChannel?, messageID: UUID, contactID: Data) {
    if let index = conversations[contactID]?.firstIndex(where: { $0.id == messageID }) {
      conversations[contactID]?[index].transport = channel
    }
    if let index = persistedConversations[contactID]?.firstIndex(where: { $0.id == messageID }) {
      persistedConversations[contactID]?[index].transport = channel
    }
  }

  // MARK: - Logging & persistence

  func note(_ message: String) {
    log.append(message)
    if log.count > 200 { log.removeFirst(log.count - 200) }
  }

  /// Appends a message to the in-memory view, and to the on-disk mirror unless
  /// the chat is ephemeral, then persists.
  func record(_ message: ChatMessage, for contactID: Data) {
    conversations[contactID, default: []].append(message)
    if !ephemeralContactIDs.contains(contactID) {
      persistedConversations[contactID, default: []].append(message)
    }
    persist()
  }

  /// Writes contacts, the on-disk conversation mirror, and ephemeral flags to
  /// the encrypted store (no-op before unlock).
  func persist() {
    guard let store, isUnlocked else { return }
    let persistedContacts = contacts.map { contact in
      PersistedContact(
        name: contact.displayName, bundle: contact.bundle.encoded(),
        relayURLs: contact.relayURLs.map(\.absoluteString),
        preferredRelayURL: contact.preferredRelayURL?.absoluteString,
        prekeyBundle: contact.prekeyBundle?.encoded(),
        verifiedInPerson: contact.verifiedInPerson)
    }
    var conversationsByKey: [String: [ChatMessage]] = [:]
    for (id, messages) in persistedConversations {
      conversationsByKey[id.base64EncodedString()] = messages
    }
    store.save(
      PersistedState(
        contacts: persistedContacts,
        conversations: conversationsByKey,
        ephemeralContactIDs: ephemeralContactIDs.map { $0.base64EncodedString() },
        bluetoothContactIDs: bluetoothChatIDs.map { $0.base64EncodedString() },
        myName: myName))
  }
}
