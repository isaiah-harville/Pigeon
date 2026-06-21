//
//  SessionManager+Delivery.swift
//  Pigeon
//
//  Delivery plumbing behind the messaging protocol in SessionManager+Messaging:
//  the establishment retry loop, locked-receipt buffering, store-and-forward
//  resend, and the encrypted on-disk persistence mirror.
//

import Foundation
import PigeonCore
import PigeonMesh

extension SessionManager {

  // MARK: - Connectivity-driven delivery (#82)

  /// Re-drives every contact when a link comes up: (re)establish stalled sessions
  /// and flush unacked messages. This is the event-driven replacement for the old
  /// 3s polling timer. It fires only on concrete connectivity events (a peer
  /// connects, a relay authenticates) — not on a clock — so a peer that stays
  /// offline no longer makes us re-encrypt on a cadence and outrun the ratchet's
  /// skip limit. That makes the per-contact resend backoff stopgap unnecessary;
  /// the relay still retains each deposited copy, so a later reconnect delivers.
  func flushOnConnectivity() {
    guard isUnlocked else { return }  // can't decrypt/sign or read contacts yet
    for contact in contacts {
      if establishedContactIDs.contains(contact.id) {
        sendPending(to: contact)
      } else {
        ensureEstablishing(contactID: contact.id)
      }
    }
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

  /// Buffers an envelope received while locked and prompts the user to unlock.
  /// The notification is content-free and fires once per locked session
  /// (coalesced by `LockedInbox`) so a flood of deposits can't spam notifications.
  func bufferWhileLocked(_ data: Data, channel: TransportChannel) {
    if lockedInbox.buffer(data, channel: channel) { presenter.notifyLocal() }
  }

  /// Replays envelopes buffered while locked, now that we can decrypt and
  /// persist. Called from `attachStore` once the vault is open.
  func drainLockedInbox() {
    for entry in lockedInbox.drain() { handleInbound(entry.data, channel: entry.channel) }
  }

  // MARK: - Store-and-forward

  /// (Re)sends every unacknowledged outbound message for a contact. Pending is
  /// cleared only when the peer ACKs, so a message survives disconnects and
  /// lost packets; duplicates are deduplicated by the recipient.
  func sendPending(to contact: Contact) {
    guard establishedContactIDs.contains(contact.id) else { return }
    // For a session whose initiation isn't yet acknowledged, resend the
    // initiation first so it always precedes the messages, even on reorder/loss.
    if let initiation = pendingInitiation[contact.id] {
      sendEnvelope(.x3dhInit, payload: initiation, to: contact)
    }
    for message in conversationStore.pending(for: contact.id) {
      transmit(message, to: contact)
    }
  }

  /// Flips a message's pending flag in both the in-memory view and the disk mirror.
  func setPending(_ pending: Bool, messageID: UUID, contactID: Data) {
    conversationStore.setPending(pending, messageID: messageID, contactID: contactID)
  }

  /// Records the link a message is being dispatched over, in both the in-memory
  /// view and the disk mirror, so a pending message resent after a transport
  /// switch reflects the link it actually went out on (shown on long-press).
  func setTransport(_ channel: TransportChannel?, messageID: UUID, contactID: Data) {
    conversationStore.setTransport(channel, messageID: messageID, contactID: contactID)
  }

  // MARK: - Logging & persistence

  func note(_ message: String) {
    log.append(message)
    if log.count > 200 { log.removeFirst(log.count - 200) }
  }

  /// Appends a message to the in-memory view, and to the on-disk mirror unless
  /// the chat is ephemeral, then persists.
  func record(_ message: ChatMessage, for contactID: Data) {
    conversationStore.record(
      message, for: contactID, ephemeral: ephemeralContactIDs.contains(contactID))
    persist()
  }

  /// Snapshots the live state (contacts, conversation mirror, ephemeral/Bluetooth
  /// flags, Olm account) and hands it to `SessionPersistence` to seal at rest.
  /// No-op before unlock; the store handle inside `persistence` is the second
  /// guard once attached.
  func persist() {
    guard isUnlocked else { return }
    persistence.save(
      SessionPersistence.Snapshot(
        contacts: contacts,
        conversations: conversationStore.persistedConversations,
        ephemeralContactIDs: ephemeralContactIDs,
        bluetoothChatIDs: bluetoothChatIDs,
        myName: myName,
        account: account))
  }
}
