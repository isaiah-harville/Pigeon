//
//  SessionManager+Delivery.swift
//  Pigeon
//
//  Delivery plumbing behind the messaging protocol in SessionManager+Messaging:
//  the establishment retry loop, locked-receipt buffering, store-and-forward
//  resend, and the encrypted on-disk persistence mirror.
//

import Foundation
import PigeonFFI

extension SessionManager {

  // MARK: - Connectivity-driven delivery

  /// Re-drives every contact when a link comes up: (re)establish stalled sessions
  /// and flush unacked messages. This is the event-driven replacement for the old
  /// 3s polling timer. It fires only on concrete connectivity events (a peer
  /// connects, a relay authenticates) — not on a clock — so a peer that stays
  /// offline no longer makes us re-encrypt on a cadence and outrun the ratchet's
  /// skip limit. That makes the per-contact resend backoff stopgap unnecessary;
  /// the relay still retains each deposited copy, so a later reconnect delivers.
  func flushOnConnectivity() {
    guard isUnlocked else { return }  // can't decrypt/sign or read contacts yet
    expireStaleDeliveries(now: Date())
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
  /// persist. Called from `attachStore` once the vault is open. Returns whether
  /// anything was buffered, so the caller can re-pull any relay copies we
  /// surfaced-but-didn't-ack while locked (the relay still holds them).
  @discardableResult
  func drainLockedInbox() -> Bool {
    let buffered = lockedInbox.drain()
    for entry in buffered { handleInbound(entry.data, channel: entry.channel) }
    return !buffered.isEmpty
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

  /// Records an outbound message's delivery state in both the in-memory view and
  /// the disk mirror, driving the Sent → Delivered status under the bubble.
  func setDelivery(_ status: DeliveryStatus, messageID: UUID, contactID: Data) {
    conversationStore.setDelivery(status, messageID: messageID, contactID: contactID)
  }

  // MARK: - Delivery confidence window

  /// How long an outbound message may sit *undispatched* before its status drops
  /// to "Not delivered" with a resend affordance. Long enough that establishment +
  /// a first send completes on a healthy link, short enough to surface a genuinely
  /// unreachable peer. Once dispatched (`.sent`) a message never times out — it's
  /// in store-and-forward and only the recipient's ack moves it to `.delivered`.
  static let deliveryConfidenceWindow: TimeInterval = 30

  /// How long we keep auto-resending an unacknowledged outbound message before
  /// retiring it from the local queue to `.expired`. A long-horizon safety
  /// valve, not a deadline: the relay retains deposited copies and every reconnect
  /// retries, so a peer offline for hours or days still receives the message.
  /// Expiry only stops the *local* queue from growing without bound and, after a
  /// week with no ack, surfaces a genuinely-undeliverable message as "Not
  /// delivered" (resend revives it) rather than resending it silently forever.
  /// Relay-side retention is a separate, server-side policy.
  static let deliveryRetentionWindow: TimeInterval = 7 * 24 * 60 * 60

  /// Retires unacknowledged outbound messages past the retention window to
  /// `.expired`, persisting only when something changed. Run at unlock and on every
  /// connectivity flush, so stale queue entries are purged across app restarts.
  func expireStaleDeliveries(now: Date) {
    if conversationStore.expireStale(retention: Self.deliveryRetentionWindow, now: now) {
      persist()
    }
  }

  /// Arms the confidence deadline for a freshly-queued message: after the window,
  /// if it still hasn't reached a transport, mark it failed so the user sees an
  /// honest "Not delivered" and can resend. Self-cancelling — the closure re-reads
  /// the live state, so a message that became `.sent`/`.delivered` meanwhile is
  /// left untouched.
  func armDeliveryDeadline(messageID: UUID, contactID: Data) {
    Task { [weak self] in
      try? await Task.sleep(for: .seconds(Self.deliveryConfidenceWindow))
      self?.conversationStore.failIfStillSending(messageID: messageID, contactID: contactID)
      self?.persist()
    }
  }

  /// After a relaunch, the in-flight deadlines are gone, so reconcile persisted
  /// statuses against the wall clock: an outbound message still `.sending` past
  /// the window is failed now; a newer one gets a fresh deadline. Keeps a message
  /// killed mid-send from showing "Sending…" forever.
  func reconcileDeliveryStatuses(now: Date) {
    let window = Self.deliveryConfidenceWindow
    for contact in contacts {
      for message in conversationStore.pending(for: contact.id) where message.delivery == .sending {
        if message.delivery?.timedOut(age: now.timeIntervalSince(message.date), window: window)
          == true
        {
          setDelivery(.failed, messageID: message.id, contactID: contact.id)
        } else {
          armDeliveryDeadline(messageID: message.id, contactID: contact.id)
        }
      }
    }
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
    // Any recorded message (sent, received, or system) opens the conversation, so
    // it appears on the home list — a deleted chat reappears when a message lands.
    activeConversationIDs.insert(contactID)
    conversationStore.record(
      message, for: contactID, ephemeral: ephemeralContactIDs.contains(contactID))
    persist()
  }

  /// Seals the full live state (bulk + crypto) at rest via `SessionPersistence`.
  /// No-op before unlock; the store handle inside `persistence` is the second
  /// guard once attached.
  func persist() {
    guard isUnlocked else { return }
    persistence.save(snapshot())
  }

  /// Re-seals only the crypto blob (account + per-contact session pickles). The
  /// fast path for a ratchet advance, where conversation history is unchanged —
  /// avoids re-encoding the whole bulk store on every encrypted envelope. The
  /// session pickle must be durable promptly (a stale one reuses Olm message
  /// indices), so this is called on every session-encrypted send.
  func persistCrypto() {
    guard isUnlocked else { return }
    persistence.saveCrypto(snapshot())
  }

  /// Snapshots the live state (contacts, conversation mirror, ephemeral/Bluetooth
  /// flags, Olm account + per-contact session state) for `SessionPersistence` to
  /// seal at rest.
  private func snapshot() -> SessionPersistence.Snapshot {
    SessionPersistence.Snapshot(
      contacts: contacts,
      conversations: conversationStore.persistedConversations,
      ephemeralContactIDs: ephemeralContactIDs,
      bluetoothChatIDs: bluetoothChatIDs,
      activeConversationIDs: activeConversationIDs,
      myName: myName,
      account: account,
      sessions: sessions,
      pendingInitiation: pendingInitiation,
      lastInitiationIn: lastInitiationIn,
      fallbackRotatedAt: fallbackRotatedAt)
  }
}
