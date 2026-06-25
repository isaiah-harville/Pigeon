//
//  ConversationStore.swift
//  Pigeon
//
//  The message-data slice of the session coordinator: the in-memory view of
//  every conversation plus the on-disk mirror (which excludes ephemeral-era
//  messages), and the per-message edits — pending flags, the link a message went
//  out on, and reactions. Extracted from SessionManager so message bookkeeping
//  lives in one focused, observable type. It owns data only: the owner decides
//  ephemerality and drives persistence to the encrypted store.
//

import Foundation

/// Owns conversation history and the per-message mutations the UI observes.
/// `@Observable` so chat views refresh as messages land and change state.
@MainActor
@Observable
final class ConversationStore {

  /// What the UI shows: every message this session, persisted or not.
  private(set) var conversations: [Data: [ChatMessage]] = [:]
  /// The on-disk mirror (excludes ephemeral-era messages); the owner persists it.
  private(set) var persistedConversations: [Data: [ChatMessage]] = [:]

  /// Restores both views from data loaded off disk at unlock.
  func load(_ loaded: [Data: [ChatMessage]]) {
    conversations = loaded
    persistedConversations = loaded
  }

  // MARK: - Reads

  func messages(for contactID: Data) -> [ChatMessage] { conversations[contactID] ?? [] }

  func lastNonSystem(for contactID: Data) -> ChatMessage? {
    conversations[contactID]?.last { !$0.system }
  }

  func contains(messageID: UUID, for contactID: Data) -> Bool {
    conversations[contactID]?.contains { $0.id == messageID } ?? false
  }

  /// Our own still-unacknowledged messages to a contact, for store-and-forward.
  func pending(for contactID: Data) -> [ChatMessage] {
    (conversations[contactID] ?? []).filter { $0.mine && $0.pending }
  }

  func personalReaction(messageID: UUID, for contactID: Data) -> String? {
    conversations[contactID]?.first { $0.id == messageID }?.personalReaction
  }

  // MARK: - Writes

  /// Appends to the in-memory view, and to the on-disk mirror unless the chat is
  /// ephemeral (the owner supplies that, since it owns the ephemeral set).
  func record(_ message: ChatMessage, for contactID: Data, ephemeral: Bool) {
    conversations[contactID, default: []].append(message)
    if !ephemeral { persistedConversations[contactID, default: []].append(message) }
  }

  /// Drops a contact's entire message history from both the in-memory view and
  /// the on-disk mirror. Used when deleting a conversation; the contact and its
  /// session are kept by the owner.
  func clear(contactID: Data) {
    conversations[contactID] = nil
    persistedConversations[contactID] = nil
  }

  /// Sets an outbound message's delivery state in both the in-memory view and the
  /// disk mirror, so the Sent → Delivered status survives relaunch.
  func setDelivery(_ status: DeliveryStatus, messageID: UUID, contactID: Data) {
    mutate(messageID: messageID, contactID: contactID) { $0.delivery = status }
  }

  /// Flips an *undispatched* message to `.failed` (a no-op once it has reached
  /// `.sent`/`.delivered`), so a confidence-window deadline can only fail a
  /// message we never got onto a transport — never one already on its way.
  func failIfStillSending(messageID: UUID, contactID: Data) {
    mutate(messageID: messageID, contactID: contactID) { message in
      if message.delivery == .sending { message.delivery = .failed }
    }
  }

  /// The current delivery state of a message, or `nil` if it's gone or not ours.
  func delivery(messageID: UUID, contactID: Data) -> DeliveryStatus? {
    conversations[contactID]?.first { $0.id == messageID }?.delivery
  }

  /// Retires every unacknowledged outbound message older than `retention` to
  /// `.expired`, so the local store-and-forward queue can't grow without bound and
  /// a permanently-unreachable peer's messages surface as "Not delivered" instead
  /// of resending forever (#32). Returns whether anything changed, so the caller
  /// persists only when needed. Nothing is dropped — an expired message stays in
  /// history and can be revived. Relay-side retention is a separate concern.
  func expireStale(retention: TimeInterval, now: Date) -> Bool {
    var changed = false
    for contactID in Array(conversations.keys) {
      let stale = (conversations[contactID] ?? []).filter { message in
        guard message.mine, let status = message.delivery else { return false }
        return status.expired(age: now.timeIntervalSince(message.date), retention: retention)
      }
      for message in stale {
        setDelivery(.expired, messageID: message.id, contactID: contactID)
        changed = true
      }
    }
    return changed
  }

  /// Revives a contact's `.expired` messages back to `.sending` so a manual resend
  /// can drive them again, returning the revived IDs so the caller can re-arm their
  /// confidence deadlines.
  func reviveExpired(contactID: Data) -> [UUID] {
    let expired = (conversations[contactID] ?? []).filter { $0.mine && $0.delivery == .expired }
    for message in expired { setDelivery(.sending, messageID: message.id, contactID: contactID) }
    return expired.map(\.id)
  }

  func setTransport(_ channel: TransportChannel?, messageID: UUID, contactID: Data) {
    mutate(messageID: messageID, contactID: contactID) { $0.transport = channel }
  }

  /// Sets either our own reaction (`personal`) or the peer's reaction on a
  /// message; `nil` clears it.
  func setReaction(_ emoji: String?, personal: Bool, messageID: UUID, contactID: Data) {
    mutate(messageID: messageID, contactID: contactID) { message in
      if personal {
        message.personalReaction = emoji
      } else {
        message.otherReactions = emoji.map { [$0] } ?? []
      }
    }
  }

  /// Applies an edit to a message in both the in-memory view and the disk mirror,
  /// keeping the two in step.
  private func mutate(messageID: UUID, contactID: Data, _ edit: (inout ChatMessage) -> Void) {
    Self.apply(edit, to: &conversations, messageID: messageID, contactID: contactID)
    Self.apply(edit, to: &persistedConversations, messageID: messageID, contactID: contactID)
  }

  /// Edits the matching message in one conversation map in place (copy, edit,
  /// write back), a no-op when the message isn't present in that map.
  private static func apply(
    _ edit: (inout ChatMessage) -> Void, to map: inout [Data: [ChatMessage]],
    messageID: UUID, contactID: Data
  ) {
    guard var messages = map[contactID],
      let index = messages.firstIndex(where: { $0.id == messageID })
    else { return }
    edit(&messages[index])
    map[contactID] = messages
  }
}
