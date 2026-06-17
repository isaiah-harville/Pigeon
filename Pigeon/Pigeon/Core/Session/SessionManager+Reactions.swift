//
//  SessionManager+Reactions.swift
//  Pigeon
//
//  Synced emoji reactions for chat messages.
//

import Foundation
import PigeonCrypto
import PigeonMesh

extension SessionManager {

  func toggleReaction(_ emoji: String, for message: ChatMessage, in contact: Contact) {
    let current = conversations[contact.id]?.first { $0.id == message.id }?.personalReaction
    let reaction = current == emoji ? nil : emoji
    setReaction(reaction, messageID: message.id, contactID: contact.id, fromMe: true)
    sendReaction(reaction, messageID: message.id, to: contact)
  }

  func applyReaction(_ emoji: String?, messageID: UUID, from contact: Contact) {
    setReaction(emoji, messageID: messageID, contactID: contact.id, fromMe: false)
  }

  /// Fire-and-forget: a reaction is a one-shot control message, not queued or
  /// retried like a chat message. If the session isn't established yet we kick
  /// off establishment but drop this reaction — local state already reflects it,
  /// and the peer simply won't see a reaction made while disconnected.
  private func sendReaction(_ emoji: String?, messageID: UUID, to contact: Contact) {
    guard let session = sessions[contact.id], establishedContactIDs.contains(contact.id),
      let ciphertext = try? session.encrypt(Self.encodeReaction(messageID: messageID, emoji: emoji))
    else {
      ensureEstablishing(contactID: contact.id)
      return
    }
    sendEnvelope(.control, payload: ciphertext, to: contact)
  }

  private func setReaction(
    _ emoji: String?, messageID: UUID, contactID: Data, fromMe: Bool
  ) {
    if let index = conversations[contactID]?.firstIndex(where: { $0.id == messageID }) {
      if fromMe {
        conversations[contactID]?[index].personalReaction = emoji
      } else {
        conversations[contactID]?[index].otherReactions = emoji.map { [$0] } ?? []
      }
    }
    if let index = persistedConversations[contactID]?.firstIndex(where: { $0.id == messageID }) {
      if fromMe {
        persistedConversations[contactID]?[index].personalReaction = emoji
      } else {
        persistedConversations[contactID]?[index].otherReactions = emoji.map { [$0] } ?? []
      }
    }
    persist()
  }

  /// Reaction control wire form: command(0x03) ‖ message UUID string ‖ emoji.
  static func encodeReaction(messageID: UUID, emoji: String?) -> Data {
    Data([0x03]) + Data(messageID.uuidString.utf8) + Data((emoji ?? "").utf8)
  }

  /// A reaction should be a single emoji; a modified peer could send anything,
  /// so clamp to a few graphemes (enough for ZWJ/flag sequences) to keep one
  /// hostile "reaction" from distorting the chip layout or bloating storage.
  private static let maxReactionGraphemes = 8

  static func decodeReaction(_ data: Data) -> (messageID: UUID, emoji: String?)? {
    guard data.count >= 37, data.first == 0x03,
      let idString = String(bytes: data.dropFirst().prefix(36), encoding: .utf8),
      let id = UUID(uuidString: idString),
      let emoji = String(bytes: data.dropFirst(37), encoding: .utf8)
    else { return nil }
    if emoji.isEmpty { return (id, nil) }
    return (id, String(emoji.prefix(maxReactionGraphemes)))
  }
}
