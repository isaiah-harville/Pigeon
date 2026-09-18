//
//  SessionManager+Reactions.swift
//  Pigeon
//
//  Synced emoji reactions for chat messages.
//

import Foundation
import PigeonFFI

extension SessionManager {

  func toggleReaction(_ emoji: String, for message: ChatMessage, in contact: Contact) {
    let current = conversationStore.personalReaction(messageID: message.id, for: contact.id)
    let reaction = current == emoji ? nil : emoji
    setReaction(reaction, messageID: message.id, contactID: contact.id, fromMe: true)
    sendReaction(reaction, messageID: message.id, to: contact)
  }

  func applyReaction(_ emoji: String?, messageID: UUID, from contact: Contact) {
    setReaction(emoji, messageID: messageID, contactID: contact.id, fromMe: false)
  }

  /// Fire-and-forget: a reaction is a one-shot authenticated application event.
  private func sendReaction(_ emoji: String?, messageID: UUID, to contact: Contact) {
    guard let current = contacts.first(where: { $0.id == contact.id }),
      current.requestState == .none,
      canUseCorePairwise(with: current)
    else { return }
    _ = try? sendDirectCoreApplication(
      .reaction(messageID: messageID.uuidString, emoji: emoji), id: UUID(), to: current)
  }

  private func setReaction(
    _ emoji: String?, messageID: UUID, contactID: Data, fromMe: Bool
  ) {
    conversationStore.setReaction(
      emoji, personal: fromMe, messageID: messageID, contactID: contactID)
    persist()
  }

}
