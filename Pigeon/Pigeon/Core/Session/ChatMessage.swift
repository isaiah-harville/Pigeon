//
//  ChatMessage.swift
//  Pigeon
//

import Foundation

/// A single decrypted message in a conversation.
struct ChatMessage: Identifiable, Equatable {
    let id = UUID()
    let mine: Bool
    let text: String
    var date: Date = Date()
}
