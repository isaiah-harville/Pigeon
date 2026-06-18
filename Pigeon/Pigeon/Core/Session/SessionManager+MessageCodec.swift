//
//  SessionManager+MessageCodec.swift
//  Pigeon
//
//  Encrypted application-message payloads.
//

import Foundation

extension SessionManager {
  /// On-wire form of an app message, carried *inside* the Double Ratchet
  /// ciphertext (so the ratchet authenticates these bytes end-to-end; JSON key
  /// ordering is therefore not security-relevant). Encoded as JSON for forward
  /// extensibility — new optional fields can be added without breaking older
  /// peers' decoding.
  ///
  /// NOTE: this replaced the earlier positional `UUID‖text` form and is not
  /// wire-compatible with it; peers must run a build new enough to speak JSON.
  private struct AppMessagePayload: Codable {
    let id: UUID
    let text: String
    let replySnippet: String?
    /// The sender's send time, so a message delayed in store-and-forward shows
    /// when it was actually sent rather than when it happened to arrive.
    let sentAt: Date?
  }

  /// Longest reply snippet we keep from a peer. The sender already truncates to
  /// a preview length, but a modified peer can send anything; clamp on receipt
  /// so a hostile snippet can't bloat storage or distort layout.
  private static let maxReplySnippet = 80

  /// Returns `nil` rather than empty `Data` if encoding fails, so a malformed
  /// payload is never silently encrypted and sent as an empty message.
  static func encodeMessage(_ message: ChatMessage) -> Data? {
    let payload = AppMessagePayload(
      id: message.id, text: message.text, replySnippet: message.replySnippet,
      sentAt: message.date)
    return try? JSONEncoder().encode(payload)
  }

  static func decodeMessage(_ data: Data) -> ChatMessage? {
    guard let payload = try? JSONDecoder().decode(AppMessagePayload.self, from: data) else {
      return nil
    }
    var message = ChatMessage(mine: false, text: payload.text)
    message.id = payload.id
    message.replySnippet = payload.replySnippet.map(clampSnippet)
    // A message can't have been sent after it arrived; clamp a fast/skewed peer
    // clock to our arrival time so the displayed send time is never in the future.
    message.sentAt = payload.sentAt.map { min($0, message.date) }
    return message
  }

  private static func clampSnippet(_ snippet: String) -> String {
    let oneLine = snippet.replacingOccurrences(of: "\n", with: " ")
    return oneLine.count > maxReplySnippet ? String(oneLine.prefix(maxReplySnippet)) : oneLine
  }
}
