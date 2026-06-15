//
//  ChatMessage.swift
//  Pigeon
//

import Foundation

/// A single message in a conversation. `pending` marks an outbound message that
/// is queued for store-and-forward delivery (the contact wasn't reachable yet).
struct ChatMessage: Identifiable, Equatable, Codable {
  var id = UUID()
  let mine: Bool
  let text: String
  var date = Date()
  var pending: Bool = false
  /// A centered notice (e.g. "Ephemeral enabled") rather than a chat bubble.
  var system: Bool = false

  init(mine: Bool, text: String) {
    self.init(mine: mine, text: text, pending: false, system: false)
  }

  init(mine: Bool, text: String, pending: Bool) {
    self.init(mine: mine, text: text, pending: pending, system: false)
  }

  init(mine: Bool, text: String, system: Bool) {
    self.init(mine: mine, text: text, pending: false, system: system)
  }

  init(mine: Bool, text: String, pending: Bool, system: Bool) {
    self.mine = mine
    self.text = text
    self.pending = pending
    self.system = system
  }

  // Tolerant decoding: missing optional-ish fields default rather than fail,
  // so adding fields doesn't discard already-stored history.
  private enum CodingKeys: String, CodingKey { case id, mine, text, date, pending, system }

  init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    id = (try? container.decode(UUID.self, forKey: .id)) ?? UUID()
    mine = try container.decode(Bool.self, forKey: .mine)
    text = try container.decode(String.self, forKey: .text)
    date = (try? container.decode(Date.self, forKey: .date)) ?? Date()
    pending = (try? container.decode(Bool.self, forKey: .pending)) ?? false
    system = (try? container.decode(Bool.self, forKey: .system)) ?? false
  }
}
