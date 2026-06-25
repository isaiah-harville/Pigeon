//
//  ChatMessage.swift
//  Pigeon
//

import Foundation

/// Delivery state of one of *our* outbound messages — the confidence signal shown
/// under the bubble. Always `nil` for received and system messages; only our own
/// messages carry it. The progression is deliberately honest: we never claim more
/// than we can prove, so `delivered` is reached only on the recipient's
/// end-to-end ack, and a message we handed to a transport is never downgraded to
/// `failed` just because the ack is slow (store-and-forward will still deliver it).
enum DeliveryStatus: String, Codable {
  /// Composed but not yet dispatched: no session exists yet, or it's queued for
  /// the next connectivity event. Still on our device.
  case sending
  /// Encrypted and handed to a transport; awaiting the recipient's ack. Genuinely
  /// on its way — store-and-forward keeps it moving even if the peer is offline.
  case sent
  /// The recipient acknowledged it end-to-end. The only state we can *prove*.
  case delivered
  /// Couldn't be dispatched within the confidence window (we never reached a
  /// session to encrypt against). Auto-retry on connectivity continues and the UI
  /// offers a manual resend; this is purely an "unconfirmed, you can act" hint.
  case failed
  /// Retired from the local resend queue after the retention window elapsed with
  /// no ack (#32) — a terminal, non-pending state so a permanently-unreachable
  /// peer's messages stop resending forever instead of growing the queue. Nothing
  /// is dropped: it stays in history and the UI offers a manual resend, which
  /// revives it. Distinct from `.failed`, which keeps auto-retrying.
  case expired

  /// Whether a message in this state, this old, should fall to `.failed`. Only an
  /// undispatched message (`.sending`) past the window does — a handed-off `.sent`
  /// message stays `sent` (it's in store-and-forward) until the ack upgrades it.
  /// Pure so the timeout policy is unit-tested without the session machinery.
  func timedOut(age: TimeInterval, window: TimeInterval) -> Bool {
    self == .sending && age >= window
  }

  /// Whether an unacknowledged message left this long has exhausted the local
  /// retention window and should be retired to `.expired` (#32). Only unacked
  /// states expire; `.delivered` and `.expired` are terminal. Pure so the
  /// retention policy is unit-tested without the session machinery.
  func expired(age: TimeInterval, retention: TimeInterval) -> Bool {
    switch self {
    case .delivered, .expired: return false
    case .sending, .sent, .failed: return age >= retention
    }
  }

  /// States the UI surfaces as needing the user's attention (a "Not delivered"
  /// line with a resend affordance): a message that couldn't be dispatched, or one
  /// retired from the queue after the retention window.
  var needsAttention: Bool { self == .failed || self == .expired }
}

/// A single message in a conversation. `delivery` is set only on our own outbound
/// messages and drives the Sent → Delivered status (and the not-delivered resend
/// affordance); `pending` is the derived "not yet acknowledged" flag the
/// store-and-forward resend loop keys off.
struct ChatMessage: Identifiable, Equatable, Codable {
  var id = UUID()
  let mine: Bool
  let text: String
  /// When this message arrived on *this* device (local time), used for ordering
  /// and day separators. For our own messages this is also the send time.
  var date = Date()
  /// The original send time stamped by the sender. Differs from `date` when a
  /// message waited in store-and-forward before reaching us; `nil` for our own
  /// messages (we display `date`). Surfaces a "delivered late" hint in the UI.
  var sentAt: Date?
  /// Outbound delivery state; `nil` for received and system messages.
  var delivery: DeliveryStatus?
  /// A centered notice (e.g. "Ephemeral enabled") rather than a chat bubble.
  var system: Bool = false
  /// Which link this message travelled over (locally observed), shown in the UI.
  /// `nil` for older history or messages not yet dispatched.
  var transport: TransportChannel?
  /// One reaction from the local user and reactions from other chat members.
  var personalReaction: String?
  var otherReactions: [String] = []
  /// Short preview of the message this one replies to.
  var replySnippet: String?

  /// Our own message that the peer hasn't acknowledged yet — what the
  /// store-and-forward resend loop must keep (re)sending. Derived from `delivery`,
  /// so there is a single source of truth for delivery state.
  var pending: Bool {
    guard let delivery else { return false }
    return delivery != .delivered && delivery != .expired
  }

  init(mine: Bool, text: String) {
    self.init(mine: mine, text: text, delivery: nil, system: false)
  }

  init(mine: Bool, text: String, pending: Bool) {
    self.init(mine: mine, text: text, delivery: pending ? .sending : nil, system: false)
  }

  init(mine: Bool, text: String, system: Bool) {
    self.init(mine: mine, text: text, delivery: nil, system: system)
  }

  init(mine: Bool, text: String, delivery: DeliveryStatus?, system: Bool) {
    self.mine = mine
    self.text = text
    self.delivery = delivery
    self.system = system
  }

  // Tolerant decoding: missing optional-ish fields default rather than fail,
  // so adding fields doesn't discard already-stored history.
  private enum CodingKeys: String, CodingKey {
    case id, mine, text, date, sentAt, delivery, pending, system, transport
    case personalReaction, otherReactions, replySnippet
  }

  init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    id = (try? container.decode(UUID.self, forKey: .id)) ?? UUID()
    mine = try container.decode(Bool.self, forKey: .mine)
    text = try container.decode(String.self, forKey: .text)
    date = (try? container.decode(Date.self, forKey: .date)) ?? Date()
    sentAt = try? container.decode(Date.self, forKey: .sentAt)
    delivery = Self.decodeDelivery(from: container, mine: mine)
    system = (try? container.decode(Bool.self, forKey: .system)) ?? false
    transport = try? container.decode(TransportChannel.self, forKey: .transport)
    personalReaction = try? container.decode(String.self, forKey: .personalReaction)
    otherReactions = (try? container.decode([String].self, forKey: .otherReactions)) ?? []
    replySnippet = try? container.decode(String.self, forKey: .replySnippet)
  }

  func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(id, forKey: .id)
    try container.encode(mine, forKey: .mine)
    try container.encode(text, forKey: .text)
    try container.encode(date, forKey: .date)
    try container.encodeIfPresent(sentAt, forKey: .sentAt)
    try container.encodeIfPresent(delivery, forKey: .delivery)
    try container.encode(system, forKey: .system)
    try container.encodeIfPresent(transport, forKey: .transport)
    try container.encodeIfPresent(personalReaction, forKey: .personalReaction)
    try container.encode(otherReactions, forKey: .otherReactions)
    try container.encodeIfPresent(replySnippet, forKey: .replySnippet)
  }

  /// Reads the stored `delivery`, or migrates pre-status history: a legacy
  /// outbound `pending` flag maps to `.sent` (it re-confirms or times out on the
  /// next connectivity pass), a settled outbound message to `.delivered`.
  private static func decodeDelivery(
    from container: KeyedDecodingContainer<CodingKeys>, mine: Bool
  ) -> DeliveryStatus? {
    if let status = try? container.decode(DeliveryStatus.self, forKey: .delivery) {
      return status
    }
    guard mine, let legacyPending = try? container.decode(Bool.self, forKey: .pending) else {
      return nil
    }
    return legacyPending ? .sent : .delivered
  }
}
