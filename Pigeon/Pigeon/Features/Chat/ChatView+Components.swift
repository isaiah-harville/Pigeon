//
//  ChatView+Components.swift
//  Pigeon
//
//  Supporting views and shapes for ChatView.
//

import SwiftUI

/// Centered timeline chrome for day separators and low-importance system events.
struct ChatTimelineMarker: View {
  let text: String
  var systemImage: String?

  var body: some View {
    HStack(spacing: 5) {
      if let systemImage {
        Image(systemName: systemImage)
          .font(.caption2.weight(.semibold))
      }
      Text(text)
        .font(.caption2.weight(.semibold))
    }
    .foregroundStyle(.secondary)
    .padding(.horizontal, 10)
    .padding(.vertical, 5)
    .background(.fill.quaternary, in: Capsule())
    .frame(maxWidth: .infinity, alignment: .center)
    .padding(.vertical, 4)
  }
}

enum ChatTimelineIcon {
  static func name(for text: String) -> String? {
    if text.hasPrefix("Switched to Bluetooth") { return "dot.radiowaves.left.and.right" }
    if text.hasPrefix("Switched to relay") { return "globe" }
    if text.hasPrefix("Ephemeral") { return "clock.arrow.circlepath" }
    return nil
  }
}

/// A message's timestamp under its bubble. The link it travelled over is kept
/// off the bubble and surfaced on long-press instead (see `MessageDetailMenu`).
struct MessageFooter: View {
  let message: ChatMessage

  var body: some View {
    HStack(spacing: 4) {
      Text(message.displayDate.formatted(date: .omitted, time: .shortened))
      if message.deliveryDelay != nil {
        Image(systemName: "clock.arrow.circlepath")
        Text("received \(message.date.formatted(date: .omitted, time: .shortened))")
      }
    }
    .font(.caption2)
    .foregroundStyle(.secondary)
  }
}

/// The delivery-confidence line under one of our own bubbles: an honest
/// Sent → Delivered progression (we only ever claim what we can prove), and a
/// tap-to-resend affordance when a message couldn't be dispatched. Auto-retry
/// keeps running regardless; this just lets an anxious sender act immediately.
struct MessageStatusLabel: View {
  let status: DeliveryStatus
  let onResend: () -> Void

  var body: some View {
    switch status {
    case .sending: line("Sending…", icon: "clock")
    case .sent: line("Sent", icon: "checkmark")
    case .delivered: line("Delivered", icon: "checkmark.circle.fill")
    case .failed, .expired:
      Button(action: onResend) {
        Label("Not delivered · Resend", systemImage: "exclamationmark.arrow.circlepath")
          .font(.caption2.weight(.semibold))
      }
      .buttonStyle(.plain)
      .foregroundStyle(.red)
      .accessibilityHint("Resend this message")
    }
  }

  private func line(_ text: String, icon: String) -> some View {
    Label(text, systemImage: icon)
      .font(.caption2)
      .foregroundStyle(.secondary)
  }
}

struct MessageBubbleContent: View {
  let message: ChatMessage

  var body: some View {
    VStack(alignment: .leading, spacing: 4) {
      if let replySnippet = message.replySnippet {
        ReplyBubblePreview(text: replySnippet, mine: message.mine)
      }
      Text(message.text)
        .foregroundStyle(message.mine ? .white : .primary)
    }
  }
}

struct ReplyBubblePreview: View {
  let text: String
  let mine: Bool

  var body: some View {
    HStack(spacing: 5) {
      RoundedRectangle(cornerRadius: 2, style: .continuous)
        .fill(mine ? .white.opacity(0.75) : Color.accentColor)
        .frame(width: 3, height: 14)
      Text(text)
        .font(.caption2)
        .lineLimit(2)
        .foregroundStyle(mine ? .white.opacity(0.9) : .secondary)
    }
    .padding(.horizontal, 7)
    .padding(.vertical, 3)
    .background(
      mine ? AnyShapeStyle(.white.opacity(0.14)) : AnyShapeStyle(.fill.quaternary),
      in: RoundedRectangle(cornerRadius: 6)
    )
  }
}

struct MessageReactions: View {
  let message: ChatMessage

  var body: some View {
    if message.personalReaction != nil || !message.otherReactions.isEmpty {
      HStack(spacing: 4) {
        if let personalReaction = message.personalReaction {
          ReactionChip(reaction: personalReaction, personal: true)
        }
        ForEach(Array(message.otherReactions.enumerated()), id: \.offset) { _, reaction in
          ReactionChip(reaction: reaction, personal: false)
        }
      }
    }
  }
}

struct ReactionChip: View {
  let reaction: String
  let personal: Bool

  var body: some View {
    Text(reaction)
      .font(.caption)
      .lineLimit(1)
      .padding(.horizontal, 7)
      .padding(.vertical, 3)
      .background(
        personal ? AnyShapeStyle(Color.accentColor) : AnyShapeStyle(.fill.tertiary),
        in: Capsule()
      )
      .foregroundStyle(personal ? .white : .primary)
  }
}

struct MessageContextMenu: View {
  let message: ChatMessage
  let onReact: (String) -> Void
  let onReply: () -> Void
  /// Present only for a still-pending message of our own, so the user can force
  /// a resend now instead of waiting for the next connectivity event (#82).
  var onRetry: (() -> Void)?

  private let quickReactions = ["👍", "❤️", "😂"]

  var body: some View {
    if !message.pending {
      ControlGroup {
        ForEach(quickReactions, id: \.self) { reaction in
          reactionButton(reaction)
        }
      }
    }
    if let onRetry {
      Button {
        onRetry()
      } label: {
        Label("Retry now", systemImage: "arrow.clockwise")
      }
    }
    Button {
      onReply()
    } label: {
      Label("Reply", systemImage: "arrowshape.turn.up.left")
    }
    Menu {
      MessageDetailMenu(message: message)
    } label: {
      Label("Details", systemImage: "info.circle")
    }
  }

  private func reactionButton(_ reaction: String) -> some View {
    Button {
      onReact(reaction)
    } label: {
      Text(reaction)
        .font(.title3)
    }
  }
}

extension ChatMessage {
  var replySnippetText: String {
    let text = self.text.replacingOccurrences(of: "\n", with: " ")
    return text.count > 72 ? String(text.prefix(72)) + "..." : text
  }

  /// The time to show on the bubble: the original send time when known, so a
  /// store-and-forward-delayed message reads as when it was sent.
  var displayDate: Date { sentAt ?? date }

  /// How long an incoming message waited between being sent and arriving here,
  /// or `nil` when it arrived promptly (or is our own message). Drives the
  /// "received at" hint so a delayed message doesn't look brand new. Threshold:
  /// more than three minutes late.
  var deliveryDelay: TimeInterval? {
    guard !mine, let sentAt else { return nil }
    let delay = date.timeIntervalSince(sentAt)
    return delay > 180 ? delay : nil
  }
}

/// Long-press detail for a message: the link it travelled over plus the full
/// timestamp. The link is the genuinely-observed arrival transport for received
/// messages, and the link it was last sent over for sent ones (#24).
struct MessageDetailMenu: View {
  let message: ChatMessage

  var body: some View {
    if let transport = message.transport {
      Label(linkText(transport), systemImage: symbol(transport))
    }
    if message.deliveryDelay != nil {
      Text("Sent \(message.displayDate.formatted(date: .abbreviated, time: .standard))")
      Text("Received \(message.date.formatted(date: .abbreviated, time: .standard))")
    } else {
      Text(message.date.formatted(date: .abbreviated, time: .standard))
    }
  }

  private func linkText(_ channel: TransportChannel) -> String {
    let verb = message.mine ? "Sent via" : "Received via"
    switch channel {
    case .bluetooth: return "\(verb) Bluetooth"
    case .localWiFi: return "\(verb) Wi-Fi"
    case .relay(let host): return "\(verb) relay · \(host)"
    }
  }

  private func symbol(_ channel: TransportChannel) -> String {
    switch channel {
    case .bluetooth: return "dot.radiowaves.left.and.right"
    case .localWiFi: return "wifi"
    case .relay: return "globe"
    }
  }
}

/// A chat bubble with a softened tail corner on the sender's side, the way
/// modern messengers shape them.
struct BubbleShape: Shape {
  let mine: Bool

  func path(in rect: CGRect) -> Path {
    let radius: CGFloat = 18
    let tail: CGFloat = 5
    return Path(
      roundedRect: rect,
      cornerRadii: RectangleCornerRadii(
        topLeading: radius,
        bottomLeading: mine ? radius : tail,
        bottomTrailing: mine ? tail : radius,
        topTrailing: radius
      ))
  }
}

/// Shows the safety number two people compare in person to confirm no MITM.
struct SafetyNumberSheet: View {
  let number: String
  let name: String
  /// When the contact isn't yet verified in person, an optional action to mark
  /// them verified after the user has compared the numbers out of band.
  var isVerified: Bool = true
  var onVerify: (() -> Void)?
  @Environment(\.dismiss) private var dismiss

  var body: some View {
    NavigationStack {
      ScrollView { details.padding() }
        .navigationTitle("Safety Number")
        .toolbar {
          ToolbarItem(placement: .confirmationAction) {
            Button("Done") { dismiss() }
          }
        }
    }
  }

  private var details: some View {
    VStack(spacing: 16) {
      Text(explanation)
        .font(.footnote)
        .foregroundStyle(.secondary)
        .multilineTextAlignment(.center)
      Text(number)
        .font(.title3.monospaced())
        .multilineTextAlignment(.center)
      if !isVerified, let onVerify {
        Button {
          onVerify()
          dismiss()
        } label: {
          Label("Mark as Verified", systemImage: "checkmark.shield.fill")
            .frame(maxWidth: .infinity)
        }
        .buttonStyle(.borderedProminent)
        .padding(.top, 4)
      }
    }
  }

  private var explanation: String {
    """
    Compare this with \(name) in person. If the numbers match on both devices, \
    no one is intercepting your conversation.
    """
  }
}
