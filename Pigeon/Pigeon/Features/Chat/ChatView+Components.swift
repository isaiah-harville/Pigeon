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

/// A chat's current reachability: local Bluetooth peers and/or the relay (with
/// its host), so users can see the path messages take (#15).
struct ConnectionSummary: View {
  let peers: Int
  let relayHosts: [String]

  var body: some View {
    HStack(spacing: 6) {
      Image(systemName: icon)
      Text(text)
      Spacer()
    }
    .font(.caption2)
    .foregroundStyle(.secondary)
  }

  private var icon: String {
    if peers > 0 { return "dot.radiowaves.left.and.right" }
    if !relayHosts.isEmpty { return "globe" }
    return "wifi.slash"
  }

  private var text: String {
    var parts: [String] = []
    if peers > 0 { parts.append("Bluetooth · \(peers) peer\(peers == 1 ? "" : "s")") }
    if let host = relayHosts.first { parts.append("Relay · \(host)") }
    return parts.isEmpty ? "Offline" : parts.joined(separator: "   ")
  }
}

/// A thin pill above the composer to pick the chat's link. Relay is the default
/// (we encourage relays); Bluetooth is the opt-in second option. Tap a segment
/// or swipe to switch; the choice is mirrored to the peer (#24).
struct TransportPill: View {
  @Environment(SessionManager.self) private var session
  let contact: Contact

  var body: some View {
    let bluetooth = session.usesBluetooth(contact)
    HStack(spacing: 2) {
      segment("Relay", "globe", selected: !bluetooth) {
        session.setChatUsesBluetooth(false, for: contact)
      }
      segment("Bluetooth", "dot.radiowaves.left.and.right", selected: bluetooth) {
        session.setChatUsesBluetooth(true, for: contact)
      }
    }
    .padding(3)
    .background(Capsule().fill(.fill.tertiary))
    .padding(.horizontal)
    .gesture(
      DragGesture(minimumDistance: 24).onEnded { value in
        session.setChatUsesBluetooth(value.translation.width > 0, for: contact)
      }
    )
    .animation(.easeInOut(duration: 0.15), value: bluetooth)
  }

  private func segment(
    _ title: String, _ symbol: String, selected: Bool, action: @escaping () -> Void
  ) -> some View {
    Button(action: action) {
      Label(title, systemImage: symbol)
        .font(.caption2.weight(.medium))
        .frame(maxWidth: .infinity)
        .padding(.vertical, 5)
        .foregroundStyle(selected ? AnyShapeStyle(.white) : AnyShapeStyle(.secondary))
        .background(
          selected ? AnyShapeStyle(Color.accentColor) : AnyShapeStyle(.clear), in: Capsule())
    }
    .buttonStyle(.plain)
  }
}

/// Lets the user pin a conversation to one of the contact's advertised relays,
/// or leave it automatic; hidden when the contact advertises none (#18).
struct RelayPicker: View {
  @Environment(SessionManager.self) private var session
  let contact: Contact

  var body: some View {
    let relays = session.advertisedRelays(for: contact)
    if !relays.isEmpty {
      Picker("Relay for this chat", selection: selection) {
        Text("Automatic").tag(URL?.none)
        ForEach(relays, id: \.self) { url in
          Text(url.host ?? url.absoluteString).tag(URL?.some(url))
        }
      }
    }
  }

  private var selection: Binding<URL?> {
    Binding(
      get: { session.preferredRelay(for: contact) },
      set: { session.setPreferredRelay($0, for: contact) }
    )
  }
}

/// A message's timestamp under its bubble. The link it travelled over is kept
/// off the bubble and surfaced on long-press instead (see `MessageDetailMenu`).
struct MessageFooter: View {
  let message: ChatMessage

  var body: some View {
    HStack(spacing: 4) {
      Text(message.displayDate.formatted(date: .omitted, time: .shortened))
      if let delay = message.deliveryDelay {
        Image(systemName: "clock.arrow.circlepath")
        Text("delivered \(Self.delayText(delay)) later")
      }
    }
    .font(.caption2)
    .foregroundStyle(.secondary)
  }

  /// Compact "2h" / "5m" / "1d" rendering of a delivery delay.
  static func delayText(_ delay: TimeInterval) -> String {
    let minutes = Int(delay / 60)
    if minutes < 60 { return "\(minutes)m" }
    let hours = minutes / 60
    return hours < 24 ? "\(hours)h" : "\(hours / 24)d"
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

  private let quickReactions = ["👍", "❤️", "😂"]

  var body: some View {
    if !message.pending {
      ControlGroup {
        ForEach(quickReactions, id: \.self) { reaction in
          reactionButton(reaction)
        }
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
  /// "delivered late" hint so a old message doesn't look brand new.
  var deliveryDelay: TimeInterval? {
    guard !mine, let sentAt else { return nil }
    let delay = date.timeIntervalSince(sentAt)
    return delay >= 30 ? delay : nil
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
    case .relay(let host): return "\(verb) relay · \(host)"
    }
  }

  private func symbol(_ channel: TransportChannel) -> String {
    switch channel {
    case .bluetooth: return "dot.radiowaves.left.and.right"
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
