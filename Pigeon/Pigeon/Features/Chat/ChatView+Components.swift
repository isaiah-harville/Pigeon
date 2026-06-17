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
    Text(message.date.formatted(date: .omitted, time: .shortened))
      .font(.caption2)
      .foregroundStyle(.secondary)
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
    Text(message.date.formatted(date: .abbreviated, time: .standard))
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
  @Environment(\.dismiss) private var dismiss

  var body: some View {
    NavigationStack {
      ScrollView {
        VStack(spacing: 16) {
          Text(explanation)
            .font(.footnote)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
          Text(number)
            .font(.title3.monospaced())
            .multilineTextAlignment(.center)
        }
        .padding()
      }
      .navigationTitle("Safety Number")
      .toolbar {
        ToolbarItem(placement: .confirmationAction) {
          Button("Done") { dismiss() }
        }
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
