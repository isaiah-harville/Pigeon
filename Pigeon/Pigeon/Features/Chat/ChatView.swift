//
//  ChatView.swift
//  Pigeon
//
//  An end-to-end-encrypted conversation with one verified contact.
//

import SwiftUI

struct ChatView: View {
  @Environment(SessionManager.self) private var session
  let contact: Contact

  @State private var draft = ""
  @State private var showSafetyNumber = false
  @State private var showRename = false
  @State private var newName = ""

  private var isSecure: Bool { session.establishedContactIDs.contains(contact.id) }
  private var messages: [ChatMessage] { session.messages(with: contact) }

  var body: some View {
    chatLayout
      .navigationTitle(contact.displayName)
      .navigationBarTitleDisplayMode(.inline)
      .onAppear { session.activeChatID = contact.id }
      .onDisappear { if session.activeChatID == contact.id { session.activeChatID = nil } }
      .toolbar { chatToolbar }
      .sheet(isPresented: $showSafetyNumber) {
        SafetyNumberSheet(number: session.safetyNumber(with: contact), name: contact.displayName)
      }
      .alert("Rename Contact", isPresented: $showRename) {
        TextField("Name", text: $newName)
        Button("Cancel", role: .cancel) {}
        Button("Save") { session.renameContact(contact, to: newName) }
      }
  }

  private var chatLayout: some View {
    VStack(spacing: 0) {
      statusBanner
      messagesScroll
      composer
      if session.hasRelay {
        TransportPill(contact: contact)
          .padding(.bottom, 6)
      }
    }
  }

  private var messagesScroll: some View {
    ScrollViewReader { proxy in
      ScrollView {
        LazyVStack(alignment: .leading, spacing: 6) {
          ForEach(Array(messages.enumerated()), id: \.element.id) { index, message in
            if showsDaySeparator(before: index) {
              daySeparator(for: message.date)
            }
            bubble(message).id(message.id)
          }
        }
        .padding()
      }
      .onChange(of: messages.count) {
        if let last = messages.last {
          withAnimation { proxy.scrollTo(last.id, anchor: .bottom) }
        }
      }
      .onAppear {
        if let last = messages.last { proxy.scrollTo(last.id, anchor: .bottom) }
      }
    }
  }

  private var composer: some View {
    HStack {
      TextField("Message", text: $draft)
        .textFieldStyle(.roundedBorder)
      Button("Send") {
        session.send(draft, to: contact)
        draft = ""
      }
      .disabled(draft.isEmpty)
    }
    .padding()
  }

  @ToolbarContentBuilder
  private var chatToolbar: some ToolbarContent {
    ToolbarItem(placement: .primaryAction) {
      Menu {
        chatMenuContent
      } label: {
        Image(systemName: "ellipsis.circle")
      }
    }
  }

  @ViewBuilder
  private var chatMenuContent: some View {
    Toggle(isOn: ephemeralBinding) {
      Label("Ephemeral chat", systemImage: "clock.arrow.circlepath")
    }
    RelayPicker(contact: contact)
    Button {
      newName = contact.displayName
      showRename = true
    } label: {
      Label("Rename", systemImage: "pencil")
    }
    Button {
      showSafetyNumber = true
    } label: {
      Label("Safety number", systemImage: "checkmark.shield")
    }
  }

  private var ephemeralBinding: Binding<Bool> {
    Binding(
      get: { session.isEphemeral(contact) },
      set: { session.setEphemeral($0, for: contact) }
    )
  }

  @ViewBuilder
  private var statusBanner: some View {
    VStack(spacing: 2) {
      HStack(spacing: 6) {
        Image(systemName: isSecure ? "lock.fill" : "lock.open")
        Text(isSecure ? "End-to-end encrypted" : "Establishing secure session…")
        Spacer()
        if session.isEphemeral(contact) {
          Label("Ephemeral", systemImage: "clock.arrow.circlepath")
            .foregroundStyle(.orange)
        }
      }
      .foregroundStyle(isSecure ? .green : .secondary)
      ConnectionSummary(peers: session.connectedPeerCount, relayHosts: session.relayHosts)
    }
    .font(.footnote)
    .padding(.horizontal)
    .padding(.vertical, 6)
    .background(.bar)
  }

  @ViewBuilder
  private func bubble(_ message: ChatMessage) -> some View {
    if message.system {
      Text("— \(message.text) —")
        .font(.caption)
        .foregroundStyle(.secondary)
        .frame(maxWidth: .infinity, alignment: .center)
        .padding(.vertical, 2)
    } else {
      messageBubble(message)
    }
  }

  private func showsDaySeparator(before index: Int) -> Bool {
    guard index > 0 else { return true }
    return !Calendar.current.isDate(messages[index].date, inSameDayAs: messages[index - 1].date)
  }

  private func daySeparator(for date: Date) -> some View {
    Text(dayLabel(for: date))
      .font(.caption2.weight(.semibold))
      .foregroundStyle(.secondary)
      .frame(maxWidth: .infinity, alignment: .center)
      .padding(.vertical, 6)
  }

  private func dayLabel(for date: Date) -> String {
    if Calendar.current.isDateInToday(date) { return "Today" }
    return date.formatted(date: .abbreviated, time: .omitted)
  }

  @ViewBuilder
  private func messageBubble(_ message: ChatMessage) -> some View {
    VStack(alignment: message.mine ? .trailing : .leading, spacing: 2) {
      HStack(alignment: .bottom, spacing: 4) {
        if message.mine { Spacer(minLength: 48) }
        Text(message.text)
          .foregroundStyle(message.mine ? .white : .primary)
          .padding(.horizontal, 13)
          .padding(.vertical, 9)
          .background(
            message.mine ? AnyShapeStyle(Color.accentColor) : AnyShapeStyle(.fill.tertiary),
            in: BubbleShape(mine: message.mine)
          )
          .opacity(message.pending ? 0.6 : 1)
          .contextMenu { MessageDetailMenu(message: message) }
        if message.mine {
          if message.pending {
            Image(systemName: "clock")
              .font(.caption2)
              .foregroundStyle(.secondary)
          }
        } else {
          Spacer(minLength: 48)
        }
      }
      MessageFooter(message: message)
    }
    .frame(maxWidth: .infinity, alignment: message.mine ? .trailing : .leading)
  }
}

/// A chat's current reachability: local Bluetooth peers and/or the relay (with
/// its host), so users can see the path messages take (#15).
private struct ConnectionSummary: View {
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
    if !relayHosts.isEmpty { return "network" }
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
private struct TransportPill: View {
  @Environment(SessionManager.self) private var session
  let contact: Contact

  var body: some View {
    let bluetooth = session.usesBluetooth(contact)
    HStack(spacing: 2) {
      segment("Relay", "network", selected: !bluetooth) {
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
private struct RelayPicker: View {
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
private struct MessageFooter: View {
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
private struct MessageDetailMenu: View {
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
    case .relay: return "network"
    }
  }
}

/// A chat bubble with a softened tail corner on the sender's side, the way
/// modern messengers shape them.
private struct BubbleShape: Shape {
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
private struct SafetyNumberSheet: View {
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
