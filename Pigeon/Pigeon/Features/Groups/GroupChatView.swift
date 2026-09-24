import PigeonFFI
import SwiftUI

struct GroupChatView: View {
  @Environment(SessionManager.self) private var session
  let groupID: Data

  @State private var draft = ""
  @State private var sendError: String?
  @State private var showSettings = false
  @FocusState private var composerFocused: Bool

  private var group: PigeonGroupState? {
    session.groups.first { $0.groupID == groupID }
  }

  private var entries: [GroupChatEntry] {
    session.groupConversations[groupID]?.messages ?? []
  }

  var body: some View {
    VStack(spacing: 0) {
      if let group, group.dissolved {
        Label("This group was dissolved", systemImage: "exclamationmark.lock.fill")
          .font(.callout.weight(.semibold))
          .foregroundStyle(.red)
          .padding(10)
          .frame(maxWidth: .infinity)
          .background(.red.opacity(0.1))
      }
      timeline
      composer
    }
    .navigationBarTitleDisplayMode(.inline)
    .toolbar { toolbar }
    .sheet(isPresented: $showSettings) { GroupSettingsView(groupID: groupID) }
    .alert("Message Not Sent", isPresented: errorBinding) {
      Button("OK", role: .cancel) {}
    } message: {
      Text(sendError ?? "The message could not be sent.")
    }
  }
}

extension GroupChatView {
  private var timeline: some View {
    ScrollViewReader { proxy in
      ScrollView {
        LazyVStack(spacing: 8) {
          ForEach(entries) { entry in
            entryView(entry).id(entry.id)
          }
        }
        .padding()
      }
      .scrollDismissesKeyboard(.interactively)
      .onAppear { scrollToLatest(proxy) }
      .onChange(of: entries.count) { scrollToLatest(proxy, animated: true) }
    }
  }

  @ViewBuilder
  private func entryView(_ entry: GroupChatEntry) -> some View {
    switch entry.content {
    case .message(let text, _):
      messageView(text, entry: entry)

    case .status(let status):
      ChatTimelineMarker(text: statusLabel(status))

    case .securityWarning(let code, let evidenceID):
      securityWarning(code: code, evidenceID: evidenceID)
    }
  }

  private func messageView(_ text: String, entry: GroupChatEntry) -> some View {
    VStack(alignment: entry.mine ? .trailing : .leading, spacing: 3) {
      if !entry.mine {
        Text(displayName(for: entry.senderIdentity))
          .font(.caption.weight(.semibold))
          .foregroundStyle(.secondary)
      }
      HStack {
        if entry.mine { Spacer(minLength: 48) }
        Text(text)
          .foregroundStyle(entry.mine ? .white : .primary)
          .padding(.horizontal, 13)
          .padding(.vertical, 9)
          .background(
            entry.mine ? AnyShapeStyle(Color.accentColor) : AnyShapeStyle(.fill.tertiary),
            in: BubbleShape(mine: entry.mine))
        if !entry.mine { Spacer(minLength: 48) }
      }
      if entry.mine, let delivery = entry.delivery {
        Text(deliveryLabel(delivery))
          .font(.caption2)
          .foregroundStyle(delivery.state == .failed ? .red : .secondary)
      }
    }
    .frame(maxWidth: .infinity, alignment: entry.mine ? .trailing : .leading)
  }

  private func securityWarning(code: UInt32, evidenceID: Data) -> some View {
    let evidence = evidenceID.prefix(6).map { String(format: "%02x", $0) }.joined()
    return Label {
      VStack(alignment: .leading, spacing: 2) {
        Text("Group security warning").font(.callout.weight(.bold))
        Text("Code \(code) · evidence \(evidence)")
          .font(.caption.monospaced())
      }
    } icon: {
      Image(systemName: "exclamationmark.shield.fill")
    }
    .foregroundStyle(.red)
    .padding(10)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(.red.opacity(0.1), in: RoundedRectangle(cornerRadius: 12))
  }

  private var composer: some View {
    HStack(alignment: .bottom, spacing: 8) {
      TextField("Message", text: $draft, axis: .vertical)
        .lineLimit(1...5)
        .focused($composerFocused)
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(.fill.tertiary, in: Capsule())
      Button {
        send()
      } label: {
        Image(systemName: "arrow.up.circle.fill")
          .font(.system(size: 32))
      }
      .disabled(!canSend)
      .accessibilityLabel("Send message")
    }
    .padding(.horizontal)
    .padding(.vertical, 8)
    .background(.bar)
  }

  @ToolbarContentBuilder
  private var toolbar: some ToolbarContent {
    ToolbarItem(placement: .principal) {
      if let group {
        Button {
          showSettings = true
        } label: {
          HStack(spacing: 7) {
            GroupAvatar(seed: group.groupID, size: 30)
            Text(group.name).font(.headline).lineLimit(1)
          }
        }
        .buttonStyle(.plain)
      }
    }
    ToolbarItem(placement: .primaryAction) {
      Button {
        showSettings = true
      } label: {
        Image(systemName: "info.circle")
      }
      .accessibilityLabel("Group settings")
    }
  }

  private var canSend: Bool {
    guard let group else { return false }
    return !group.dissolved && group.memberIdentities.contains(session.myID)
      && !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
      && draft.utf8.count <= SessionManager.maximumGroupMessageBytes
  }

  private var errorBinding: Binding<Bool> {
    Binding(get: { sendError != nil }, set: { if !$0 { sendError = nil } })
  }

  private func send() {
    guard let group else { return }
    do {
      try session.sendGroupMessage(draft, in: group, replyToMessageID: nil)
      draft = ""
    } catch {
      sendError =
        "Pigeon kept the message local because it could not durably stage the encrypted group send."
    }
  }

  private func scrollToLatest(_ proxy: ScrollViewProxy, animated: Bool = false) {
    guard let last = entries.last else { return }
    if animated {
      withAnimation { proxy.scrollTo(last.id, anchor: .bottom) }
    } else {
      proxy.scrollTo(last.id, anchor: .bottom)
    }
  }

  private func displayName(for identity: Data?) -> String {
    guard let identity else { return "Pigeon" }
    if identity == session.myID { return "You" }
    if let contact = session.contacts.first(where: { $0.id == identity }) {
      return contact.displayName
    }
    return "Member \(identity.prefix(3).map { String(format: "%02x", $0) }.joined())"
  }

  private func statusLabel(_ status: GroupStatusEvent) -> String {
    switch status {
    case .created(let owner): return "\(displayName(for: owner)) created the group"
    case .memberAdded(let actor, let subject):
      return "\(displayName(for: actor)) added \(displayName(for: subject))"
    case .memberRemoved(let actor, let subject):
      return "\(displayName(for: actor)) removed \(displayName(for: subject))"
    case .memberLeft(_, let subject): return "\(displayName(for: subject)) left the group"
    case .adminPromoted(let actor, let subject):
      return "\(displayName(for: actor)) made \(displayName(for: subject)) an admin"
    case .adminDemoted(let actor, let subject):
      return "\(displayName(for: actor)) removed \(displayName(for: subject)) as admin"
    case .nameChanged(let actor, let name):
      return "\(displayName(for: actor)) changed the group name to \(name)"
    case .meshChanged(let actor, let enabled):
      return "\(displayName(for: actor)) turned local mesh \(enabled ? "on" : "off")"
    case .relayChanged(let actor, _): return "\(displayName(for: actor)) changed the group relay"
    case .dissolved(let actor): return "\(displayName(for: actor)) dissolved the group"
    }
  }

  private func deliveryLabel(_ delivery: GroupDeliverySummary) -> String {
    switch delivery.state {
    case .sending: return "Sending…"
    case .sent: return "Sent"
    case .deliveredTo: return "Delivered to \(delivery.deliveredCount) of \(delivery.intendedCount)"
    case .delivered: return "Delivered"
    case .failed: return "Not delivered"
    case .expired: return "Delivery expired"
    }
  }
}
