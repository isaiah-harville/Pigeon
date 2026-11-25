//
//  ChatView.swift
//  Pigeon
//
//  An end-to-end-encrypted conversation with one verified contact.
//

import PigeonFFI
import SwiftUI

struct ChatView: View {
  @Environment(SessionManager.self) private var session
  let contact: Contact

  @State private var draft = ""
  @State private var showSafetyNumber = false
  @State private var showRename = false
  @State private var newName = ""
  @State private var replyTarget: ChatMessage?
  @State private var isAtBottom = true
  @FocusState private var composerFocused: Bool

  private static let bottomAnchor = "chat-bottom"

  var body: some View {
    chatLayout
      .navigationBarTitleDisplayMode(.inline)
      .onAppear { session.activeChatID = contact.id }
      .onDisappear { if session.activeChatID == contact.id { session.activeChatID = nil } }
      .toolbar { chatToolbar }
      .sheet(isPresented: $showSafetyNumber) {
        SafetyNumberSheet(
          number: session.safetyNumber(with: contact), name: contact.displayName,
          isVerified: session.isVerifiedInPerson(contact)
        ) { session.markVerifiedInPerson(contact) }
      }
      .alert("Rename Contact", isPresented: $showRename) {
        TextField("Name", text: $newName)
        Button("Cancel", role: .cancel) {}
        Button("Save") { session.renameContact(contact, to: newName) }
      }
  }

  private var chatLayout: some View {
    VStack(spacing: 0) {
      ChatStatusBanner(contact: contact)
      messagesScroll
      composer
      if session.hasRelay,
        ChatInteraction.canConfigureChat(requestState: contact.requestState)
      {
        TransportPill(contact: contact)
          .padding(.bottom, 6)
      }
    }
  }

  private var messagesScroll: some View {
    // One read of the conversation per render: day breaks and the latest
    // outgoing message are derived in a single pass, not per bubble.
    let messages = session.messages(with: contact)
    let lastOutgoingID = messages.last { $0.mine && !$0.system }?.id
    let dayStarts = Self.dayStarts(in: messages)
    return ScrollViewReader { proxy in
      ScrollView {
        LazyVStack(alignment: .leading, spacing: 6) {
          ForEach(messages) { message in
            if dayStarts.contains(message.id) {
              daySeparator(for: message.date)
            }
            bubble(message, lastOutgoingID: lastOutgoingID).id(message.id)
          }
          Color.clear
            .frame(height: 1)
            .id(Self.bottomAnchor)
            .onAppear { isAtBottom = true }
            .onDisappear { isAtBottom = false }
        }
        .padding()
      }
      .scrollDismissesKeyboard(.interactively)
      .onChange(of: messages.count) {
        // Follow new messages only when already at the bottom or when the
        // new message is our own; never pull someone out of older history.
        guard isAtBottom || messages.last?.mine == true else { return }
        withAnimation { proxy.scrollTo(Self.bottomAnchor, anchor: .bottom) }
      }
      .onAppear { proxy.scrollTo(Self.bottomAnchor, anchor: .bottom) }
    }
  }

  /// IDs of messages that begin a new calendar day.
  private static func dayStarts(in messages: [ChatMessage]) -> Set<UUID> {
    var starts: Set<UUID> = []
    var previous: Date?
    let calendar = Calendar.current
    for message in messages {
      if previous.map({ !calendar.isDate(message.date, inSameDayAs: $0) }) ?? true {
        starts.insert(message.id)
      }
      previous = message.date
    }
    return starts
  }

  private var composer: some View {
    ChatComposer(
      draft: $draft, replyTarget: $replyTarget, focus: $composerFocused,
      enabled: session.canSendMessage(to: contact),
      disabledMessage: contact.requestState == .outgoing
        ? "You sent an introduction. You can send more after they accept." : nil
    ) { text, reply in
      session.send(text, replySnippet: reply?.replySnippetText, to: contact)
    }
  }

}

extension ChatView {

  @ToolbarContentBuilder
  private var chatToolbar: some ToolbarContent {
    ToolbarItem(placement: .principal) {
      Button {
        showSafetyNumber = true
      } label: {
        HStack(spacing: 5) {
          Text(contact.displayName)
            .font(.headline)
            .lineLimit(1)
          VerifiedBadge(verified: session.isVerifiedInPerson(contact), font: .caption)
        }
      }
      .buttonStyle(.plain)
      .accessibilityHint("Shows safety number")
    }
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
    if !session.advertisedRelays(for: contact).isEmpty {
      Section("Relay Selection") {
        RelayPicker(contact: contact)
      }
    }
    if contact.requestState == .none, !session.relayURLs.isEmpty {
      Section("Share Relay") {
        ForEach(session.relayURLs, id: \.self) { url in
          Button {
            session.shareRelay(url, with: contact)
          } label: {
            Label(url.host ?? url.absoluteString, systemImage: "square.and.arrow.up")
          }
        }
      }
    }
    if ChatInteraction.canConfigureChat(requestState: contact.requestState) {
      Section("Chat") {
        Toggle(isOn: ephemeralBinding) {
          Label("Ephemeral Chat", systemImage: "clock.arrow.circlepath")
        }
      }
    }
    Section("Contact") {
      Button {
        newName = contact.displayName
        showRename = true
      } label: {
        Label("Rename", systemImage: "pencil")
      }
      Button {
        showSafetyNumber = true
      } label: {
        Label("Safety Number", systemImage: "checkmark.shield")
      }
    }
  }

  private var ephemeralBinding: Binding<Bool> {
    Binding(
      get: { session.isEphemeral(contact) },
      set: { session.setEphemeral($0, for: contact) }
    )
  }

  @ViewBuilder
  private func bubble(_ message: ChatMessage, lastOutgoingID: UUID?) -> some View {
    if message.system && message.event != .relayRecommendation {
      ChatTimelineMarker(text: message.text, systemImage: ChatTimelineIcon.name(for: message.text))
    } else {
      messageBubble(message, showsStatus: showsStatus(message, lastOutgoingID: lastOutgoingID))
    }
  }

  private func daySeparator(for date: Date) -> some View {
    ChatTimelineMarker(text: dayLabel(for: date))
  }

  private func dayLabel(for date: Date) -> String {
    if Calendar.current.isDateInToday(date) { return "Today" }
    return date.formatted(date: .abbreviated, time: .omitted)
  }

  @ViewBuilder
  private func messageBubble(_ message: ChatMessage, showsStatus: Bool) -> some View {
    VStack(alignment: message.mine ? .trailing : .leading, spacing: 2) {
      HStack(alignment: .bottom, spacing: 4) {
        if message.mine { Spacer(minLength: 48) }
        messageText(message)
        if !message.mine { Spacer(minLength: 48) }
      }
      MessageReactions(message: message)
      MessageFooter(message: message)
      if let status = message.delivery, showsStatus {
        MessageStatusLabel(status: status) { session.retryDelivery(to: contact) }
      }
    }
    .frame(maxWidth: .infinity, alignment: message.mine ? .trailing : .leading)
  }

  /// Show the Sent → Delivered line under the latest outbound message (matching
  /// iMessage), plus under any not-delivered one so a stuck message stays
  /// actionable.
  private func showsStatus(_ message: ChatMessage, lastOutgoingID: UUID?) -> Bool {
    message.mine && (message.delivery?.needsAttention == true || message.id == lastOutgoingID)
  }

  private func messageText(_ message: ChatMessage) -> some View {
    Group {
      if message.event == .relayRecommendation {
        RelayRecommendationMessageCard(urls: message.relayRecommendationURLs, mine: message.mine)
      } else if ContactCard.mightBeShared(message.text),
        let card = ContactCard(scanned: message.text)
      {
        ContactShareMessageCard(card: card)
      } else {
        MessageBubbleContent(message: message)
      }
    }
    .padding(.horizontal, 13)
    .padding(.vertical, 9)
    .background(
      message.mine ? AnyShapeStyle(Color.accentColor) : AnyShapeStyle(.fill.tertiary),
      in: BubbleShape(mine: message.mine)
    )
    .opacity(message.delivery == .sending ? 0.6 : 1)
    .contextMenu {
      MessageContextMenu(
        message: message,
        onReact: { session.toggleReaction($0, for: message, in: contact) },
        onReply: { reply(to: message) },
        onRetry: message.mine && message.pending
          ? { session.retryDelivery(to: contact) } : nil)
    }
  }

  private struct ContactShareMessageCard: View {
    @Environment(SessionManager.self) private var session
    let card: ContactCard

    private var alreadyAdded: Bool {
      session.contacts.contains { $0.id == card.bundle.identityKey }
    }

    var body: some View {
      VStack(alignment: .leading, spacing: 8) {
        Label("Pigeon Contact", systemImage: "person.crop.circle.badge.plus")
          .font(.caption.weight(.semibold))
        Text(card.name.isEmpty ? "Unnamed" : card.name)
          .font(.headline)
        Button(alreadyAdded ? "In Contacts" : "Add Contact") {
          _ = session.addContact(
            card.bundle, name: card.name, relayURLs: card.relayURLs,
            prekeys: ContactPrekeyBundles(
              chat: card.prekeyBundle, control: card.pairwiseControlPrekeyBundle),
            admission: .outgoingRequest)
        }
        .buttonStyle(.bordered)
        .disabled(alreadyAdded)
      }
      .foregroundStyle(.primary)
      .frame(minWidth: 190, alignment: .leading)
    }
  }

  private func reply(to message: ChatMessage) {
    replyTarget = message
    Task { @MainActor in
      await Task.yield()
      composerFocused = true
    }
  }
}
