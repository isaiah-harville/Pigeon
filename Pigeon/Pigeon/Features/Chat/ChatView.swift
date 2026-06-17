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
    HStack(spacing: 8) {
      TextField("Message", text: $draft)
        .textFieldStyle(.plain)
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(Capsule().fill(.fill.tertiary))
      Button {
        session.send(draft, to: contact)
        draft = ""
      } label: {
        Image(systemName: "paperplane.fill")
          .font(.system(size: 15, weight: .semibold))
          .foregroundStyle(.white)
          .frame(width: 38, height: 38)
          .background(Capsule().fill(Color.accentColor))
      }
      .disabled(draft.isEmpty)
      .opacity(draft.isEmpty ? 0.45 : 1)
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
