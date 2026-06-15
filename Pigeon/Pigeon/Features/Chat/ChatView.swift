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
    }
  }

  private var messagesScroll: some View {
    ScrollViewReader { proxy in
      ScrollView {
        LazyVStack(alignment: .leading, spacing: 6) {
          ForEach(messages) { message in
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
    HStack(spacing: 6) {
      Image(systemName: isSecure ? "lock.fill" : "lock.open")
      Text(isSecure ? "End-to-end encrypted" : "Establishing secure session…")
      Spacer()
      if session.isEphemeral(contact) {
        Label("Ephemeral", systemImage: "clock.arrow.circlepath")
          .foregroundStyle(.orange)
      }
    }
    .font(.footnote)
    .foregroundStyle(isSecure ? .green : .secondary)
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

  @ViewBuilder
  private func messageBubble(_ message: ChatMessage) -> some View {
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
    .frame(maxWidth: .infinity, alignment: message.mine ? .trailing : .leading)
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
