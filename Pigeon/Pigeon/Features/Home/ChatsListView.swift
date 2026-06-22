//
//  ChatsListView.swift
//  Pigeon
//
//  The app's home: a sleek list of conversations. The leading toolbar button
//  opens the menu (identity, Bluetooth, activity); the trailing button adds a
//  contact by scanning their QR code.
//

import SwiftUI

struct ChatsListView: View {
  @Environment(SessionManager.self) private var session
  @Environment(IdentityManager.self) private var identity

  @State private var showAddContact = false
  @State private var showMenu = false
  @State private var showContacts = false

  var body: some View {
    NavigationStack {
      content
    }
  }

  private var content: some View {
    Group {
      if session.chatContacts.isEmpty {
        emptyState
      } else {
        contactList
      }
    }
    .navigationTitle("Pigeon")
    .navigationBarTitleDisplayMode(.inline)
    .safeAreaInset(edge: .bottom) { statusStrip }
    .refreshable { await session.refreshChats() }
    .toolbar { toolbarContent }
    .sheet(isPresented: $showAddContact) { AddContactView() }
    .sheet(isPresented: $showMenu) { MenuView() }
    .sheet(isPresented: $showContacts) { ContactsListView() }
  }

  @ToolbarContentBuilder
  private var toolbarContent: some ToolbarContent {
    ToolbarItem(placement: .topBarLeading) {
      Button {
        showMenu = true
      } label: {
        Image(systemName: "line.3.horizontal")
          .font(.title3.weight(.semibold))
      }
      .accessibilityLabel("Menu")
    }
    ToolbarItem(placement: .principal) {
      Text("Pigeon")
        .font(.system(size: 28, weight: .heavy, design: .rounded).smallCaps())
        .tracking(2)
        .foregroundStyle(.primary)
    }
    ToolbarItem(placement: .topBarTrailing) {
      Button {
        showContacts = true
      } label: {
        Image(systemName: "person.2")
          .font(.title3)
      }
      .accessibilityLabel("Contacts")
    }
    ToolbarItem(placement: .topBarTrailing) {
      Button {
        showAddContact = true
      } label: {
        Image(systemName: "qrcode.viewfinder")
          .font(.title3)
      }
      .accessibilityLabel("Add contact")
    }
  }

  // MARK: - Connection status

  private var statusStrip: some View {
    HStack(spacing: 8) {
      Circle()
        .fill(statusColor)
        .frame(width: 8, height: 8)
      Text(statusText)
        .font(.footnote.weight(.medium))
        .foregroundStyle(.secondary)
      Spacer()
    }
    .padding(.horizontal)
    .padding(.vertical, 8)
    .background(.bar)
  }

  private var statusColor: Color {
    if session.connectedPeerCount > 0 { return .green }
    switch session.status {
    case .scanning: return .orange
    case .idle: return .secondary
    case .unauthorized, .poweredOff: return .red
    }
  }

  private var statusText: String {
    if session.connectedPeerCount > 0 {
      let peers = session.connectedPeerCount
      return "Connected to \(peers) \(peers == 1 ? "peer" : "peers")"
    }
    return session.status.rawValue
  }

  // MARK: - Contact list

  private var contactList: some View {
    List {
      ForEach(session.chatContacts) { contact in
        NavigationLink {
          ChatView(contact: contact)
        } label: {
          ContactRow(contact: contact)
        }
        .listRowInsets(EdgeInsets(top: 8, leading: 16, bottom: 8, trailing: 16))
        .swipeActions(edge: .trailing) {
          Button(role: .destructive) {
            session.deleteConversation(with: contact)
          } label: {
            Label("Delete", systemImage: "trash")
          }
        }
      }
    }
    .listStyle(.plain)
  }

  // MARK: - Empty state

  // Two cases: no contacts at all (add one), or contacts exist in the book but no
  // open conversation (open one).
  private var hasContacts: Bool { !session.contacts.isEmpty }

  private var emptyState: some View {
    VStack(spacing: 20) {
      Image(systemName: hasContacts ? "person.2" : "qrcode.viewfinder")
        .font(.system(size: 64, weight: .light))
        .foregroundStyle(.tint)
      VStack(spacing: 6) {
        Text("No conversations yet")
          .font(.title3.weight(.semibold))
        Text(
          hasContacts
            ? "Open a contact from your contacts book to start chatting."
            : "Add someone by scanning their Pigeon QR code in person."
        )
        .font(.callout)
        .foregroundStyle(.secondary)
        .multilineTextAlignment(.center)
      }
      emptyStateButton
    }
    .padding(40)
    .frame(maxWidth: .infinity, maxHeight: .infinity)
  }

  private var emptyStateButton: some View {
    Button {
      if hasContacts { showContacts = true } else { showAddContact = true }
    } label: {
      Label(
        hasContacts ? "Open Contacts" : "Add Contact",
        systemImage: hasContacts ? "person.2" : "plus"
      )
      .font(.body.weight(.semibold))
      .padding(.horizontal, 8)
    }
    .buttonStyle(.borderedProminent)
    .controlSize(.large)
    .buttonBorderShape(.capsule)
  }
}

/// One conversation row: avatar, name, last-message preview, time, and the
/// per-chat security state.
private struct ContactRow: View {
  @Environment(SessionManager.self) private var session
  let contact: Contact

  private var secure: Bool { session.establishedContactIDs.contains(contact.id) }

  var body: some View {
    HStack(spacing: 14) { rowContent }
      .padding(.vertical, 2)
  }

  @ViewBuilder
  private var rowContent: some View {
    ContactAvatar(name: contact.displayName, seed: contact.id, size: 52)

    VStack(alignment: .leading, spacing: 3) {
      titleRow
      previewRow
    }
  }

  private var titleRow: some View {
    HStack(spacing: 5) {
      Text(contact.displayName)
        .font(.headline)
        .lineLimit(1)
      if session.isEphemeral(contact) {
        Image(systemName: "clock.arrow.circlepath")
          .font(.caption2)
          .foregroundStyle(.orange)
      }
      Spacer(minLength: 4)
      if let time = timeString {
        Text(time)
          .font(.caption)
          .foregroundStyle(.secondary)
      }
    }
  }

  private var previewRow: some View {
    HStack(spacing: 5) {
      Image(systemName: secure ? "lock.fill" : "lock.open")
        .font(.caption2)
        .foregroundStyle(secure ? .green : .secondary)
      Text(previewText)
        .font(.subheadline)
        .foregroundStyle(.secondary)
        .lineLimit(1)
    }
  }

  private var previewText: String {
    guard let message = session.lastMessage(with: contact) else {
      return secure ? "Secure — say hello" : "Connecting…"
    }
    return (message.mine ? "You: " : "") + message.text
  }

  private var timeString: String? {
    guard let date = session.lastMessage(with: contact)?.date else { return nil }
    let formatter = DateFormatter()
    if Calendar.current.isDateInToday(date) {
      formatter.timeStyle = .short
    } else {
      formatter.dateStyle = .short
    }
    return formatter.string(from: date)
  }
}
