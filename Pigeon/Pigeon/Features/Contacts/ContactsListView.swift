//
//  ContactsListView.swift
//  Pigeon
//
//  The contacts book: every verified contact, separate from the chats list.
//  Tapping a contact opens (or re-opens) its conversation; the chats list only
//  shows contacts with an open conversation, so a deleted chat can be restarted
//  from here without re-scanning. Swiping fully forgets a contact (requires a
//  re-scan to reach again).
//

import SwiftUI

struct ContactsListView: View {
  @Environment(SessionManager.self) private var session
  @Environment(\.dismiss) private var dismiss

  @State private var showAddContact = false
  @State private var openedContactID: Data?
  @State private var contactToRemove: Contact?

  /// All contacts, sorted by display name (case-insensitive).
  private var contacts: [Contact] {
    session.contacts.sorted { lhs, rhs in
      lhs.displayName.localizedCaseInsensitiveCompare(rhs.displayName) == .orderedAscending
    }
  }

  var body: some View {
    NavigationStack {
      content
        .navigationTitle("Contacts")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar { toolbarContent }
        .navigationDestination(item: $openedContactID) { id in
          if let contact = session.contacts.first(where: { $0.id == id }) {
            ChatView(contact: contact)
          }
        }
        .sheet(isPresented: $showAddContact) { AddContactView() }
        .alert(
          "Remove Contact?", isPresented: removeAlertBinding, presenting: contactToRemove
        ) { contact in
          Button("Remove", role: .destructive) { session.removeContact(contact) }
          Button("Cancel", role: .cancel) {}
        } message: { contact in
          Text(
            "This deletes your conversation and forgets \(contact.displayName). "
              + "You'll need to scan their QR code again to reach them.")
        }
    }
  }

  @ViewBuilder
  private var content: some View {
    if contacts.isEmpty {
      emptyState
    } else {
      contactList
    }
  }

  private var contactList: some View {
    List {
      ForEach(contacts) { contact in
        Button {
          session.startConversation(with: contact)
          openedContactID = contact.id
        } label: {
          ContactBookRow(contact: contact)
        }
        .buttonStyle(.plain)
        .listRowInsets(EdgeInsets(top: 8, leading: 16, bottom: 8, trailing: 16))
        .swipeActions(edge: .trailing) {
          Button(role: .destructive) {
            contactToRemove = contact
          } label: {
            Label("Remove", systemImage: "trash")
          }
        }
      }
    }
    .listStyle(.plain)
  }

  private var emptyState: some View {
    VStack(spacing: 20) {
      Image(systemName: "person.crop.circle.badge.plus")
        .font(.system(size: 64, weight: .light))
        .foregroundStyle(.tint)
      VStack(spacing: 6) {
        Text("No contacts yet")
          .font(.title3.weight(.semibold))
        Text("Add someone by scanning their Pigeon QR code in person.")
          .font(.callout)
          .foregroundStyle(.secondary)
          .multilineTextAlignment(.center)
      }
      Button {
        showAddContact = true
      } label: {
        Label("Add Contact", systemImage: "plus")
          .font(.body.weight(.semibold))
          .padding(.horizontal, 8)
      }
      .buttonStyle(.borderedProminent)
      .controlSize(.large)
      .buttonBorderShape(.capsule)
    }
    .padding(40)
    .frame(maxWidth: .infinity, maxHeight: .infinity)
  }

  @ToolbarContentBuilder
  private var toolbarContent: some ToolbarContent {
    ToolbarItem(placement: .topBarLeading) {
      Button("Done") { dismiss() }
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

  /// Drives the remove-confirmation alert off the optional `contactToRemove`.
  private var removeAlertBinding: Binding<Bool> {
    Binding(
      get: { contactToRemove != nil },
      set: { if !$0 { contactToRemove = nil } })
  }
}

/// One contacts-book row: avatar, name, and whether the safety number was
/// exchanged in person.
private struct ContactBookRow: View {
  @Environment(SessionManager.self) private var session
  let contact: Contact

  var body: some View {
    HStack(spacing: 14) {
      ContactAvatar(name: contact.displayName, seed: contact.id, size: 44)
      VStack(alignment: .leading, spacing: 3) {
        Text(contact.displayName)
          .font(.headline)
          .lineLimit(1)
        if !session.isVerifiedInPerson(contact) {
          Text("Not verified in person")
            .font(.caption)
            .foregroundStyle(.orange)
        }
      }
      Spacer(minLength: 4)
      if session.hasConversation(contact) {
        Image(systemName: "bubble.left.fill")
          .font(.caption)
          .foregroundStyle(.secondary)
          .accessibilityLabel("Has open conversation")
      }
    }
    .padding(.vertical, 2)
    .contentShape(Rectangle())
  }
}
