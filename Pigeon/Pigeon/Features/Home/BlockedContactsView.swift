import SwiftUI

struct BlockedContactsView: View {
  @Environment(SessionManager.self) private var session

  var body: some View {
    Group {
      if session.blockedContacts.isEmpty {
        ContentUnavailableView(
          "No Blocked Contacts", systemImage: "person.crop.circle.badge.checkmark")
      } else {
        List(session.blockedContacts) { contact in
          HStack(spacing: 12) {
            ContactAvatar(name: contact.displayName, seed: contact.id, size: 42)
            Text(contact.displayName)
            Spacer()
            Button("Unblock") { session.unblockContact(id: contact.id) }
              .buttonStyle(.bordered)
          }
        }
      }
    }
    .navigationTitle("Blocked Contacts")
    .navigationBarTitleDisplayMode(.inline)
  }
}
