import PigeonFFI
import SwiftUI

struct AddGroupMemberView: View {
  @Environment(SessionManager.self) private var session
  @Environment(\.dismiss) private var dismiss
  let groupID: Data

  @State private var errorMessage: String?

  private var group: PigeonGroupState? { session.groups.first { $0.groupID == groupID } }
  private var candidates: [Contact] {
    guard let group else { return [] }
    return session.contacts.filter { contact in
      contact.requestState == .none && !group.memberIdentities.contains(contact.id)
        && contact.pairwiseControlPrekeyBundle != nil
        && (contact.preferredRelayURL != nil || !contact.relayURLs.isEmpty)
    }
  }

  var body: some View {
    NavigationStack {
      List {
        ForEach(candidates) { contact in
          Button {
            add(contact)
          } label: {
            HStack(spacing: 12) {
              ContactAvatar(name: contact.displayName, seed: contact.id, size: 42)
              Text(contact.displayName).foregroundStyle(.primary)
              Spacer()
              Image(systemName: "plus.circle.fill")
            }
          }
        }
        if candidates.isEmpty {
          ContentUnavailableView(
            "No contacts to add", systemImage: "person.badge.plus",
            description: Text(
              "Eligible contacts need an accepted, current Pigeon contact card."))
        }
        if let errorMessage { Text(errorMessage).foregroundStyle(.red) }
      }
    }
    .navigationTitle("Add Member")
    .navigationBarTitleDisplayMode(.inline)
    .toolbar {
      ToolbarItem(placement: .cancellationAction) {
        Button("Cancel") { dismiss() }
      }
    }
  }

  private func add(_ contact: Contact) {
    guard let group else { return }
    do {
      try session.changeGroupPolicy(
        .memberAdded, in: group, subjectIdentity: contact.id,
        stringValue: "", boolValue: false)
      dismiss()
    } catch {
      errorMessage =
        "The invitation could not be staged. Wait for any pending group change and try again."
    }
  }
}
