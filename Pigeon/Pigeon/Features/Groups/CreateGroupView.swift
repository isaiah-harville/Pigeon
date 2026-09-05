import SwiftUI

struct CreateGroupView: View {
  @Environment(SessionManager.self) private var session
  @Environment(\.dismiss) private var dismiss

  @State private var name = ""
  @State private var selectedMemberIDs: Set<Data> = []
  @State private var selectedRelay: URL?
  @State private var meshEnabled = false
  @State private var isCreating = false
  @State private var errorMessage: String?

  private var eligibleContacts: [Contact] {
    session.contacts
      .filter { contact in
        contact.requestState == .none && contact.pairwiseControlPrekeyBundle != nil
          && (contact.preferredRelayURL != nil || !contact.relayURLs.isEmpty)
      }
      .sorted { first, second in
        first.displayName.localizedCaseInsensitiveCompare(second.displayName)
          == .orderedAscending
      }
  }

  private var groupRelays: [URL] {
    session.relayURLs.filter { relay in
      guard let scheme = relay.scheme?.lowercased() else { return false }
      return scheme == "https" || scheme == "wss"
    }
  }

  var body: some View {
    NavigationStack {
      Form {
        groupSection
        peopleSection
        relaySection
        meshSection
        errorSection
      }
      .navigationTitle("New Group")
      .navigationBarTitleDisplayMode(.inline)
      .toolbar {
        ToolbarItem(placement: .cancellationAction) {
          Button("Cancel") { dismiss() }
            .disabled(isCreating)
        }
        ToolbarItem(placement: .confirmationAction) {
          Button("Create") { create() }
            .disabled(!canCreate || isCreating)
        }
      }
      .interactiveDismissDisabled(isCreating)
      .onAppear { selectedRelay = selectedRelay ?? groupRelays.first }
    }
  }

  private var groupSection: some View {
    Section("Group") {
      TextField("Group name", text: $name)
        .textInputAutocapitalization(.words)
      LabeledContent(
        "Members",
        value: "\(selectedMemberIDs.count + 1) / \(SessionManager.maximumGroupMembers)")
    }
  }

  @ViewBuilder
  private var peopleSection: some View {
    Section("People") {
      if eligibleContacts.isEmpty {
        ContentUnavailableView(
          "No eligible contacts",
          systemImage: "person.2.slash",
          description: Text(
            "Group members must be accepted contacts with a current Pigeon QR card and relay."))
      } else {
        ForEach(eligibleContacts) { contact in contactButton(contact) }
      }
    }
  }

  private func contactButton(_ contact: Contact) -> some View {
    Button {
      toggle(contact.id)
    } label: {
      HStack {
        ContactAvatar(name: contact.displayName, seed: contact.id, size: 38)
        Text(contact.displayName).foregroundStyle(.primary)
        Spacer()
        Image(
          systemName: selectedMemberIDs.contains(contact.id)
            ? "checkmark.circle.fill" : "circle"
        )
        .foregroundStyle(
          selectedMemberIDs.contains(contact.id) ? Color.accentColor : Color.secondary)
      }
    }
    .disabled(
      !selectedMemberIDs.contains(contact.id)
        && selectedMemberIDs.count >= SessionManager.maximumGroupMembers - 1)
  }

  private var relaySection: some View {
    Section("Group relay") {
      if groupRelays.isEmpty {
        Text("Add an HTTPS or WSS relay in Settings before creating a group.")
          .foregroundStyle(.secondary)
      } else {
        Picker("Relay", selection: $selectedRelay) {
          ForEach(groupRelays, id: \.self) { relay in
            Text(relay.host ?? relay.absoluteString).tag(Optional(relay))
          }
        }
      }
      Text(
        "This relay hosts encrypted group messages and MLS coordination. "
          + "It never receives plaintext or group keys."
      )
      .font(.footnote)
      .foregroundStyle(.secondary)
    }
  }

  private var meshSection: some View {
    Section("Local mesh") {
      Toggle("Enable for this group", isOn: $meshEnabled)
      Text(
        "Off by default. Enable only for smaller groups that should exchange "
          + "encrypted group traffic over nearby devices."
      )
      .font(.footnote)
      .foregroundStyle(.secondary)
    }
  }

  @ViewBuilder
  private var errorSection: some View {
    if let errorMessage {
      Section { Text(errorMessage).foregroundStyle(.red) }
    }
  }

  private var canCreate: Bool {
    selectedMemberIDs.count >= 2 && selectedRelay != nil
      && !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
  }

  private func toggle(_ id: Data) {
    if selectedMemberIDs.contains(id) {
      selectedMemberIDs.remove(id)
    } else {
      selectedMemberIDs.insert(id)
    }
  }

  private func create() {
    guard let selectedRelay else { return }
    isCreating = true
    errorMessage = nil
    Task { @MainActor in
      do {
        try await session.createGroup(
          name: name, memberIDs: selectedMemberIDs, relayURL: selectedRelay,
          meshEnabled: meshEnabled)
        dismiss()
      } catch {
        errorMessage =
          "The group could not be created. Check its name, members, and relay, then try again."
        isCreating = false
      }
    }
  }
}
