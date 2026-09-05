import PigeonFFI
import SwiftUI

struct GroupSettingsView: View {
  @Environment(SessionManager.self) private var session
  @Environment(\.dismiss) private var dismiss
  let groupID: Data

  @State private var showRename = false
  @State private var proposedName = ""
  @State private var showAddMember = false
  @State private var confirmation: DestructiveAction?
  @State private var errorMessage: String?

  private enum DestructiveAction: String, Identifiable {
    case leave
    case dissolve
    var id: String { rawValue }
  }

  private var group: PigeonGroupState? {
    session.groups.first { $0.groupID == groupID }
  }

  var body: some View {
    NavigationStack {
      settingsContent
    }
    .navigationTitle("Group Info")
    .navigationBarTitleDisplayMode(.inline)
    .toolbar {
      ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
    }
    .alert("Change Group Name", isPresented: $showRename) {
      TextField("Group name", text: $proposedName)
      Button("Cancel", role: .cancel) {}
      Button("Save") { apply(.nameChanged, stringValue: proposedName) }
    }
    .confirmationDialog(
      confirmation == .dissolve ? "Dissolve this group?" : "Leave this group?",
      isPresented: confirmationBinding,
      titleVisibility: .visible
    ) {
      if confirmation == .dissolve {
        Button("Dissolve Group", role: .destructive) { apply(.dissolved) }
      } else {
        Button("Leave Group", role: .destructive) { apply(.memberLeft) }
      }
      Button("Cancel", role: .cancel) {}
    } message: {
      Text(
        confirmation == .dissolve
          ? "Dissolving is permanent for every member."
          : "You will lose access to messages sent after you leave.")
    }
    .sheet(isPresented: $showAddMember) { AddGroupMemberView(groupID: groupID) }
  }
}

extension GroupSettingsView {
  @ViewBuilder
  private var settingsContent: some View {
    if let group {
      Form {
        groupHeader(group)
        ownerControls(group)
        membersSection(group)
        securitySection
        destructiveSection(group)
        errorSection
      }
    } else {
      ContentUnavailableView("Group unavailable", systemImage: "person.3.sequence")
    }
  }

  private func groupHeader(_ group: PigeonGroupState) -> some View {
    Section {
      HStack(spacing: 16) {
        GroupAvatar(seed: group.groupID, size: 64)
        VStack(alignment: .leading, spacing: 3) {
          Text(group.name).font(.title3.weight(.semibold))
          Text("\(group.memberIdentities.count) members · MLS epoch \(group.epoch)")
            .font(.footnote).foregroundStyle(.secondary)
        }
      }
    }
  }

  @ViewBuilder
  private func ownerControls(_ group: PigeonGroupState) -> some View {
    if isOwner(group) {
      Section("Owner controls") {
        Button {
          proposedName = group.name
          showRename = true
        } label: {
          Label("Change Group Name", systemImage: "pencil")
        }
        Button {
          apply(.meshChanged, boolValue: !group.meshEnabled)
        } label: {
          Label(
            group.meshEnabled ? "Turn Off Local Mesh" : "Turn On Local Mesh",
            systemImage: group.meshEnabled
              ? "antenna.radiowaves.left.and.right.slash"
              : "antenna.radiowaves.left.and.right")
        }
        LabeledContent(
          "Group relay", value: URL(string: group.relayURL)?.host ?? group.relayURL)
      }
    }
  }

  private func membersSection(_ group: PigeonGroupState) -> some View {
    Section("Members") {
      if isAdmin(group), group.memberIdentities.count < SessionManager.maximumGroupMembers {
        Button {
          showAddMember = true
        } label: {
          Label("Add Member", systemImage: "person.badge.plus")
        }
      }
      ForEach(group.memberIdentities, id: \.self) { identity in
        memberRow(identity, group: group)
      }
    }
  }

  private var securitySection: some View {
    Section("Security") {
      Label("End-to-end encrypted with MLS", systemImage: "lock.shield.fill")
      Text(
        "New members can decrypt only messages sent after they join. Membership "
          + "and policy changes are authenticated and serialized by the selected relay."
      )
      .font(.footnote)
      .foregroundStyle(.secondary)
    }
  }

  @ViewBuilder
  private func destructiveSection(_ group: PigeonGroupState) -> some View {
    if group.dissolved {
      Section {
        Label("Group dissolved", systemImage: "exclamationmark.lock.fill")
          .foregroundStyle(.red)
      }
    } else if isOwner(group) {
      Section {
        Button("Dissolve Group", role: .destructive) { confirmation = .dissolve }
      }
    } else if group.memberIdentities.contains(session.myID), group.memberIdentities.count > 3 {
      Section {
        Button("Leave Group", role: .destructive) { confirmation = .leave }
      }
    }
  }

  @ViewBuilder
  private var errorSection: some View {
    if let errorMessage {
      Section { Text(errorMessage).foregroundStyle(.red) }
    }
  }

  @ViewBuilder
  private func memberRow(_ identity: Data, group: PigeonGroupState) -> some View {
    let owner = identity == group.ownerIdentity
    let admin = group.adminIdentities.contains(identity)
    HStack(spacing: 12) {
      ContactAvatar(name: displayName(identity), seed: identity, size: 40)
      VStack(alignment: .leading, spacing: 2) {
        Text(displayName(identity))
        if owner {
          Text("Owner").font(.caption).foregroundStyle(.secondary)
        } else if admin {
          Text("Admin").font(.caption).foregroundStyle(.secondary)
        }
      }
      Spacer()
      if canManage(identity, in: group) {
        memberMenu(identity, admin: admin, memberCount: group.memberIdentities.count)
      }
    }
  }

  private func memberMenu(_ identity: Data, admin: Bool, memberCount: Int) -> some View {
    Menu {
      if admin {
        Button("Remove as Admin") { apply(.adminDemoted, subject: identity) }
      } else {
        Button("Make Admin") { apply(.adminPromoted, subject: identity) }
      }
      if memberCount > 3 {
        Button("Remove from Group", role: .destructive) {
          apply(.memberRemoved, subject: identity)
        }
      }
    } label: {
      Image(systemName: "ellipsis.circle")
    }
  }

  private func displayName(_ identity: Data) -> String {
    if identity == session.myID { return "You" }
    return session.contacts.first { $0.id == identity }?.displayName
      ?? "Member \(identity.prefix(3).map { String(format: "%02x", $0) }.joined())"
  }

  private func isOwner(_ group: PigeonGroupState) -> Bool {
    group.ownerIdentity == session.myID
  }

  private func isAdmin(_ group: PigeonGroupState) -> Bool {
    group.adminIdentities.contains(session.myID)
  }

  private func canManage(_ identity: Data, in group: PigeonGroupState) -> Bool {
    isAdmin(group) && identity != session.myID
      && identity != group.ownerIdentity && !group.dissolved
  }

  private var confirmationBinding: Binding<Bool> {
    Binding(get: { confirmation != nil }, set: { if !$0 { confirmation = nil } })
  }

  private func apply(
    _ kind: PigeonGroupPolicyChangeKind,
    subject: Data = Data(),
    stringValue: String = "",
    boolValue: Bool = false
  ) {
    guard let group else { return }
    do {
      try session.changeGroupPolicy(
        kind, in: group, subjectIdentity: subject,
        stringValue: stringValue, boolValue: boolValue)
      confirmation = nil
    } catch {
      errorMessage =
        "The change was not staged. Another group change may still be pending, "
        + "or your role may not allow it."
    }
  }
}

private struct AddGroupMemberView: View {
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
