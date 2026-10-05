import PigeonFFI
import SwiftUI

struct GroupSettingsView: View {
  @Environment(SessionManager.self) private var session
  @Environment(\.dismiss) private var dismiss
  let groupID: Data

  @State private var showRename = false
  @State private var proposedName = ""
  @State private var showAddMember = false
  @State private var showRecovery = false
  @State private var showRelayChange = false
  @State private var confirmation: DestructiveAction?
  @State private var errorMessage: String?
  @State private var proposedRelayURL = ""
  @State private var recoveryInProgress = false
  @State private var relayChangeInProgress = false
  @State private var recoveryStatusMessage: String?

  private enum DestructiveAction: String, Identifiable {
    case leave
    case dissolve
    var id: String { rawValue }
  }

  private var group: PigeonGroupState? { session.groups.first { $0.groupID == groupID } }

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
    .alert("Recover Group Relay", isPresented: $showRecovery) {
      TextField("https://relay.example", text: $proposedRelayURL)
        .textInputAutocapitalization(.never)
        .keyboardType(.URL)
      Button("Cancel", role: .cancel) {}
      Button("Start Recovery") { startRecovery() }
        .disabled(recoveryInProgress || replacementRelayURL == nil)
    } message: {
      Text(
        "Admins will authenticate this replacement inside the existing MLS group. "
          + "The relay changes only after the required admin quorum agrees."
      )
    }
    .alert("Change Group Relay", isPresented: $showRelayChange) {
      TextField("https://relay.example", text: $proposedRelayURL)
        .textInputAutocapitalization(.never)
        .keyboardType(.URL)
      Button("Cancel", role: .cancel) {}
      Button("Change") { changeRelay() }
        .disabled(relayChangeInProgress || replacementRelayURL == nil)
    } message: {
      Text(
        "The new endpoint must use the group's current coordinator key. "
          + "Use relay recovery when moving to a different operator."
      )
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
        recoveryControls(group)
        membersSection(group)
        GroupInviteSettingsSection(groupID: groupID, group: group)
        securitySection
        destructiveSection(group)
        errorSection
      }
    } else {
      ContentUnavailableView("Group unavailable", systemImage: "person.3.sequence")
    }
  }

  @ViewBuilder
  private func recoveryControls(_ group: PigeonGroupState) -> some View {
    if isAdmin(group), !group.dissolved {
      Section("Relay recovery") {
        Button {
          proposedRelayURL = group.relayURL
          showRecovery = true
        } label: {
          Label("Recover Group Relay", systemImage: "arrow.trianglehead.2.clockwise.rotate.90")
        }
        .disabled(recoveryInProgress)
        if recoveryInProgress {
          HStack {
            ProgressView()
            Text("Starting authenticated recovery…")
          }
        } else if let recoveryStatusMessage {
          Text(recoveryStatusMessage)
            .font(.footnote)
            .foregroundStyle(.secondary)
        }
      }
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
        renameButton(group)
        meshButton(group)
        relayButton(group)
        LabeledContent("Current relay", value: URL(string: group.relayURL)?.host ?? group.relayURL)
        if relayChangeInProgress {
          HStack {
            ProgressView()
            Text("Verifying coordinator and staging relay change…")
          }
          .font(.footnote)
          .foregroundStyle(.secondary)
        }
      }
    }
  }

  private func renameButton(_ group: PigeonGroupState) -> some View {
    Button {
      proposedName = group.name
      showRename = true
    } label: {
      Label("Change Group Name", systemImage: "pencil")
    }
  }

  private func meshButton(_ group: PigeonGroupState) -> some View {
    Button {
      apply(.meshChanged, boolValue: !group.meshEnabled)
    } label: {
      Label(
        group.meshEnabled ? "Turn Off Local Mesh" : "Turn On Local Mesh",
        systemImage: group.meshEnabled
          ? "antenna.radiowaves.left.and.right.slash"
          : "antenna.radiowaves.left.and.right")
    }
  }

  private func relayButton(_ group: PigeonGroupState) -> some View {
    Button {
      proposedRelayURL = group.relayURL
      showRelayChange = true
    } label: {
      Label("Change Group Relay", systemImage: "network")
    }
    .disabled(relayChangeInProgress)
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
        if group.localLeavePending {
          HStack {
            ProgressView()
            Text("Waiting for an admin to approve your leave request…")
          }
          .font(.footnote)
          .foregroundStyle(.secondary)
        } else {
          Button("Leave Group", role: .destructive) { confirmation = .leave }
        }
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

  private func isOwner(_ group: PigeonGroupState) -> Bool { group.ownerIdentity == session.myID }

  private func isAdmin(_ grp: PigeonGroupState) -> Bool {
    grp.adminIdentities.contains(session.myID)
  }

  private func canManage(_ identity: Data, in group: PigeonGroupState) -> Bool {
    isAdmin(group) && identity != session.myID
      && identity != group.ownerIdentity && !group.dissolved
  }

  private var confirmationBinding: Binding<Bool> {
    Binding(get: { confirmation != nil }, set: { if !$0 { confirmation = nil } })
  }

  private var replacementRelayURL: URL? {
    guard let url = URL(string: proposedRelayURL.trimmingCharacters(in: .whitespacesAndNewlines)),
      let scheme = url.scheme?.lowercased(), scheme == "https" || scheme == "wss",
      url.host != nil
    else { return nil }
    return url
  }

  private func startRecovery() {
    guard let group, let replacementRelayURL else { return }
    recoveryInProgress = true
    recoveryStatusMessage = nil
    Task {
      do {
        try await session.recoverGroup(group, using: replacementRelayURL)
        recoveryStatusMessage =
          "Recovery proposed. Pigeon will switch relays after the required admin quorum agrees."
      } catch {
        errorMessage =
          "Recovery was not staged. Verify the replacement relay and try again."
      }
      recoveryInProgress = false
    }
  }

  private func changeRelay() {
    guard let group, let replacementRelayURL else { return }
    relayChangeInProgress = true
    errorMessage = nil
    Task {
      do {
        try await session.changeGroupRelay(group, to: replacementRelayURL)
      } catch SessionManager.GroupRecoveryError.coordinatorMismatch {
        errorMessage =
          "That relay uses a different coordinator key. Use Recover Group Relay instead."
      } catch {
        errorMessage = "The relay change could not be staged. Verify the relay and try again."
      }
      relayChangeInProgress = false
    }
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
      errorMessage = "Could not save the change. Check your role and pending group changes."
    }
  }
}
