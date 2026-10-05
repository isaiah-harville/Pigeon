import PigeonFFI
import SwiftUI

struct GroupInviteSettingsSection: View {
  @Environment(SessionManager.self) private var session
  let groupID: Data
  let group: PigeonGroupState

  @State private var inviteIsPublic = false
  @State private var selectedInviteLink: GroupInviteLink?
  @State private var showInvite = false
  @State private var errorMessage: String?

  @ViewBuilder
  var body: some View {
    if group.adminIdentities.contains(session.myID), !group.dissolved {
      Section("Invite link") {
        inviteControls
        pendingInviteRequests
        if let errorMessage {
          Text(errorMessage).foregroundStyle(.red)
        }
      }
      .sheet(isPresented: $showInvite) {
        if let selectedInviteLink {
          GroupInviteShareView(link: selectedInviteLink) {
            try session.revokeGroupInvite(selectedInviteLink)
          }
        }
      }
    }
  }

  @ViewBuilder
  private var inviteControls: some View {
    if let active = activeInvite {
      Label(
        active.metadata.publicMode ? "Public · automatic approval" : "Private · admin approval",
        systemImage: active.metadata.publicMode ? "person.3.fill" : "lock.fill")
      Button("Show Link and QR") {
        selectedInviteLink = active
        showInvite = true
      }
      Text("Revoke this link before changing how people join.")
        .font(.footnote)
        .foregroundStyle(.secondary)
    } else if group.memberIdentities.count < SessionManager.maximumGroupMembers {
      Toggle("Public · join automatically", isOn: $inviteIsPublic)
      Text(
        inviteIsPublic
          ? "Anyone holding the link can join while an admin is online."
          : "Each request needs an admin's approval."
      )
      .font(.footnote)
      .foregroundStyle(.secondary)
      Button("Create Link and QR") { createInvite() }
    }
  }

  private var pendingInviteRequests: some View {
    ForEach(groupInvites, id: \.ticket) { invite in
      if let link = GroupInviteLink(ticket: invite.ticket) {
        ForEach(invite.requests.filter { $0.progress == .pending }, id: \.requestID) { request in
          VStack(alignment: .leading, spacing: 8) {
            Text(requesterLabel(request.requesterIdentity))
            Text(request.requesterIdentity.hexEncoded)
              .font(.caption.monospaced())
              .textSelection(.enabled)
              .accessibilityLabel("Requester identity fingerprint")
            HStack {
              Button("Approve") {
                decideInvite(
                  address: link.metadata.inboxAddress,
                  requestID: request.requestID, approve: true)
              }
              Button("Reject", role: .destructive) {
                decideInvite(
                  address: link.metadata.inboxAddress,
                  requestID: request.requestID, approve: false)
              }
            }
          }
        }
      }
    }
  }

  private var groupInvites: [PigeonGroupInviteState] {
    session.groupInvites.filter { invite in
      GroupInviteLink(ticket: invite.ticket)?.metadata.groupId == groupID
    }
  }

  private var activeInvite: GroupInviteLink? {
    groupInvites.compactMap { GroupInviteLink(ticket: $0.ticket) }.first
  }

  private func createInvite() {
    do {
      let link = try session.createGroupInvite(
        groupID: groupID, publicMode: inviteIsPublic,
        expiresAt: Date().addingTimeInterval(7 * 24 * 60 * 60))
      selectedInviteLink = link
      showInvite = true
    } catch {
      errorMessage = "Could not create the invite. Check relay and storage, then try again."
    }
  }

  private func decideInvite(address: Data, requestID: Data, approve: Bool) {
    do {
      try session.decideGroupInviteRequest(
        inboxAddress: address, requestID: requestID, approve: approve)
    } catch {
      errorMessage = "Could not save the decision. Check storage and try again."
    }
  }

  private func requesterLabel(_ identity: Data) -> String {
    if let contact = session.contacts.first(where: { $0.id == identity }) {
      return contact.displayName
    }
    return "Unknown requester · verify identity before approving"
  }
}
