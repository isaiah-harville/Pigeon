import PigeonFFI
import SwiftUI

struct JoinGroupView: View {
  @Environment(\.dismiss) private var dismiss

  var initialCode = ""
  let onJoin: (GroupInviteLink) -> Bool

  @State private var pasted = ""
  @State private var scanning = true
  @State private var selectedLink: GroupInviteLink?
  @State private var errorMessage: String?
  @State private var requestSent = false

  var body: some View {
    NavigationStack {
      ScrollView {
        VStack(spacing: 20) {
          if requestSent {
            pendingNotice
          } else if let selectedLink {
            preview(selectedLink)
          } else {
            input
          }
        }
        .padding()
      }
      .navigationTitle("Join Group")
      .navigationBarTitleDisplayMode(.inline)
      .onAppear {
        if !initialCode.isEmpty { select(initialCode) }
      }
      .toolbar {
        ToolbarItem(placement: .cancellationAction) {
          Button(requestSent ? "Done" : "Cancel") { dismiss() }
        }
      }
    }
  }

  @ViewBuilder
  private var input: some View {
    Picker("Invite", selection: $scanning) {
      Text("Scan QR").tag(true)
      Text("Paste Link").tag(false)
    }
    .pickerStyle(.segmented)
    if scanning {
      QRScanner { code in select(code) }
        .frame(height: 320)
        .clipShape(RoundedRectangle(cornerRadius: 16))
      Text("Scan a group invite QR code.")
        .foregroundStyle(.secondary)
    } else {
      TextField("https://pigeonwire.app/group#ticket=…", text: $pasted)
        .textInputAutocapitalization(.never)
        .autocorrectionDisabled()
        .keyboardType(.URL)
        .textFieldStyle(.roundedBorder)
        .onSubmit { select(pasted) }
      Button("Review Invite") { select(pasted) }
        .buttonStyle(.borderedProminent)
        .disabled(pasted.isEmpty)
    }
    if let errorMessage {
      Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
        .font(.footnote)
        .foregroundStyle(.red)
    }
  }

  private func preview(_ link: GroupInviteLink) -> some View {
    VStack(alignment: .leading, spacing: 16) {
      Label("Group invite", systemImage: "person.3.fill")
        .font(.title2.weight(.semibold))
      Text(
        link.metadata.publicMode
          ? "Public · joins automatically" : "Private · admin approval required"
      )
      .foregroundStyle(.secondary)
      LabeledContent("Relay", value: relayHost(link))
      LabeledContent("Group code", value: groupCode(link))
      Text(
        "The group name and members are verified after an admin adds you. "
          + "Confirm this link came from the group you expect."
      )
      .font(.footnote)
      .foregroundStyle(.secondary)
      inviteActions(link)
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }

  private func inviteActions(_ link: GroupInviteLink) -> some View {
    VStack(spacing: 16) {
      Button("Request to Join") {
        if onJoin(link) {
          requestSent = true
        } else {
          errorMessage = "Couldn't save the join request. Try again after checking storage."
        }
      }
      .buttonStyle(.borderedProminent)
      .frame(maxWidth: .infinity)
      Button("Use Another Link") {
        selectedLink = nil
        errorMessage = nil
      }
      .frame(maxWidth: .infinity)
      if let errorMessage {
        Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
          .font(.footnote)
          .foregroundStyle(.red)
      }
    }
  }

  private func relayHost(_ link: GroupInviteLink) -> String {
    URL(string: link.metadata.relayUrl)?.host ?? link.metadata.relayUrl
  }

  private func groupCode(_ link: GroupInviteLink) -> String {
    link.metadata.groupId.prefix(4).map { String(format: "%02x", $0) }.joined()
  }

  private var pendingNotice: some View {
    ContentUnavailableView(
      "Request saved",
      systemImage: "clock",
      description: Text(
        "An authorized admin must come online. Private groups also require approval. "
          + "Check Groups for status; the invite may expire or fill before you join."))
  }

  private func select(_ code: String) {
    guard let link = GroupInviteLink(scanned: code) else {
      errorMessage = "Invalid or expired group invite."
      return
    }
    selectedLink = link
    errorMessage = nil
  }
}
