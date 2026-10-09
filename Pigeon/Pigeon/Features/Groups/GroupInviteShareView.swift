import PigeonFFI
import SwiftUI

struct GroupInviteShareView: View {
  @Environment(\.dismiss) private var dismiss

  let link: GroupInviteLink
  let onRevoke: () throws -> Void

  @State private var confirmingRevocation = false
  @State private var revocationError: String?

  var body: some View {
    NavigationStack {
      ScrollView {
        inviteContent
      }
      .navigationTitle("Group Invite")
      .navigationBarTitleDisplayMode(.inline)
      .toolbar {
        ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
      }
      .confirmationDialog("Revoke this invite?", isPresented: $confirmingRevocation) {
        Button("Revoke Invite", role: .destructive) {
          do {
            try onRevoke()
            dismiss()
          } catch {
            revocationError = "Could not revoke the invite. Check storage and try again."
          }
        }
      } message: {
        Text("People who already joined stay in the group. New requests using this link stop.")
      }
    }
  }

  private var inviteContent: some View {
    VStack(spacing: 20) {
      modeNotice
      if let url = link.shareURL {
        QRCode.image(from: url.absoluteString)
          .frame(maxWidth: 280, maxHeight: 280)
          .padding()
          .background(.background.secondary, in: RoundedRectangle(cornerRadius: 20))
        ShareLink(item: url) {
          Label("Share Invite Link", systemImage: "square.and.arrow.up")
            .frame(maxWidth: .infinity)
        }
        .buttonStyle(.borderedProminent)
      }
      LabeledContent("Expires", value: expiry.formatted(date: .abbreviated, time: .shortened))
        .font(.footnote)
      Button("Revoke Invite", role: .destructive) { confirmingRevocation = true }
        .buttonStyle(.bordered)
      if let revocationError {
        Text(revocationError).foregroundStyle(.red)
      }
    }
    .padding()
  }

  private var expiry: Date {
    Date(timeIntervalSince1970: Double(link.metadata.expiresAtMs) / 1_000)
  }

  private var modeNotice: some View {
    VStack(alignment: .leading, spacing: 8) {
      Label(
        link.metadata.publicMode ? "Public invite" : "Private invite",
        systemImage: link.metadata.publicMode ? "person.3.fill" : "lock.fill"
      )
      .font(.headline)
      Text(modeExplanation)
        .font(.callout)
        .foregroundStyle(.secondary)
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }

  private var modeExplanation: String {
    if link.metadata.publicMode {
      return "Anyone with this link can request to join automatically while an admin is online. "
        + "People can pass the link on."
    }
    return "Anyone with this link can request to join, but an admin must approve each request. "
      + "People can pass the link on."
  }
}
