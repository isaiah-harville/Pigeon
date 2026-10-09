import PigeonFFI
import SwiftUI

struct PendingGroupInvitesSection: View {
  @Environment(SessionManager.self) private var session

  @ViewBuilder
  var body: some View {
    let active = session.groupInviteJoins.filter { join in
      join.progress == .pending || join.progress == .approved
    }
    if !active.isEmpty {
      Section("Group requests") {
        ForEach(active, id: \.requestID) { join in
          if let link = GroupInviteLink(
            ticket: join.ticket, now: Date(timeIntervalSince1970: 0))
          {
            HStack {
              Image(systemName: "clock")
              VStack(alignment: .leading) {
                Text("Group \(link.metadata.groupId.prefix(4).hexEncoded)")
                Text(joinStatus(join.progress, expiresAtMs: link.metadata.expiresAtMs))
                  .font(.footnote)
                  .foregroundStyle(.secondary)
              }
            }
          }
        }
      }
    }
  }

  private func joinStatus(_ progress: PigeonGroupInviteProgress, expiresAtMs: Int64) -> String {
    if progress == .approved { return "Approved · waiting for membership" }
    if Int64(Date().timeIntervalSince1970 * 1_000) >= expiresAtMs {
      return "Invite expired · request may not complete"
    }
    return "Waiting for an admin"
  }
}
