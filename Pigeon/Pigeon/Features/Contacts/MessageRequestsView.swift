import SwiftUI

struct MessageRequestsView: View {
  @Environment(SessionManager.self) private var session

  var body: some View {
    List(session.incomingMessageRequests) { contact in
      NavigationLink {
        MessageRequestDetailView(contactID: contact.id)
      } label: {
        HStack(spacing: 12) {
          ContactAvatar(name: contact.displayName, seed: contact.id, size: 44)
          VStack(alignment: .leading, spacing: 3) {
            Text(contact.displayName).font(.headline)
            Text("Unverified sender").font(.caption).foregroundStyle(.orange)
          }
        }
      }
    }
    .navigationTitle("Message Requests")
  }
}

private struct MessageRequestDetailView: View {
  @Environment(SessionManager.self) private var session
  @Environment(\.dismiss) private var dismiss
  let contactID: Data

  private var contact: Contact? { session.contacts.first { $0.id == contactID } }

  var body: some View {
    Group {
      if let contact {
        requestList(contact)
      } else {
        ContentUnavailableView("Request unavailable", systemImage: "person.crop.circle.badge.xmark")
      }
    }
    .navigationTitle(contact?.displayName ?? "Request")
    .navigationBarTitleDisplayMode(.inline)
  }

  private func requestList(_ contact: Contact) -> some View {
    List {
      profileSection(contact)
      Section("Introduction") {
        Text(session.messages(with: contact).first { !$0.mine && !$0.system }?.text ?? "")
      }
      verificationSection(contact)
      actionSection(contact)
    }
  }

  private func profileSection(_ contact: Contact) -> some View {
    Section {
      HStack(spacing: 14) {
        ContactAvatar(name: contact.displayName, seed: contact.id, size: 54)
        VStack(alignment: .leading, spacing: 4) {
          Text(contact.displayName).font(.title3.weight(.semibold))
          Label(
            session.isVerifiedInPerson(contact) ? "Verified" : "Unverified sender",
            systemImage: session.isVerifiedInPerson(contact)
              ? "checkmark.shield.fill" : "questionmark.diamond"
          )
          .font(.caption)
          .foregroundStyle(session.isVerifiedInPerson(contact) ? .green : .orange)
        }
      }
    }
  }

  private func verificationSection(_ contact: Contact) -> some View {
    Section {
      Text(session.safetyNumber(with: contact))
        .font(.caption.monospaced())
        .textSelection(.enabled)
      if !session.isVerifiedInPerson(contact) {
        Button("Mark as Verified") { session.markVerifiedInPerson(contact) }
      }
    } header: {
      Text("Verify identity")
    } footer: {
      Text("Compare this safety number with the sender using another trusted channel.")
    }
  }

  private func actionSection(_ contact: Contact) -> some View {
    Section {
      Button("Accept Message Request") {
        session.acceptMessageRequest(from: contact)
        dismiss()
      }
      Button("Block Sender", role: .destructive) {
        session.blockContact(contact)
        dismiss()
      }
    }
  }
}
