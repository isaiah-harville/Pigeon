//
//  ContentView.swift
//  Pigeon
//
//  App hub: identity QR, Bluetooth status, verified contacts, and encrypted
//  chats. (Onboarding and a polished contacts model come in Phase 6.)
//

import SwiftUI

struct ContentView: View {
    @Environment(IdentityManager.self) private var identity
    @Environment(SessionManager.self) private var session
    @State private var showAddContact = false

    var body: some View {
        if !session.isUnlocked {
            UnlockView()
        } else if session.myName.isEmpty {
            OnboardingNameView()
        } else {
            hub
        }
    }

    private var hub: some View {
        NavigationStack {
            List {
                Section("My Identity") {
                    NavigationLink {
                        IdentityQRView()
                    } label: {
                        LabeledContent("Fingerprint", value: identity.publicKey.shortFingerprint)
                            .font(.body.monospaced())
                    }
                }

                Section("Bluetooth") {
                    LabeledContent("Status", value: session.status.rawValue)
                    LabeledContent("Connected peers", value: "\(session.connectedPeerCount)")
                }

                Section("Contacts") {
                    if session.contacts.isEmpty {
                        ContentUnavailableView("No Contacts",
                                               systemImage: "person.crop.circle.badge.plus",
                                               description: Text("Add someone by scanning their QR code."))
                    }
                    ForEach(session.contacts) { contact in
                        NavigationLink {
                            ChatView(contact: contact)
                        } label: {
                            contactRow(contact)
                        }
                    }
                    Button {
                        showAddContact = true
                    } label: {
                        Label("Add Contact", systemImage: "qrcode.viewfinder")
                    }
                }

                Section("Activity") {
                    ForEach(Array(session.log.suffix(12).enumerated()), id: \.offset) { _, line in
                        Text(line).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("Pigeon")
            .sheet(isPresented: $showAddContact) {
                AddContactView()
            }
        }
    }

    @ViewBuilder
    private func contactRow(_ contact: Contact) -> some View {
        let secure = session.establishedContactIDs.contains(contact.id)
        HStack(spacing: 12) {
            ZStack {
                Circle().fill(.tint.opacity(0.2))
                Text(initials(contact.displayName)).font(.headline).foregroundStyle(.tint)
            }
            .frame(width: 40, height: 40)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(contact.displayName).font(.headline)
                    if session.isEphemeral(contact) {
                        Image(systemName: "clock.arrow.circlepath").font(.caption2).foregroundStyle(.orange)
                    }
                }
                Text(previewText(contact))
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            Image(systemName: secure ? "lock.fill" : "lock.open")
                .font(.footnote)
                .foregroundStyle(secure ? .green : .secondary)
        }
    }

    private func previewText(_ contact: Contact) -> String {
        guard let message = session.lastMessage(with: contact) else {
            return session.establishedContactIDs.contains(contact.id) ? "Secure — say hello" : "Connecting…"
        }
        let prefix = message.mine ? "You: " : ""
        return prefix + message.text
    }

    private func initials(_ name: String) -> String {
        let parts = name.split(separator: " ").prefix(2)
        let letters = parts.compactMap { $0.first }.map(String.init).joined()
        return letters.isEmpty ? "?" : letters.uppercased()
    }
}
