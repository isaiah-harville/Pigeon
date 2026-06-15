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
                        Text("No contacts yet. Add one by scanning their QR code.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(session.contacts) { contact in
                        NavigationLink {
                            ChatView(contact: contact)
                        } label: {
                            HStack {
                                Image(systemName: session.establishedContactIDs.contains(contact.id) ? "lock.fill" : "lock.open")
                                    .foregroundStyle(session.establishedContactIDs.contains(contact.id) ? .green : .secondary)
                                Text(contact.displayName)
                            }
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
}
