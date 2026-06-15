//
//  ChatView.swift
//  Pigeon
//
//  An end-to-end-encrypted conversation with one verified contact.
//

import SwiftUI

struct ChatView: View {
    @Environment(SessionManager.self) private var session
    let contact: Contact

    @State private var draft = ""
    @State private var showSafetyNumber = false

    private var isSecure: Bool { session.establishedContactIDs.contains(contact.id) }

    var body: some View {
        VStack(spacing: 0) {
            statusBanner

            ScrollView {
                LazyVStack(alignment: .leading, spacing: 6) {
                    ForEach(session.messages(with: contact)) { message in
                        bubble(message)
                    }
                }
                .padding()
            }

            HStack {
                TextField("Message", text: $draft)
                    .textFieldStyle(.roundedBorder)
                Button("Send") {
                    session.send(draft, to: contact)
                    draft = ""
                }
                .disabled(draft.isEmpty || !isSecure)
            }
            .padding()
        }
        .navigationTitle(contact.displayName)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button("Safety #") { showSafetyNumber = true }
            }
        }
        .sheet(isPresented: $showSafetyNumber) {
            SafetyNumberSheet(number: session.safetyNumber(with: contact), name: contact.displayName)
        }
    }

    @ViewBuilder
    private var statusBanner: some View {
        HStack {
            Image(systemName: isSecure ? "lock.fill" : "lock.open")
            Text(isSecure ? "End-to-end encrypted" : "Establishing secure session…")
            Spacer()
        }
        .font(.footnote)
        .foregroundStyle(isSecure ? .green : .secondary)
        .padding(.horizontal)
        .padding(.vertical, 6)
        .background(.bar)
    }

    @ViewBuilder
    private func bubble(_ message: ChatMessage) -> some View {
        HStack {
            if message.mine { Spacer(minLength: 40) }
            Text(message.text)
                .padding(8)
                .background(message.mine ? Color.accentColor.opacity(0.25) : Color.gray.opacity(0.2))
                .clipShape(RoundedRectangle(cornerRadius: 10))
            if !message.mine { Spacer(minLength: 40) }
        }
    }
}

/// Shows the safety number two people compare in person to confirm no MITM.
private struct SafetyNumberSheet: View {
    let number: String
    let name: String
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    Text("Compare this with \(name) in person. If the numbers match on both devices, no one is intercepting your conversation.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                    Text(number)
                        .font(.title3.monospaced())
                        .multilineTextAlignment(.center)
                }
                .padding()
            }
            .navigationTitle("Safety Number")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
}
