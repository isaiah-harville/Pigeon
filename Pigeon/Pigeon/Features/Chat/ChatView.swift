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
                .disabled(draft.isEmpty)
            }
            .padding()
        }
        .navigationTitle(contact.displayName)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Menu {
                    Toggle(isOn: ephemeralBinding) {
                        Label("Ephemeral chat", systemImage: "clock.arrow.circlepath")
                    }
                    Button {
                        showSafetyNumber = true
                    } label: {
                        Label("Safety number", systemImage: "checkmark.shield")
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
            }
        }
        .sheet(isPresented: $showSafetyNumber) {
            SafetyNumberSheet(number: session.safetyNumber(with: contact), name: contact.displayName)
        }
    }

    private var ephemeralBinding: Binding<Bool> {
        Binding(
            get: { session.isEphemeral(contact) },
            set: { session.setEphemeral($0, for: contact) }
        )
    }

    @ViewBuilder
    private var statusBanner: some View {
        HStack(spacing: 6) {
            Image(systemName: isSecure ? "lock.fill" : "lock.open")
            Text(isSecure ? "End-to-end encrypted" : "Establishing secure session…")
            Spacer()
            if session.isEphemeral(contact) {
                Label("Ephemeral", systemImage: "clock.arrow.circlepath")
                    .foregroundStyle(.orange)
            }
        }
        .font(.footnote)
        .foregroundStyle(isSecure ? .green : .secondary)
        .padding(.horizontal)
        .padding(.vertical, 6)
        .background(.bar)
    }

    @ViewBuilder
    private func bubble(_ message: ChatMessage) -> some View {
        HStack(alignment: .bottom, spacing: 4) {
            if message.mine { Spacer(minLength: 40) }
            Text(message.text)
                .padding(8)
                .background(message.mine ? Color.accentColor.opacity(0.25) : Color.gray.opacity(0.2))
                .clipShape(RoundedRectangle(cornerRadius: 10))
                .opacity(message.pending ? 0.6 : 1)
            if message.mine {
                if message.pending {
                    Image(systemName: "clock")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            } else {
                Spacer(minLength: 40)
            }
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
