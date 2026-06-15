//
//  AddContactView.swift
//  Pigeon
//
//  Scan (iOS) or paste (macOS) a peer's QR card to add them. The contact's
//  name comes from their card; it can be edited later in the chat.
//

import SwiftUI

struct AddContactView: View {
    @Environment(SessionManager.self) private var session
    @Environment(\.dismiss) private var dismiss

    @State private var pasted = ""
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                #if os(iOS)
                Section("Scan their QR code") {
                    QRScanner { code in handle(code) }
                        .frame(height: 300)
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                        .listRowInsets(EdgeInsets())
                }
                #endif

                Section("Or paste their code") {
                    TextField("Pigeon contact code", text: $pasted, axis: .vertical)
                        .lineLimit(2...4)
                        .font(.caption.monospaced())
                    Button("Add Contact") { handle(pasted) }
                        .disabled(pasted.isEmpty)
                }

                if let error {
                    Section { Text(error).foregroundStyle(.red) }
                }
            }
            .navigationTitle("Add Contact")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }

    private func handle(_ code: String) {
        guard let card = ContactCard(scanned: code) else {
            error = "That isn't a valid Pigeon contact code."
            return
        }
        let name = card.name.isEmpty ? "Unnamed" : card.name
        if session.addContact(card.bundle, name: name) {
            dismiss()
        } else {
            error = "Couldn't add this contact (invalid binding, or it's your own code)."
        }
    }
}
