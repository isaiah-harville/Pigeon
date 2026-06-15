//
//  AddContactView.swift
//  Pigeon
//
//  Scan (iOS) or paste (macOS) a peer's identity code to add them as a
//  verified contact.
//

import SwiftUI
import PigeonCrypto

struct AddContactView: View {
    @Environment(SessionManager.self) private var session
    @Environment(\.dismiss) private var dismiss

    @State private var name = ""
    @State private var pasted = ""
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Section("Their name") {
                    TextField("e.g. Alice", text: $name)
                }

                #if os(iOS)
                Section("Scan their QR code") {
                    QRScanner { code in handle(code) }
                        .frame(height: 280)
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                        .listRowInsets(EdgeInsets())
                }
                #endif

                Section("Or paste their code") {
                    TextField("Pigeon identity code", text: $pasted, axis: .vertical)
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
        let trimmed = code.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let data = Data(base64Encoded: trimmed),
              let bundle = try? IdentityBundle(decoding: data) else {
            error = "That isn't a valid Pigeon identity code."
            return
        }
        if session.addContact(bundle, name: name.isEmpty ? "Peer" : name) {
            dismiss()
        } else {
            error = "Couldn't add this contact (invalid binding, or it's your own code)."
        }
    }
}
