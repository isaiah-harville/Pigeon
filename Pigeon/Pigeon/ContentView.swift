//
//  ContentView.swift
//  Pigeon
//

import SwiftUI

struct ContentView: View {
    @Environment(IdentityManager.self) private var identity

    var body: some View {
        NavigationStack {
            List {
                Section("This Device") {
                    LabeledContent("Fingerprint", value: identity.publicKey.shortFingerprint)
                        .font(.body.monospaced())
                }

                Section {
                    Text(identity.publicKey.rawRepresentation.base64EncodedString())
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                } header: {
                    Text("Public Identity Key")
                } footer: {
                    Text("Pigeon · offline encrypted mesh messaging. Identity, crypto, and transport are under construction.")
                }
            }
            .navigationTitle("Pigeon")
        }
    }
}

#Preview {
    // Preview can't access the real Keychain identity; this is illustrative.
    ContentView()
}
