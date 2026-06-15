//
//  ContentView.swift
//  Pigeon
//
//  Temporary Phase 3 test screen: shows this device's identity and exercises
//  the raw Bluetooth peer transport (no encryption yet). Replaced by the real
//  chat/contacts UI in Phase 6.
//

import SwiftUI

struct ContentView: View {
    @Environment(IdentityManager.self) private var identity
    @State private var transport = PeerTransport()
    @State private var draft = ""
    @State private var received: [String] = []

    var body: some View {
        NavigationStack {
            List {
                Section("This Device") {
                    LabeledContent("Fingerprint", value: identity.publicKey.shortFingerprint)
                        .font(.body.monospaced())
                }

                Section("Bluetooth") {
                    LabeledContent("Status", value: transport.status.rawValue)
                    LabeledContent("Connected peers", value: "\(transport.connectedPeerCount)")
                }

                Section("Send to nearby peers") {
                    HStack {
                        TextField("Message", text: $draft)
                        Button("Send") { send() }
                            .disabled(draft.isEmpty)
                    }
                }

                if !received.isEmpty {
                    Section("Received") {
                        ForEach(Array(received.enumerated()), id: \.offset) { _, line in
                            Text(line)
                        }
                    }
                }

                Section("Activity") {
                    ForEach(Array(transport.log.suffix(15).enumerated()), id: \.offset) { _, line in
                        Text(line).font(.caption.monospaced()).foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("Pigeon")
            .onAppear {
                transport.onMessage = { data, peer in
                    let text = String(data: data, encoding: .utf8) ?? "\(data.count) bytes"
                    received.append("\(peer.prefix(8)): \(text)")
                }
            }
        }
    }

    private func send() {
        transport.broadcast(Data(draft.utf8))
        received.append("me: \(draft)")
        draft = ""
    }
}
