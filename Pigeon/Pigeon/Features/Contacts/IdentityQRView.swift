//
//  IdentityQRView.swift
//  Pigeon
//
//  Shows this device's identity as a QR code for a peer to scan in person.
//

import SwiftUI
import PigeonCrypto

struct IdentityQRView: View {
    @Environment(SessionManager.self) private var session
    @Environment(IdentityManager.self) private var identity

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                QRCode.image(from: session.myBundle.encoded().base64EncodedString())
                    .frame(maxWidth: 280, maxHeight: 280)
                    .padding()

                Text("Fingerprint")
                    .font(.headline)
                Text(identity.publicKey.shortFingerprint)
                    .font(.body.monospaced())

                Text("Have the other person scan this in Add Contact, then compare your safety numbers before trusting the chat.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
            }
            .padding()
        }
        .navigationTitle("My Identity")
    }
}
