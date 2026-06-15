//
//  UnlockView.swift
//  Pigeon
//
//  Gate shown until the user unlocks encrypted storage (Face ID / Touch ID) or
//  chooses ephemeral mode (no history saved).
//

import SwiftUI

struct UnlockView: View {
    @Environment(Vault.self) private var vault
    @Environment(SessionManager.self) private var session

    @State private var unlocking = false
    @State private var error: String?

    var body: some View {
        VStack(spacing: 24) {
            Spacer()
            Image(systemName: "lock.shield")
                .font(.system(size: 64))
                .foregroundStyle(.tint)
            Text("Pigeon")
                .font(.largeTitle.bold())
            Text("Your messages are stored encrypted on this device. Unlock to continue, or use ephemeral mode to keep nothing on disk.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)

            VStack(spacing: 12) {
                Button {
                    unlock()
                } label: {
                    Label("Unlock", systemImage: "faceid")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .disabled(unlocking)

                Button("Use ephemeral mode") {
                    session.useEphemeralMode()
                }
                .disabled(unlocking)
            }
            .padding(.horizontal, 40)

            if let error {
                Text(error).font(.footnote).foregroundStyle(.red)
            }
            Spacer()
        }
        .padding()
    }

    private func unlock() {
        unlocking = true
        error = nil
        Task {
            do {
                try await vault.unlock()
                guard let key = vault.key else { throw VaultError.authenticationFailed }
                session.attachStore(EncryptedStore(key: key))
            } catch {
                self.error = "Couldn't unlock. Please try again."
            }
            unlocking = false
        }
    }
}
