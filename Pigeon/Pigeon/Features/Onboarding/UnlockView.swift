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
    content
      .padding()
  }

  private var content: some View {
    VStack(spacing: 24) {
      Spacer()
      Image(systemName: "lock.shield")
        .font(.system(size: 64))
        .foregroundStyle(.tint)
      Text("Pigeon")
        .font(.largeTitle.bold())
      Text(explanation)
        .font(.callout)
        .foregroundStyle(.secondary)
        .multilineTextAlignment(.center)
        .padding(.horizontal)

      Button {
        unlock()
      } label: {
        Label("Unlock", systemImage: "faceid")
          .frame(maxWidth: .infinity)
      }
      .buttonStyle(.borderedProminent)
      .disabled(unlocking)
      .padding(.horizontal, 40)

      if let error {
        Text(error).font(.footnote).foregroundStyle(.red)
      }
      Spacer()
    }
  }

  private var explanation: String {
    """
    Your messages are stored encrypted on this device. Unlock with Face ID or \
    Touch ID to continue.
    """
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
