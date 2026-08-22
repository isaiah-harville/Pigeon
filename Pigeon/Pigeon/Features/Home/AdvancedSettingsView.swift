//
//  AdvancedSettingsView.swift
//  Pigeon
//
//  Security and recovery controls that most people should not need day to day.
//

import SwiftUI

struct AdvancedSettingsView: View {
  @Environment(SessionManager.self) private var session
  @Environment(\.cleanSlateAction) private var cleanSlateAction

  @State private var receiveWhileLocked = true
  @State private var connectivityEnabled = true
  @State private var showCleanSlateConfirmation = false
  @State private var cleanSlateRunning = false
  @State private var cleanSlateError: String?

  var body: some View {
    List {
      faradaySection
      lockedDeliverySection
      cleanSlateSection
    }
    .navigationTitle("Advanced Settings")
    .navigationBarTitleDisplayMode(.inline)
    .onAppear {
      receiveWhileLocked = session.backgroundDeliveryEnabled
      connectivityEnabled = session.connectivityEnabled
    }
    .confirmationDialog(
      "Erase all local Pigeon data?",
      isPresented: $showCleanSlateConfirmation,
      titleVisibility: .visible
    ) {
      Button("Erase and rotate identity", role: .destructive) { runCleanSlate() }
      Button("Cancel", role: .cancel) {}
    } message: {
      Text("This permanently removes every message and contact. It cannot be undone.")
    }
    .alert(
      "Clean Slate failed",
      isPresented: Binding(
        get: { cleanSlateError != nil },
        set: { if !$0 { cleanSlateError = nil } })
    ) {
      Button("OK", role: .cancel) {}
    } message: {
      Text(cleanSlateError ?? "Pigeon did not complete the reset.")
    }
  }

  private var faradaySection: some View {
    Section {
      Toggle(isOn: $connectivityEnabled) {
        Label("Connectivity", systemImage: "antenna.radiowaves.left.and.right.slash")
      }
      .onChange(of: connectivityEnabled) { _, enabled in
        session.setConnectivityEnabled(enabled)
      }
    } header: {
      Text("Faraday")
    } footer: {
      Text("Turn off Bluetooth, local Wi-Fi discovery, and internet relays at once.")
    }
  }

  private var lockedDeliverySection: some View {
    Section {
      Toggle(isOn: $receiveWhileLocked) {
        Label("Receive while locked", systemImage: "bell.badge")
      }
      .onChange(of: receiveWhileLocked) { _, enabled in
        if !session.setBackgroundDeliveryEnabled(enabled) {
          receiveWhileLocked = session.backgroundDeliveryEnabled
        }
      }
    } footer: {
      Text(
        "Allows Pigeon to relaunch for new messages while your device is locked. "
          + "Notifications never include message content.")
    }
  }

  private var cleanSlateSection: some View {
    Section {
      Button(role: .destructive) {
      } label: {
        Label(
          cleanSlateRunning ? "Erasing…" : "Hold for Clean Slate",
          systemImage: "trash.slash"
        )
        .frame(maxWidth: .infinity, alignment: .leading)
      }
      .disabled(cleanSlateRunning)
      .onLongPressGesture(minimumDuration: 5) {
        showCleanSlateConfirmation = true
      }
    } header: {
      Text("Clean Slate")
    } footer: {
      Text(
        "Hold for 5 seconds, confirm, then authenticate. This deletes all messages "
          + "and contacts and creates a new long-term identity.")
    }
  }

  private func runCleanSlate() {
    cleanSlateRunning = true
    Task {
      do {
        try await cleanSlateAction.perform()
      } catch is VaultError {
        cleanSlateError = "Authentication was canceled. Nothing was reset."
      } catch CleanSlateError.recoveryStateFailed {
        cleanSlateError = "The reset did not start. Check device storage and try again."
      } catch CleanSlateError.identityRotationFailed {
        cleanSlateError = "Local data was erased, but identity rotation failed. Try again."
      } catch CleanSlateError.vaultRotationFailed {
        cleanSlateError = "Local data was erased, but storage key rotation failed. Try again."
      } catch CleanSlateError.serviceRestartFailed {
        cleanSlateError =
          "Local data was erased and identity rotated, but Pigeon could not restart. "
          + "Relaunch the app."
      } catch CleanSlateError.wipeFailed {
        cleanSlateError = "The reset could not finish. Pigeon is offline; try Clean Slate again."
      } catch {
        cleanSlateError = "Clean Slate could not finish. Try again."
      }
      cleanSlateRunning = false
    }
  }
}

struct CleanSlateAction {
  let perform: @MainActor () async throws -> Void
}

private struct CleanSlateActionKey: EnvironmentKey {
  static let defaultValue = CleanSlateAction {
    throw CleanSlateError.serviceRestartFailed
  }
}

extension EnvironmentValues {
  var cleanSlateAction: CleanSlateAction {
    get { self[CleanSlateActionKey.self] }
    set { self[CleanSlateActionKey.self] = newValue }
  }
}
