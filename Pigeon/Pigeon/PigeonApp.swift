//
//  PigeonApp.swift
//  Pigeon
//
//  Offline-capable, end-to-end-encrypted mesh messaging.
//

import SwiftUI

#if os(iOS)
  import Combine
  import UIKit
#endif

@main
struct PigeonApp: App {
  @Environment(\.scenePhase) private var scenePhase

  /// The device identity loads once at launch and is shared via the
  /// environment. It can fail on a background relaunch while the device is still
  /// locked (the identity keys aren't readable yet) — that's recoverable, not
  /// fatal, so we defer and retry rather than crash.
  @State private var services: AppServices?
  @State private var startupError: String?
  @State private var vault = Vault()

  init() {
    let startup = Self.loadServices()
    _services = State(initialValue: startup.services)
    _startupError = State(initialValue: startup.errorMessage)
  }

  var body: some Scene {
    WindowGroup {
      Group {
        if let services {
          ContentView()
            .environment(services.identity)
            .environment(services.session)
            .environment(vault)
        } else {
          StartupRecoveryView(message: startupError)
        }
      }
      .task { retryStartupIfNeeded() }
      .onChange(of: scenePhase) { _, phase in
        if phase == .active { retryStartupIfNeeded() }
        services?.session.setAppActive(phase == .active)
      }
      #if os(iOS)
        // A locked background launch couldn't read the keys; the moment the
        // device unlocks we can, so initialize then — even before foreground.
        .onReceive(
          NotificationCenter.default.publisher(
            for: UIApplication.protectedDataDidBecomeAvailableNotification)
        ) { _ in retryStartupIfNeeded() }
      #endif
    }
  }

  /// Builds the services once, if we don't already have them. Idempotent.
  private func retryStartupIfNeeded() {
    guard services == nil else { return }
    let startup = Self.loadServices()
    services = startup.services
    startupError = startup.errorMessage
  }

  private static func loadServices() -> StartupResult {
    #if os(iOS)
      guard UIApplication.shared.isProtectedDataAvailable else {
        return StartupResult(
          services: nil,
          errorMessage: "Waiting for the device to unlock before loading identity keys.")
      }
    #endif

    do {
      let identity = try IdentityManager()
      let session = SessionManager(identity: identity)
      let notifier = MessageNotifier()
      // Wire here (not in a view task): a background relaunch on a BLE/relay
      // event won't run view lifecycle, but must still post notifications.
      notifier.start()
      session.onIncomingNotification = { notifier.notifyIncomingMessage() }
      return StartupResult(
        services: AppServices(identity: identity, session: session, notifier: notifier),
        errorMessage: nil)
    } catch {
      return StartupResult(
        services: nil,
        errorMessage: "Pigeon could not load its device identity.")
    }
  }
}

private struct StartupResult {
  let services: AppServices?
  let errorMessage: String?
}

/// Bundles the services built once identity is available, so they move together.
private struct AppServices {
  let identity: IdentityManager
  let session: SessionManager
  let notifier: MessageNotifier
}

/// Shown when identity can't load yet (device still locked after a background
/// relaunch). Resolves automatically once the device unlocks.
private struct StartupRecoveryView: View {
  let message: String?

  var body: some View {
    VStack(spacing: 16) {
      Image(systemName: "lock.shield")
        .font(.system(size: 42, weight: .semibold))
        .foregroundStyle(.tint)
      Text("Pigeon is locked")
        .font(.title2.weight(.semibold))
      Text(message ?? "Unlock your device and open Pigeon again.")
        .font(.body)
        .foregroundStyle(.secondary)
        .multilineTextAlignment(.center)
    }
    .padding()
  }
}
