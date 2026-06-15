//
//  PigeonApp.swift
//  Pigeon
//
//  Fully-offline, end-to-end-encrypted Bluetooth mesh messaging.
//

import SwiftUI

@main
struct PigeonApp: App {
  /// The device identity is loaded once at launch and shared via the
  /// environment. Failure here is fatal — without an identity the app
  /// cannot encrypt, sign, or be addressed.
  @Environment(\.scenePhase) private var scenePhase

  @State private var identity: IdentityManager
  @State private var session: SessionManager
  @State private var vault = Vault()
  @State private var notifier = MessageNotifier()

  init() {
    do {
      let identity = try IdentityManager()
      let session = SessionManager(identity: identity)
      let notifier = MessageNotifier()
      // Wire here (not in a view task): a background relaunch on a BLE
      // event won't run view lifecycle, but must still post notifications.
      notifier.start()
      session.onIncomingNotification = { notifier.notifyIncomingMessage() }
      _identity = State(initialValue: identity)
      _session = State(initialValue: session)
      _notifier = State(initialValue: notifier)
    } catch {
      fatalError("Failed to initialize device identity: \(error)")
    }
  }

  var body: some Scene {
    WindowGroup {
      ContentView()
        .environment(identity)
        .environment(session)
        .environment(vault)
        .onChange(of: scenePhase) { _, phase in
          session.setAppActive(phase == .active)
        }
    }
  }
}
