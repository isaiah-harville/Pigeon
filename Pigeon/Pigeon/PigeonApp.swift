//
//  PigeonApp.swift
//  Pigeon
//
//  Offline-capable, end-to-end-encrypted mesh messaging.
//

import CryptoKit
import SwiftUI

#if os(iOS)
  import Combine
  import UIKit
#endif

@main
struct PigeonApp: App {
  @Environment(\.scenePhase) private var scenePhase

  #if os(iOS)
    // Receives the APNs device token (opt-in push wake-ups) and forwards it to
    // `RemoteNotificationManager`; SwiftUI has no hook for these UIKit callbacks.
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
  #endif

  /// The device identity loads once at launch and is shared via the
  /// environment. It can fail on a background relaunch while the device is still
  /// locked (the identity keys aren't readable yet) — that's recoverable, not
  /// fatal, so we defer and retry rather than crash.
  @State private var services: AppServices?
  @State private var startupError: String?
  @State private var vault = Vault()

  /// A contact link tapped elsewhere on the device, held here rather than in
  /// `ContentView` because a link can arrive while identity is still loading and
  /// `ContentView` isn't in the hierarchy yet. `ContentView` presents it once the
  /// app is unlocked and past onboarding.
  @State private var pendingContactCode: String?

  init() {
    let startup = Self.loadServices()
    _services = State(initialValue: startup.services)
    _startupError = State(initialValue: startup.errorMessage)
  }

  var body: some Scene {
    WindowGroup {
      Group {
        if let services {
          ContentView(pendingContactCode: $pendingContactCode)
            .environment(services.identity)
            .environment(services.session)
            .environment(vault)
            .environment(\.cleanSlateAction, CleanSlateAction(perform: performCleanSlate))
        } else {
          StartupRecoveryView(message: startupError)
        }
      }
      .onOpenURL(perform: queueContactImport)
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

  /// Holds a tapped contact link for `ContentView` to present. Only a real
  /// contact card is kept; anything else on our scheme isn't ours to act on.
  /// Adding still needs an explicit confirmation in the sheet.
  private func queueContactImport(_ url: URL) {
    let code = url.absoluteString
    guard ContactCard(scanned: code) != nil else { return }
    pendingContactCode = code
  }

  /// Builds the services once, if we don't already have them. Idempotent.
  private func retryStartupIfNeeded() {
    guard services == nil else { return }
    let startup = Self.loadServices()
    services = startup.services
    startupError = startup.errorMessage
  }

  /// Authenticates again, retires the live service graph, wipes every sealed
  /// state file, rotates the identity, and starts fresh services under the new
  /// relay mailbox. The local display name and non-secret preferences remain.
  private func performCleanSlate() async throws {
    guard let current = services, vault.key != nil else {
      throw CleanSlateError.wipeFailed
    }
    try await vault.authorizeDestructiveAction(
      reason: "Erase Pigeon messages and rotate your identity")
    let displayName = current.session.myName
    let recovery = CleanSlateRecovery()
    if try recovery.finishCleanupIfNeeded() {
      guard let key = vault.key else { throw CleanSlateError.vaultRotationFailed }
      try rebuildServices(afterCleanSlateWith: key, displayName: displayName)
      return
    }
    try recovery.begin()
    let targets = try recovery.targets()
    try await current.session.prepareCleanSlate(identitySeed: targets.identitySeed) {
      try vault.replaceKeyAfterCleanSlate(with: targets.vaultKey)
    }
    try recovery.finish()
    guard let key = vault.key else { throw CleanSlateError.vaultRotationFailed }
    try rebuildServices(afterCleanSlateWith: key, displayName: displayName)
  }

  private func rebuildServices(afterCleanSlateWith key: SymmetricKey, displayName: String) throws {
    let startup = Self.loadServices()
    guard let replacement = startup.services else {
      services = nil
      startupError = startup.errorMessage
      throw CleanSlateError.serviceRestartFailed
    }
    do {
      try replacement.session.attachStore(EncryptedStore(key: key))
      replacement.session.setMyName(displayName)
    } catch {
      services = replacement
      startupError = "Pigeon erased its local state but could not restart it."
      throw CleanSlateError.serviceRestartFailed
    }
    services = replacement
    startupError = nil
  }

  private static func loadServices() -> StartupResult {
    #if os(iOS)
      let protectedDataAvailable = UIApplication.shared.isProtectedDataAvailable
    #else
      let protectedDataAvailable = true
    #endif

    let backgroundDeliveryEnabled = BackgroundDelivery.isEnabled
    guard
      StartupPolicy.shouldAttemptIdentityLoad(
        protectedDataAvailable: protectedDataAvailable,
        backgroundDeliveryEnabled: backgroundDeliveryEnabled)
    else { return waitingForUnlock() }

    do {
      try resumeCleanSlateIfNeeded()
    } catch {
      return StartupResult(
        services: nil,
        errorMessage: "Pigeon could not finish the pending Clean Slate reset.")
    }

    do {
      let identity = try IdentityManager(
        creationPolicy: StartupPolicy.identityCreationPolicy(
          protectedDataAvailable: protectedDataAvailable))
      let mode = StartupPolicy.mode(
        protectedDataAvailable: protectedDataAvailable,
        backgroundDeliveryEnabled: backgroundDeliveryEnabled,
        identityReadable: true)
      guard mode != .waitForUnlock else { return waitingForUnlock() }
      return StartupResult(
        services: makeServices(identity: identity),
        errorMessage: nil)
    } catch {
      if !protectedDataAvailable { return waitingForUnlock() }
      return StartupResult(
        services: nil,
        errorMessage: "Pigeon could not load its device identity.")
    }
  }

  private static func waitingForUnlock() -> StartupResult {
    StartupResult(
      services: nil,
      errorMessage: "Waiting for the device to unlock before loading identity keys.")
  }

  private static func makeServices(identity: IdentityManager) -> AppServices {
    let session = SessionManager(identity: identity)
    let notifier = MessageNotifier()
    // This cannot depend on view lifecycle: BLE or relay may relaunch the app.
    notifier.start()
    session.onIncomingNotification = { notifier.notifyIncomingMessage() }
    #if os(iOS)
      RemoteNotificationManager.shared.onToken = { [weak session] token in
        session?.relay?.setPushToken(token)
      }
      if RelaySettings.pushEnabled { RemoteNotificationManager.shared.enable() }
    #endif
    return AppServices(identity: identity, session: session, notifier: notifier)
  }

  private static func resumeCleanSlateIfNeeded() throws {
    let recovery = CleanSlateRecovery()
    guard recovery.isPending else { return }
    if try recovery.finishCleanupIfNeeded() { return }
    let targets = try recovery.targets()
    guard SessionPersistence.wipeDefaultStoreFamily() else {
      throw CleanSlateError.wipeFailed
    }
    let identity = try IdentityManager(creationPolicy: .existingOnly)
    try identity.replaceIdentity(with: targets.identitySeed)
    try Vault.replaceStoredKeyAfterCleanSlate(with: targets.vaultKey)
    try recovery.finish()
  }
}

private struct StartupResult {
  let services: AppServices?
  let errorMessage: String?
}

#if os(iOS)
  /// Bridges UIKit's remote-notification registration callbacks (which SwiftUI
  /// doesn't surface) to `RemoteNotificationManager`. Only used when the user
  /// opts into push wake-ups.
  final class AppDelegate: NSObject, UIApplicationDelegate {
    func application(
      _: UIApplication,
      didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data
    ) {
      Task { @MainActor in RemoteNotificationManager.shared.didRegister(tokenData: deviceToken) }
    }

    func application(
      _: UIApplication,
      didFailToRegisterForRemoteNotificationsWithError error: Error
    ) {
      Task { @MainActor in RemoteNotificationManager.shared.didFail(error) }
    }
  }
#endif

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
