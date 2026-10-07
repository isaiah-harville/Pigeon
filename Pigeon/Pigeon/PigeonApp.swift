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
    // Receives the APNs device token (push wake-ups are enabled by default) and forwards it to
    // `RemoteNotificationManager`; SwiftUI has no hook for these UIKit callbacks.
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
  #endif

  /// The device identity loads once at launch and is shared via the
  /// environment. It can fail on a background relaunch while the device is still
  /// locked (the identity keys aren't readable yet) — that's recoverable, not
  /// fatal, so we defer and retry rather than crash.
  @State private var services: AppServices?
  @State private var startupError: String?
  @State private var requiresReinstallRecovery = false
  @State private var offersFirstLaunch = false
  @State private var hasStagedMove = false
  @State private var moveDisplayName = ""
  @State private var vault = Vault()

  /// A contact link tapped elsewhere on the device, held here rather than in
  /// `ContentView` because a link can arrive while identity is still loading and
  /// `ContentView` isn't in the hierarchy yet. `ContentView` presents it once the
  /// app is unlocked and past onboarding.
  @State private var pendingContactCode: String?
  @State private var pendingGroupInviteCode: String?

  init() {
    let startup = StartupBootstrap.loadServices()
    _services = State(initialValue: startup.services)
    _startupError = State(initialValue: startup.errorMessage)
    _requiresReinstallRecovery = State(initialValue: startup.reinstallRecovery)
    _offersFirstLaunch = State(initialValue: startup.firstLaunch)
    _hasStagedMove = State(initialValue: startup.stagedMove)
  }

  var body: some Scene {
    WindowGroup {
      rootContent
        .screenCaptureShield()
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
          .onReceive(
            NotificationCenter.default.publisher(
              for: UIApplication.userDidTakeScreenshotNotification)
          ) { _ in services?.session.reportScreenshotTaken() }
        #endif
    }
  }

  @ViewBuilder
  private var rootContent: some View {
    if let services {
      ContentView(
        pendingContactCode: $pendingContactCode,
        pendingGroupInviteCode: $pendingGroupInviteCode
      )
      .environment(services.identity)
      .environment(services.session)
      .environment(vault)
      .environment(\.cleanSlateAction, CleanSlateAction(perform: performCleanSlate))
      .environment(
        \.identityMoveAction,
        IdentityMoveAction(
          retireSource: retireSourceForMove, completeSource: completeSourceMove))
    } else {
      StartupRecoveryView(
        message: startupError,
        reinstallRecovery: requiresReinstallRecovery,
        firstLaunch: offersFirstLaunch,
        stagedMove: hasStagedMove,
        startFresh: requiresReinstallRecovery
          ? performReinstallFreshStart : beginFirstLaunch,
        moveCompleted: retryStartupIfNeeded,
        discardMove: discardStagedMove)
    }
  }

  /// Holds a tapped contact link for `ContentView` to present. Only a real
  /// contact card is kept; anything else on our scheme isn't ours to act on.
  /// Adding still needs an explicit confirmation in the sheet.
  private func queueContactImport(_ url: URL) {
    let code = url.absoluteString
    if ContactCard(scanned: code) != nil {
      pendingContactCode = code
    } else if GroupInviteLink(scanned: code) != nil {
      pendingGroupInviteCode = code
    }
  }

  /// Builds the services once, if we don't already have them. Idempotent.
  private func retryStartupIfNeeded() {
    guard services == nil else { return }
    let startup = StartupBootstrap.loadServices()
    services = startup.services
    startupError = startup.errorMessage
    requiresReinstallRecovery = startup.reinstallRecovery
    offersFirstLaunch = startup.firstLaunch
    hasStagedMove = startup.stagedMove
  }

  private func beginFirstLaunch() throws {
    guard services == nil, offersFirstLaunch else {
      throw CleanSlateError.recoveryStateFailed
    }
    try CoreIdentityProvider.deleteStoredScopedKeys()
    let startup = StartupBootstrap.loadServices(allowFirstLaunch: true)
    services = startup.services
    startupError = startup.errorMessage
    offersFirstLaunch = startup.firstLaunch
    guard services != nil else { throw CleanSlateError.serviceRestartFailed }
  }

  private func discardStagedMove() async throws {
    guard services == nil, hasStagedMove else {
      throw IdentityMoveStage.StageError.invalidState
    }
    try await vault.authorizeDestructiveAction(
      reason: "Discard the staged Pigeon device move")
    try IdentityMoveStage().discardUnretired()
    hasStagedMove = false
    offersFirstLaunch = true
    startupError = "The staged move was discarded. Start with a new identity."
  }

  private func retireSourceForMove() async throws {
    guard let current = services, vault.key != nil else {
      throw CleanSlateError.wipeFailed
    }
    moveDisplayName = current.session.myName
    try await retireCurrentIdentity(current)
  }

  private func completeSourceMove() {
    guard let key = vault.key else {
      services = nil
      startupError = "The old phone retired its identity. Reopen Pigeon to finish setup."
      return
    }
    do {
      try rebuildServices(afterCleanSlateWith: key, displayName: moveDisplayName)
    } catch {
      services = nil
      startupError = "The old phone retired its identity. Reopen Pigeon to finish setup."
    }
  }

  private func performReinstallFreshStart() async throws {
    guard services == nil, requiresReinstallRecovery else {
      throw CleanSlateError.recoveryStateFailed
    }
    try await vault.authorizeDestructiveAction(
      reason: "Remove the identity left by the previous Pigeon installation")
    let recovery = CleanSlateRecovery()
    try recovery.begin()
    try StartupBootstrap.resumeCleanSlateIfNeeded()
    let startup = StartupBootstrap.loadServices()
    services = startup.services
    startupError = startup.errorMessage
    requiresReinstallRecovery = startup.reinstallRecovery
    guard services != nil else { throw CleanSlateError.serviceRestartFailed }
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
    try await retireCurrentIdentity(current)
    guard let key = vault.key else { throw CleanSlateError.vaultRotationFailed }
    try rebuildServices(afterCleanSlateWith: key, displayName: displayName)
  }

  private func retireCurrentIdentity(_ current: AppServices) async throws {
    let recovery = CleanSlateRecovery()
    try recovery.begin()
    let targets = try recovery.targets()
    try await current.session.prepareCleanSlate(identitySeed: targets.identitySeed) {
      try vault.replaceKeyAfterCleanSlate(with: targets.vaultKey)
    }
    try recovery.finish()
  }

  private func rebuildServices(afterCleanSlateWith key: SymmetricKey, displayName: String) throws {
    let startup = StartupBootstrap.loadServices()
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

/// Shown when identity can't load yet (device still locked after a background
/// relaunch). Resolves automatically once the device unlocks.
private struct StartupRecoveryView: View {
  let message: String?
  let reinstallRecovery: Bool
  let firstLaunch: Bool
  let stagedMove: Bool
  let startFresh: @MainActor () async throws -> Void
  let moveCompleted: @MainActor () -> Void
  let discardMove: @MainActor () async throws -> Void

  @State private var isStartingFresh = false
  @State private var freshStartError: String?
  @State private var showMove = false
  @State private var showDiscardMove = false

  var body: some View {
    VStack(spacing: 16) {
      Image(systemName: "lock.shield")
        .font(.system(size: 42, weight: .semibold))
        .foregroundStyle(.tint)
      Text(
        reinstallRecovery
          ? "Previous installation found"
          : (firstLaunch || stagedMove ? "Set up Pigeon" : "Pigeon is locked")
      )
      .font(.title2.weight(.semibold))
      Text(message ?? "Unlock your device and open Pigeon again.")
        .font(.body)
        .foregroundStyle(.secondary)
        .multilineTextAlignment(.center)
      recoveryActions
      if let freshStartError {
        Text(freshStartError).font(.footnote).foregroundStyle(.red)
      }
    }
    .sheet(isPresented: $showMove) {
      IdentityMoveView(
        mode: .destination, sourceSession: nil,
        action: IdentityMoveAction(
          retireSource: { throw IdentityMoveStage.StageError.unavailable },
          completeSource: moveCompleted))
    }
    .confirmationDialog(
      "Discard this move?",
      isPresented: $showDiscardMove,
      titleVisibility: .visible
    ) {
      Button("Discard staged identity", role: .destructive) {
        Task {
          do { try await discardMove() } catch {
            freshStartError = "The staged move could not be discarded."
          }
        }
      }
    } message: {
      Text(
        "If the old phone has already retired, this permanently loses the staged identity "
          + "and group access.")
    }
    .padding()
  }

  @ViewBuilder
  private var recoveryActions: some View {
    if reinstallRecovery || firstLaunch {
      Button("Start with a new identity") {
        isStartingFresh = true
        freshStartError = nil
        Task {
          do { try await startFresh() } catch {
            freshStartError = "Pigeon could not finish the fresh start. Try again."
          }
          isStartingFresh = false
        }
      }
      .disabled(isStartingFresh)
    }
    if firstLaunch || stagedMove {
      Button(stagedMove ? "Reconnect old phone" : "Receive from old phone") {
        showMove = true
      }
      .buttonStyle(.borderedProminent)
    }
    if stagedMove {
      Button("Discard move and start fresh", role: .destructive) {
        showDiscardMove = true
      }
    }
  }
}
