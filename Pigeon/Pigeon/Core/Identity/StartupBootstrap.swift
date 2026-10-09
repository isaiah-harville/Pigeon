import CryptoKit
import Foundation

#if os(iOS)
  import UIKit
#endif

/// Starts services only after the installation and any interrupted move are resolved.
@MainActor
enum StartupBootstrap {
  static func loadServices() -> StartupResult {
    loadServices(allowFirstLaunch: false)
  }

  static func loadServices(allowFirstLaunch: Bool) -> StartupResult {
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
    if let moveResult = recoverPendingMove(protectedDataAvailable: protectedDataAvailable) {
      return moveResult
    }
    if let installationResult = checkInstallation(
      protectedDataAvailable: protectedDataAvailable,
      allowFirstLaunch: allowFirstLaunch
    ) {
      return installationResult
    }

    return createServices(
      protectedDataAvailable: protectedDataAvailable,
      backgroundDeliveryEnabled: backgroundDeliveryEnabled)
  }

  private static func recoverPendingMove(protectedDataAvailable: Bool) -> StartupResult? {
    do {
      let stage = try IdentityMoveStage()
      guard stage.isPending else { return nil }
      guard protectedDataAvailable else { return waitingForUnlock() }
      if try stage.hasRetirementReceipt() {
        try stage.activate()
        return nil
      }
      return StartupResult(
        services: nil,
        errorMessage: "A device move is staged. Reconnect both phones to finish it.",
        stagedMove: true)
    } catch {
      return StartupResult(
        services: nil,
        errorMessage: "Pigeon could not recover the staged device move. Unlock and reopen Pigeon.")
    }
  }

  private static func checkInstallation(
    protectedDataAvailable: Bool, allowFirstLaunch: Bool
  ) -> StartupResult? {
    guard !IdentityManager.hasContainerEvidence else { return nil }
    guard protectedDataAvailable else { return waitingForUnlock() }
    do {
      let installationState = StartupPolicy.installationState(
        hasContainerEvidence: false,
        hasKeychainIdentity: try IdentityManager.storedIdentityExists())
      if installationState == .reinstallRecovery {
        return StartupResult(
          services: nil,
          errorMessage: "Pigeon found an identity from a previous installation, but its local "
            + "messages and session state are gone. Starting fresh creates a new identity.",
          reinstallRecovery: true)
      }
      if !allowFirstLaunch {
        return StartupResult(
          services: nil,
          errorMessage: "Start with a new identity or move one from your old phone.",
          firstLaunch: true)
      }
      return nil
    } catch {
      return StartupResult(
        services: nil,
        errorMessage: "Pigeon could not check its stored identity.")
    }
  }

  private static func createServices(
    protectedDataAvailable: Bool, backgroundDeliveryEnabled: Bool
  ) -> StartupResult {
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

  static func waitingForUnlock() -> StartupResult {
    StartupResult(
      services: nil,
      errorMessage: "Waiting for the device to unlock before loading identity keys.")
  }

  static func makeServices(identity: IdentityManager) -> AppServices {
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

  static func resumeCleanSlateIfNeeded() throws {
    let recovery = CleanSlateRecovery()
    guard recovery.isPending else { return }
    if try recovery.finishCleanupIfNeeded() { return }
    let targets = try recovery.targets()
    guard SessionPersistence.wipeDefaultStoreFamily() else {
      throw CleanSlateError.wipeFailed
    }
    CoreCheckpointStore.clearCheckpointEvidence()
    try CoreIdentityProvider.deleteStoredScopedKeys()
    let identity = try IdentityManager(creationPolicy: .existingOnly)
    try identity.replaceIdentity(with: targets.identitySeed)
    try Vault.replaceStoredKeyAfterCleanSlate(with: targets.vaultKey)
    IdentityManager.markContainerInitialized()
    try recovery.finish()
  }
}

struct StartupResult {
  let services: AppServices?
  let errorMessage: String?
  var reinstallRecovery = false
  var firstLaunch = false
  var stagedMove = false
}

struct AppServices {
  let identity: IdentityManager
  let session: SessionManager
  let notifier: MessageNotifier
}
