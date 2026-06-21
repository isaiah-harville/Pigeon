//
//  RemoteNotificationManager.swift
//  Pigeon
//
//  Opt-in APNs registration for relay push wake-ups. Unlike `MessageNotifier`
//  (which posts purely local notifications for BLE/relay messages the running
//  app already received), this asks APNs for a device token and hands it to the
//  relay so the *official* relay's gateway can wake a suspended or terminated
//  app. The push itself is content-free — it only prompts the user to open the
//  app; the message is then drained and decrypted through the existing pipeline.
//  No content ever traverses Apple. Off by default; see SECURITY_MODEL §6.1.
//

#if os(iOS)
  import UIKit
  import UserNotifications

  @MainActor
  final class RemoteNotificationManager {
    static let shared = RemoteNotificationManager()

    /// The current APNs device token (lowercase hex), or nil when we have none
    /// (not yet registered, or opted out).
    private(set) var deviceToken: String?

    /// Delivers the device token (or nil when cleared) to whoever owns the relay.
    /// Assigning it immediately replays the current token, so wiring set up after
    /// the token already arrived still gets it.
    var onToken: ((String?) -> Void)? {
      didSet { onToken?(deviceToken) }
    }

    private init() {}

    /// Opt in: ensure notification authorization, then register for remote
    /// notifications so APNs issues a device token (delivered via the AppDelegate
    /// callbacks below). Safe to call repeatedly.
    func enable() {
      let center = UNUserNotificationCenter.current()
      center.requestAuthorization(options: [.alert, .sound, .badge]) { granted, _ in
        guard granted else { return }
        Task { @MainActor in UIApplication.shared.registerForRemoteNotifications() }
      }
    }

    /// Opt out: clear the token from the relay and stop receiving pushes. The
    /// relay-side token is removed by the relay setter seeing a nil token; here
    /// we also tell the OS to stop delivering APNs tokens to us.
    func disable() {
      deviceToken = nil
      onToken?(nil)
      UIApplication.shared.unregisterForRemoteNotifications()
    }

    /// APNs delivered a device token: hex-encode and publish it to the relay.
    func didRegister(tokenData: Data) {
      let hex = tokenData.map { String(format: "%02x", $0) }.joined()
      deviceToken = hex
      onToken?(hex)
    }

    /// APNs registration failed. We keep any prior token and never log token
    /// bytes; the app simply falls back to best-effort background reception.
    func didFail(_: Error) {}
  }
#endif
