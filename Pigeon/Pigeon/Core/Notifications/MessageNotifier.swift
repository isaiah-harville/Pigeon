//
//  MessageNotifier.swift
//  Pigeon
//
//  Local notifications for incoming messages. There is no server, so these are
//  posted by the app itself when a message arrives over Bluetooth — no remote
//  push, nothing routed through Apple. For privacy the notification reveals no
//  content or sender: it only prompts the user to open the app.
//

import Foundation
import UserNotifications

@MainActor
final class MessageNotifier: NSObject {
  private let center = UNUserNotificationCenter.current()

  /// Sets up the delegate and asks for permission (no-op if already decided).
  func start() {
    center.delegate = self
    center.requestAuthorization(options: [.alert, .sound, .badge]) { _, _ in }
  }

  /// Posts a content-free local notification prompting the user to open the app.
  func notifyIncomingMessage() {
    let content = UNMutableNotificationContent()
    content.title = "New message"
    content.body = "Open Pigeon to read your message."
    content.sound = .default
    // nil trigger => deliver immediately.
    let request = UNNotificationRequest(
      identifier: UUID().uuidString, content: content, trigger: nil)
    center.add(request)
  }
}

extension MessageNotifier: UNUserNotificationCenterDelegate {
  // Show the banner even when the app is in the foreground (in-app notice).
  nonisolated func userNotificationCenter(
    _ center: UNUserNotificationCenter,
    willPresent notification: UNNotification,
    withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
  ) {
    completionHandler([.banner, .sound, .list])
  }
}
