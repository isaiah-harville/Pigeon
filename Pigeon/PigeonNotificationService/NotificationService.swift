//
//  NotificationService.swift
//  PigeonNotificationService
//
//  Runs on every relay wake-up push (`mutable-content`). It drains the
//  still-encrypted mailbox into the device spool so the relay can release its
//  copy while the phone is locked, then shows the relay's fixed, content-free
//  alert unchanged. Decryption happens only in the app, after unlock.
//

import Foundation
import UserNotifications

final class NotificationService: UNNotificationServiceExtension {
  /// iOS allows roughly 30 seconds; leave headroom to deliver the alert.
  private static let drainBudget: Duration = .seconds(20)

  private var contentHandler: ((UNNotificationContent) -> Void)?
  private var content: UNNotificationContent?
  private var work: Task<Void, Never>?

  override func didReceive(
    _ request: UNNotificationRequest,
    withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void
  ) {
    self.contentHandler = contentHandler
    content = request.content
    let deadline = ContinuousClock.now + Self.drainBudget
    work = Task { [weak self] in
      await Self.drain(until: deadline)
      await MainActor.run { self?.finish() }
    }
  }

  override func serviceExtensionTimeWillExpire() {
    work?.cancel()
    finish()
  }

  private func finish() {
    guard let contentHandler, let content else { return }
    self.contentHandler = nil
    contentHandler(content)
  }

  private static func drain(until deadline: ContinuousClock.Instant) async {
    guard let config = SharedMailboxConfig.load(),
      config.backgroundDeliveryEnabled,
      !config.relayURLs.isEmpty,
      let spool = MailboxSpool.shared,
      let key = SharedIdentityKey.load(),
      key.publicKey.rawRepresentation.map({ String(format: "%02x", $0) }).joined()
        == config.mailboxHex
    else { return }
    _ = await MailboxDrainer(spool: spool, config: config, signingKey: key).drain(until: deadline)
  }
}
