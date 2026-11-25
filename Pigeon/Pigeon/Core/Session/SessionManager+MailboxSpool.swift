//
//  SessionManager+MailboxSpool.swift
//  Pigeon
//
//  Drains envelopes the notification service extension moved from the relay
//  into the device spool while the app was not running (see `MailboxSpool`).
//

import Foundation

extension SessionManager {
  /// Applies every spooled envelope through the live inbound path and deletes
  /// each one only once it is durably consumed. Anything that needs a retry
  /// (persistence trouble, an identity move in progress) stays spooled for the
  /// next drain. Runs only while unlocked: before that the vault key is out of
  /// reach and the envelopes are safer left where they are.
  @discardableResult
  func drainMailboxSpool() -> Int { drainMailboxSpool(.shared) }

  @discardableResult
  func drainMailboxSpool(_ spool: MailboxSpool?) -> Int {
    guard isUnlocked, isPersistenceHealthy, !isIdentityMoveFrozen, let spool,
      let entries = try? spool.entries(), !entries.isEmpty
    else { return 0 }
    var consumed = 0
    for entry in entries {
      guard mesh.receiveSpooled(entry.data) == .consumed else { continue }
      spool.remove(entry)
      consumed += 1
    }
    return consumed
  }

  /// Mirrors what the extension needs to drain our mailbox. Called whenever
  /// our receiving relays, connectivity, or Background Delivery change.
  func publishSpoolConfiguration() {
    let receiving = (relay?.isEnabled ?? false) ? RelaySettings.urls() : []
    SharedMailboxConfig.publish(
      mailboxHex: myID.map { String(format: "%02x", $0) }.joined(),
      relayURLs: receiving,
      backgroundDeliveryEnabled: BackgroundDelivery.isEnabled)
  }
}
