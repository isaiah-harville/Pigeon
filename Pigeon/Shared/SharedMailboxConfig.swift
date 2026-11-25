//
//  SharedMailboxConfig.swift
//  Pigeon (shared with PigeonNotificationService)
//
//  The few non-secret facts the notification service extension needs to drain
//  the mailbox while the app is not running: our mailbox address (the public
//  identity key), the relays we receive on, and whether the user allows
//  background delivery. The app mirrors them into the app-group defaults
//  whenever they change. Private keys are never stored here; the extension
//  reads the identity seed from the shared Keychain access group, under the
//  accessibility class the user's Background Delivery choice already set.
//

import Foundation

nonisolated enum SharedMailboxConfig {
  static let appGroup = "group.com.isaiah-harville.Pigeon"

  /// Keychain coordinates of the root identity seed (see `IdentityManager`).
  static let keychainService = "com.isaiah-harville.Pigeon.keys"
  static let identityAccount = "identity.ed25519.private"
  /// Info.plist key carrying `$(AppIdentifierPrefix)com.isaiah-harville.Pigeon`,
  /// the app's default Keychain access group, which both targets share.
  static let keychainAccessGroupInfoKey = "PigeonKeychainAccessGroup"

  private static let mailboxKey = "pigeon.spool.mailbox"
  private static let relaysKey = "pigeon.spool.relays"
  private static let enabledKey = "pigeon.spool.enabled"

  struct Snapshot: Equatable, Sendable {
    let mailboxHex: String
    let relayURLs: [URL]
    let backgroundDeliveryEnabled: Bool
  }

  private static var defaults: UserDefaults? { UserDefaults(suiteName: appGroup) }

  /// Called by the app whenever its receiving relays or the Background
  /// Delivery preference change. Empty relays mean "do not drain".
  static func publish(mailboxHex: String, relayURLs: [URL], backgroundDeliveryEnabled: Bool) {
    guard let defaults else { return }
    defaults.set(mailboxHex, forKey: mailboxKey)
    defaults.set(relayURLs.map(\.absoluteString), forKey: relaysKey)
    defaults.set(backgroundDeliveryEnabled, forKey: enabledKey)
  }

  static func setBackgroundDeliveryEnabled(_ enabled: Bool) {
    defaults?.set(enabled, forKey: enabledKey)
  }

  static func load() -> Snapshot? {
    guard let defaults,
      let mailboxHex = defaults.string(forKey: mailboxKey),
      mailboxHex.count == 64
    else { return nil }
    let relays = (defaults.stringArray(forKey: relaysKey) ?? []).compactMap(URL.init(string:))
      .filter { ["ws", "wss"].contains($0.scheme?.lowercased() ?? "") }
    return Snapshot(
      mailboxHex: mailboxHex,
      relayURLs: relays,
      backgroundDeliveryEnabled: defaults.bool(forKey: enabledKey))
  }
}
