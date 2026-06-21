//
//  RelaySettings.swift
//  Pigeon
//
//  Persistence for the user's configured relay endpoints. A relay URL is a
//  connection endpoint, not a secret (no key material), so it lives in
//  UserDefaults rather than the encrypted store. The recommended relay is always
//  present; any relay (including it) can be enabled or disabled. Only *enabled*
//  relays are advertised in our QR card and used for delivery.
//

import Foundation

/// One configured relay: its endpoint and whether it's currently in use.
struct RelayEntry: Equatable, Hashable {
  var url: URL
  var enabled: Bool
}

enum RelaySettings {
  private static let key = "pigeon.relay.urls"
  private static let disabledKey = "pigeon.relay.disabled"
  private static let pushKey = "pigeon.relay.push"

  /// Whether APNs push wake-ups are enabled (**on by default**; the user can turn
  /// them off). When on, the app registers for remote notifications and binds its
  /// device token to its mailbox on the official relay so a suspended/terminated
  /// app gets woken to drain it. A deliberate privacy tradeoff — see
  /// SECURITY_MODEL §6.1. Defaults on by treating an unset value as `true`, so
  /// only an explicit opt-out turns it off.
  static var pushEnabled: Bool {
    get { UserDefaults.standard.object(forKey: pushKey) as? Bool ?? true }
    set { UserDefaults.standard.set(newValue, forKey: pushKey) }
  }

  static var recommendedURL: URL {
    guard let url = URL(string: "wss://relay.pigeonwire.app/ws") else {
      preconditionFailure("Invalid built-in relay URL")
    }
    return url
  }

  /// Every configured relay, in stored order. The recommended relay is always
  /// included (prepended if the user hasn't added it explicitly) and enabled
  /// unless the user has turned it off.
  static func entries() -> [RelayEntry] {
    let stored = (UserDefaults.standard.stringArray(forKey: key) ?? []).compactMap(
      URL.init(string:))
    let disabled = Set(UserDefaults.standard.stringArray(forKey: disabledKey) ?? [])
    var urls = stored
    if !urls.contains(recommendedURL) { urls.insert(recommendedURL, at: 0) }
    return urls.map { RelayEntry(url: $0, enabled: !disabled.contains($0.absoluteString)) }
  }

  /// The enabled relay endpoints — what we advertise and actually use. Falls back
  /// to the recommended relay when the user has disabled everything else but left
  /// it on (the recommended relay is always present in `entries()`).
  static func urls() -> [URL] {
    entries().filter(\.enabled).map(\.url)
  }

  /// Persists the full relay list (order + enabled flags).
  static func setEntries(_ entries: [RelayEntry]) {
    UserDefaults.standard.set(entries.map(\.url.absoluteString), forKey: key)
    let disabled = entries.filter { !$0.enabled }.map(\.url.absoluteString)
    UserDefaults.standard.set(disabled, forKey: disabledKey)
  }

  /// Whether `string` is a usable relay endpoint (a `ws`/`wss` URL with a host).
  static func isValidEndpoint(_ string: String) -> Bool {
    guard let url = URL(string: string.trimmingCharacters(in: .whitespaces)),
      let scheme = url.scheme?.lowercased(), scheme == "ws" || scheme == "wss",
      url.host?.isEmpty == false
    else { return false }
    return true
  }
}
