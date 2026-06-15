//
//  RelaySettings.swift
//  Pigeon
//
//  Persistence for the user's configured relay endpoints. A relay URL is a
//  connection endpoint, not a secret (no key material), so it lives in
//  UserDefaults rather than the encrypted store. Relays are opt-in: with none
//  configured, Pigeon is fully serverless and only reaches peers over Bluetooth.
//

import Foundation

enum RelaySettings {
  private static let key = "pigeon.relay.urls"

  /// The configured relay endpoints (expected to be `wss://…`).
  static func urls() -> [URL] {
    (UserDefaults.standard.stringArray(forKey: key) ?? []).compactMap(URL.init(string:))
  }

  static func setURLs(_ urls: [URL]) {
    UserDefaults.standard.set(urls.map(\.absoluteString), forKey: key)
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
