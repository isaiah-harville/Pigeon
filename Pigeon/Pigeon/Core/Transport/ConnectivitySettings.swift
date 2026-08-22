//
//  ConnectivitySettings.swift
//  Pigeon
//
//  Persists the Faraday switch that disables every network transport.
//

import Foundation

enum ConnectivitySettings {
  private static let key = "pigeon.connectivity.enabled"

  static var isEnabled: Bool { isEnabled(in: .standard) }

  static func isEnabled(in defaults: UserDefaults) -> Bool {
    defaults.object(forKey: key) as? Bool ?? true
  }

  static func setEnabled(_ enabled: Bool) {
    setEnabled(enabled, in: .standard)
  }

  static func setEnabled(_ enabled: Bool, in defaults: UserDefaults) {
    defaults.set(enabled, forKey: key)
  }
}
