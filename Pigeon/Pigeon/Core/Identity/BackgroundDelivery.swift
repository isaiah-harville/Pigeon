//
//  BackgroundDelivery.swift
//  Pigeon
//
//  User preference: may Pigeon receive messages while the device is locked?
//
//  When enabled, the long-term identity keys are stored with `afterFirstUnlock`
//  accessibility so a locked background relaunch can read them, authenticate to
//  the relay, and post a "new message" notification (the message itself stays
//  sealed until the user unlocks). When disabled, keys revert to the stricter
//  `whenUnlocked` and background delivery stops.
//
//  On by default: most users want notifications, and the at-rest exposure is a
//  hard, narrow attack vector. The privacy-conscious can opt out.
//

import Foundation

enum BackgroundDelivery {
  private static let key = "pigeon.background.delivery"

  static var isEnabled: Bool {
    get { UserDefaults.standard.object(forKey: key) as? Bool ?? true }
    set { UserDefaults.standard.set(newValue, forKey: key) }
  }

  /// The keychain accessibility the current preference implies.
  static var accessibility: KeychainAccessibility {
    isEnabled ? .afterFirstUnlock : .whenUnlocked
  }
}
