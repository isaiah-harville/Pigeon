//
//  StartupPolicy.swift
//  Pigeon
//

import Foundation

enum StartupMode: Equatable {
  case unlocked
  case lockedTransportOnly
  case waitForUnlock
}

/// Pure startup policy for deciding whether a launch may read the identity and
/// start transports before the presence-gated vault is available.
enum StartupPolicy {

  static func identityCreationPolicy(
    protectedDataAvailable: Bool
  ) -> IdentityCreationPolicy {
    protectedDataAvailable ? .allowCreation : .existingOnly
  }

  static func shouldAttemptIdentityLoad(
    protectedDataAvailable: Bool, backgroundDeliveryEnabled: Bool
  ) -> Bool {
    protectedDataAvailable || backgroundDeliveryEnabled
  }

  static func mode(
    protectedDataAvailable: Bool, backgroundDeliveryEnabled: Bool,
    identityReadable: Bool
  ) -> StartupMode {
    if protectedDataAvailable { return identityReadable ? .unlocked : .waitForUnlock }
    guard backgroundDeliveryEnabled, identityReadable else { return .waitForUnlock }
    return .lockedTransportOnly
  }
}
