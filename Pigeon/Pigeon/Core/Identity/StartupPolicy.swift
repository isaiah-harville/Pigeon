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

enum InstallationState: Equatable {
  case freshInstall
  case existingInstall
  case reinstallRecovery
  case missingIdentity
}

/// Pure startup policy for deciding whether a launch may read the identity and
/// start transports before the presence-gated vault is available.
enum StartupPolicy {

  static func installationState(
    hasContainerEvidence: Bool, hasKeychainIdentity: Bool
  ) -> InstallationState {
    switch (hasContainerEvidence, hasKeychainIdentity) {
    case (false, false): .freshInstall
    case (true, true): .existingInstall
    case (false, true): .reinstallRecovery
    case (true, false): .missingIdentity
    }
  }

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
