import Foundation
import PigeonFFI

extension SessionManager {
  func confirmGroupRelayAuthorization(groupID: Data, capabilityID: Data) -> Bool {
    guard isUnlocked, isPersistenceHealthy else { return false }
    do {
      try executeCore(
        PigeonCoreCommand(
          id: Self.coreCommandID(
            "confirm-group-relay", "\(groupID.hexEncoded):\(capabilityID.hexEncoded)"),
          body: .confirmGroupRelayAuthorization(
            PigeonConfirmGroupRelayAuthorization(
              groupID: groupID, capabilityID: capabilityID))))
      return true
    } catch {
      return false
    }
  }
}
