import CryptoKit
import Foundation
import PigeonFFI

extension SessionManager {
  enum GroupRecoveryError: Error, Equatable {
    case inactiveGroup
    case unauthorized
    case invalidRelay
    case invalidCoordinatorKey
  }

  /// Starts an authenticated coordinator/relay recovery. Quorum collection,
  /// MLS state changes, and capability rotation remain transactional in core.
  @discardableResult
  func recoverGroup(
    _ group: PigeonGroupState,
    using replacementRelayURL: URL
  ) async throws -> PigeonCoreOutput {
    guard !group.dissolved, group.memberIdentities.contains(myID) else {
      throw GroupRecoveryError.inactiveGroup
    }
    guard group.adminIdentities.contains(myID) else {
      throw GroupRecoveryError.unauthorized
    }
    guard let scheme = replacementRelayURL.scheme?.lowercased(),
      scheme == "https" || scheme == "wss",
      GroupRelayTransport.endpoint(for: replacementRelayURL) != nil
    else { throw GroupRecoveryError.invalidRelay }

    let coordinatorKey = try await resolveGroupCoordinatorKey(replacementRelayURL)
    guard coordinatorKey.count == 32,
      (try? Curve25519.Signing.PublicKey(rawRepresentation: coordinatorKey)) != nil
    else { throw GroupRecoveryError.invalidCoordinatorKey }

    var coordinationID: Data
    repeat {
      coordinationID = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
    } while coordinationID == group.coordinationID

    return try executeCore(
      PigeonCoreCommand(
        id: "recover-group:\(UUID().uuidString.lowercased())",
        body: .beginGroupRecovery(
          PigeonBeginGroupRecovery(
            groupID: group.groupID,
            replacementRelayURL: replacementRelayURL.absoluteString,
            replacementCoordinationID: coordinationID,
            replacementCoordinatorPublicKey: coordinatorKey))))
  }
}
