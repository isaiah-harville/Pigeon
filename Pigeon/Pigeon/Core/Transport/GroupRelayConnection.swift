import Foundation
import PigeonFFI

struct GroupRelayAuthorizationState {
  private var requiresConfirmation: Bool
  private var isConfirmed = false

  init(requiresConfirmation: Bool) {
    self.requiresConfirmation = requiresConfirmation
  }

  mutating func requireConfirmation() {
    requiresConfirmation = true
  }

  mutating func confirmIfRequired(_ confirmation: () -> Bool) -> Bool {
    guard requiresConfirmation, !isConfirmed else { return true }
    guard confirmation() else { return false }
    isConfirmed = true
    return true
  }
}

struct GroupRelayEffect: Equatable {
  let id: String
  let action: PigeonCoreRelayAction
}

enum GroupRelayOperation: Equatable {
  case effect(GroupRelayEffect)
  case fetchMessages
  case advance(UInt64)
  case fetchCoordinator(UInt64)
}

final class GroupRelayConnection {
  var group: PigeonGroupState
  var socket: URLSessionWebSocketTask?
  var supervisor: Task<Void, Never>?
  var queue: [GroupRelayOperation] = []
  var awaiting: GroupRelayOperation?
  var ready = false
  var fetchedAfterConnect = false
  var needsMessageFetch = false
  var authorization: GroupRelayAuthorizationState

  convenience init(group: PigeonGroupState) {
    self.init(group: group, confirmsAuthorization: true)
  }

  init(group: PigeonGroupState, confirmsAuthorization: Bool) {
    self.group = group
    authorization = GroupRelayAuthorizationState(requiresConfirmation: confirmsAuthorization)
  }

  func usesSameEndpoint(as candidate: PigeonGroupState) -> Bool {
    group.groupID == candidate.groupID && group.relayURL == candidate.relayURL
      && group.capabilityPublicKey == candidate.capabilityPublicKey
      && group.capabilityID == candidate.capabilityID
  }
}
