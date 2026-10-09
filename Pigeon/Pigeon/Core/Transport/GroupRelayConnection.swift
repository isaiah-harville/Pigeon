import Foundation
import PigeonFFI

enum GroupRelayMessageOutcome: Equatable {
  case accepted
  case rejected
  case retry
}

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
  var needsCoordinatorFetch = false
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

  func noteWake() {
    needsMessageFetch = true
    needsCoordinatorFetch = true
  }

  func scheduleNextMessagePage(after sequence: UInt64) {
    queue.insert(contentsOf: [.advance(sequence), .fetchMessages], at: 0)
  }

  func scheduleFetchesIfNeeded() {
    guard queue.isEmpty else { return }
    if !fetchedAfterConnect {
      fetchedAfterConnect = true
      queue.append(.fetchMessages)
      queue.append(.fetchCoordinator(group.coordinatorSequence))
      return
    }
    if needsMessageFetch {
      needsMessageFetch = false
      queue.append(.fetchMessages)
    }
    if needsCoordinatorFetch {
      needsCoordinatorFetch = false
      queue.append(.fetchCoordinator(group.coordinatorSequence))
    }
  }

  func takeRegistration() -> GroupRelayEffect? {
    guard
      let index = queue.firstIndex(where: { operation in
        if case .effect(let effect) = operation, case .registration = effect.action {
          return true
        }
        return false
      }), case .effect(let effect) = queue.remove(at: index)
    else { return nil }
    return effect
  }

  func containsEffect(id: String) -> Bool {
    if case .effect(let effect)? = awaiting, effect.id == id { return true }
    return queue.contains { operation in
      if case .effect(let effect) = operation { return effect.id == id }
      return false
    }
  }
}
