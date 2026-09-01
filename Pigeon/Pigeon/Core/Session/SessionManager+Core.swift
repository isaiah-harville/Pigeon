import CryptoKit
import Foundation
import PigeonFFI

extension SessionManager {
  func makeGroupRelay() -> GroupRelayTransport {
    let transport = GroupRelayTransport { [weak self] groupID, nonce in
      guard let coreClient = self?.coreClient else {
        throw PlatformError.Unavailable
      }
      return try coreClient.relayChallengeSignature(groupID: groupID, nonce: nonce)
    }
    transport.onMessage = { [weak self] ciphertext, requestID in
      self?.consumeGroupRelayMessage(ciphertext, requestID: requestID) ?? false
    }
    transport.onCoordinatorCandidate = { [weak self] receipt, candidate, requestID in
      self?.consumeCoordinatorCandidate(
        receipt,
        candidate: candidate,
        requestID: requestID) ?? false
    }
    transport.onEffectDelivered = { [weak self] itemID in
      self?.acknowledgeCoreOutbound(itemID) ?? false
    }
    return transport
  }

  /// Atomically replaces the host projection with a snapshot from the durable
  /// core. A stale asynchronous result cannot roll the UI back.
  func applyCoreSnapshot(_ snapshot: PigeonCoreSnapshot) {
    guard snapshot.checkpointGeneration >= coreSnapshotGeneration else { return }
    groups = snapshot.groups
    coreSnapshotGeneration = snapshot.checkpointGeneration
  }

  /// Runs one idempotent core command and refreshes every host projection from
  /// the checkpoint that the core persisted before returning its effects.
  @discardableResult
  func executeCore(_ command: PigeonCoreCommand) throws -> PigeonCoreOutput {
    guard let coreClient else { throw PlatformError.Unavailable }
    let output = try coreClient.execute(command)
    let snapshot = try coreClient.stateSnapshot()
    guard snapshot.checkpointGeneration == output.checkpointGeneration else {
      throw PlatformError.InvalidOutput
    }
    applyCoreSnapshot(snapshot)
    try absorbCoreEvents(snapshot.pendingEvents)
    groupRelay.reconfigure(snapshot: try coreClient.stateSnapshot())
    return output
  }

  /// Reduces replayable core events into encrypted app history, saves that
  /// history, and only then removes the events from the core checkpoint.
  func absorbCoreEvents(_ events: [PigeonCoreEvent]) throws {
    guard !events.isEmpty else { return }
    var candidate = groupConversations
    for event in events {
      let groupID = groupID(for: event)
      var conversation = candidate[groupID] ?? GroupConversation(id: groupID)
      try GroupEventReducer.reduce(event, into: &conversation, localIdentity: myID)
      candidate[groupID] = conversation
    }
    if candidate != groupConversations {
      groupConversations = candidate
      guard persist() else { throw PlatformError.Unavailable }
    }
    try acknowledgeCoreEvents(events.map(\.id))
  }

  func consumeGroupRelayMessage(_ ciphertext: Data, requestID: String) -> Bool {
    guard isUnlocked, isPersistenceHealthy else { return false }
    do {
      try executeCore(
        PigeonCoreCommand(
          id: "group-message:\(requestID)",
          body: .applyInbound(
            PigeonApplyInbound(
              kind: .groupMessage,
              payload: ciphertext,
              requestID: requestID))))
      return true
    } catch {
      return false
    }
  }

  func consumeCoordinatorCandidate(
    _ receipt: PigeonCoordinatorReceipt,
    candidate: Data,
    requestID: String
  ) -> Bool {
    guard isUnlocked, isPersistenceHealthy else { return false }
    do {
      let inbound = try PigeonApplyInbound.coordinatorCandidate(
        receipt: receipt,
        candidate: candidate,
        requestID: requestID)
      try executeCore(
        PigeonCoreCommand(
          id: "group-coordinator:\(requestID)",
          body: .applyInbound(inbound)))
      return true
    } catch {
      return false
    }
  }

  func acknowledgeCoreOutbound(_ itemID: String) -> Bool {
    guard isUnlocked, isPersistenceHealthy else { return false }
    do {
      try executeCore(
        PigeonCoreCommand(
          id: "ack-outbound:\(itemID)",
          body: .acknowledgeEffects(
            PigeonAcknowledgeEffects(outboundItemIDs: [itemID]))))
      return true
    } catch {
      return false
    }
  }

  private func acknowledgeCoreEvents(_ eventIDs: [String]) throws {
    guard let coreClient else { throw PlatformError.Unavailable }
    let encodedIDs = try JSONEncoder().encode(eventIDs)
    let digest = SHA256.hash(data: encodedIDs)
      .map { String(format: "%02x", $0) }
      .joined()
    _ = try coreClient.execute(
      PigeonCoreCommand(
        id: "ack-events:\(digest)",
        body: .acknowledgeEffects(
          PigeonAcknowledgeEffects(eventIDs: eventIDs))))
    applyCoreSnapshot(try coreClient.stateSnapshot())
  }

  private func groupID(for event: PigeonCoreEvent) -> Data {
    switch event.body {
    case .groupCreated(let value): value.groupID
    case .groupMessageReceived(let value): value.groupID
    case .groupReactionReceived(let value): value.groupID
    case .groupPolicyChanged(let value): value.groupID
    case .groupDeliveryChanged(let value): value.groupID
    case .groupSecurityWarning(let value): value.groupID
    }
  }
}
