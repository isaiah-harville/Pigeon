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
    groupRelay.reconfigure(snapshot: snapshot)
    return output
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
}
