//
//  SessionManager+GroupAcknowledgements.swift
//  Pigeon
//
//  Throttled delivery receipts for group chats.
//

import Foundation
import PigeonFFI

extension SessionManager {
  /// How long received group messages wait before their receipts are sent as
  /// one batched ciphertext. Every member's receipts go to the whole group
  /// mailbox, so the interval grows with group size: mailbox growth then scales
  /// with elapsed time rather than with messages times members.
  static func groupAcknowledgementInterval(memberCount: Int) -> Duration {
    .milliseconds(max(2_000, memberCount * 500))
  }

  /// Starts the receipt timer for a group unless one is already running;
  /// messages received before it fires share the same batch. The core flushes a
  /// full batch on its own, so bursts are not held back by this timer.
  func scheduleGroupAcknowledgementFlush(for groupID: Data) {
    guard groupAcknowledgementFlushes[groupID] == nil else { return }
    let memberCount =
      groups.first { $0.groupID == groupID }?.memberIdentities.count
      ?? Self.maximumGroupMembers
    let interval = Self.groupAcknowledgementInterval(memberCount: memberCount)
    groupAcknowledgementFlushes[groupID] = Task { [weak self] in
      try? await Task.sleep(for: interval)
      guard let self, !Task.isCancelled else { return }
      self.groupAcknowledgementFlushes[groupID] = nil
      self.flushGroupAcknowledgements(groupID: groupID)
    }
  }

  /// Sends queued receipts for every group.
  func flushGroupAcknowledgements() {
    flushGroupAcknowledgements(groupID: nil)
  }

  /// Sends queued receipts for one group, or every group when `groupID` is nil.
  /// Receipts are durable in the core checkpoint, so a locked device or failed
  /// flush only delays them until the next flush.
  func flushGroupAcknowledgements(groupID: Data?) {
    guard isUnlocked, isPersistenceHealthy, coreClient != nil else { return }
    do {
      try executeCore(
        PigeonCoreCommand(
          id: "flush-group-acks:\(UUID().uuidString.lowercased())",
          body: .flushGroupAcknowledgements(groupID: groupID)))
    } catch {
      note(.persistenceFailed)
    }
  }
}
