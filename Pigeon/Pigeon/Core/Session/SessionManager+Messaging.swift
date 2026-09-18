//
//  SessionManager+Messaging.swift
//  Pigeon
//

import CryptoKit
import Foundation
import PigeonFFI

extension SessionManager {
  func handleInbound(_ data: Data, channel: TransportChannel) -> TransportMessageDisposition {
    guard let envelope = try? SessionEnvelope(decoding: data) else { return .consumed }
    if envelope.type == .groupMls {
      return handleInboundGroupMesh(envelope, encoded: data, channel: channel)
    }
    guard envelope.recipient == myID else { return .consumed }
    guard isUnlocked else {
      bufferWhileLocked(data, channel: channel)
      return .retryAfterRestart
    }
    guard isPersistenceHealthy else { return .retryAfterRestart }
    guard purgeExpiredIncomingRequests(now: Date()) else { return .retryAfterRestart }
    guard !blockedContactIDs.contains(envelope.sender) else { return .consumed }
    guard envelope.type == .pairwise else { return .consumed }
    let requestID = "pairwise-\(Data(SHA256.hash(data: data)).hexEncoded)"
    return consumePairwiseMessage(envelope.payload, requestID: requestID)
      ? .consumed : .retryAfterRestart
  }

  /// Records a screenshot in the visible conversation and mirrors the event to
  /// that peer through the core-owned authenticated pairwise session.
  func reportScreenshotTaken() {
    guard let contactID = activeChatID,
      let contact = contacts.first(where: { $0.id == contactID })
    else { return }
    var event = ChatMessage(
      mine: true,
      text: Self.screenshotNotice(mine: true, contactName: contact.displayName),
      pending: true)
    event.system = true
    event.event = .screenshot
    event.transientOutbox = isEphemeral(contact)
    guard record(event, for: contact.id) else { return }
    armDeliveryDeadline(messageID: event.id, contactID: contact.id)
    if canUseCorePairwise(with: contact) { transmit(event, to: contact) }
  }
}
