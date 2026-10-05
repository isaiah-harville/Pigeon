import Foundation
import PigeonFFI

extension SessionManager {
  enum GroupInviteError: Error {
    case unavailable
    case invalidTicket
    case invalidRelay
  }

  @discardableResult
  func createGroupInvite(
    groupID: Data, publicMode: Bool, expiresAt: Date
  ) throws -> GroupInviteLink {
    guard isUnlocked, isPersistenceHealthy else { throw GroupInviteError.unavailable }
    try executeCore(
      PigeonCoreCommand(
        id: "create-group-invite:\(UUID().uuidString.lowercased())",
        body: .createGroupInvite(
          PigeonCreateGroupInvite(
            groupID: groupID, publicMode: publicMode,
            expiresAtMilliseconds: Self.milliseconds(expiresAt),
            nowMilliseconds: Self.milliseconds(.now)))))
    guard
      let invitation = groupInvites.last(where: { invite in
        GroupInviteLink(ticket: invite.ticket)?.metadata.groupId == groupID
      }), let link = GroupInviteLink(ticket: invitation.ticket)
    else { throw GroupInviteError.invalidTicket }
    return link
  }

  func revokeGroupInvite(_ link: GroupInviteLink) throws {
    guard isUnlocked, isPersistenceHealthy else { throw GroupInviteError.unavailable }
    try executeCore(
      PigeonCoreCommand(
        id: "revoke-group-invite:\(UUID().uuidString.lowercased())",
        body: .revokeGroupInvite(
          PigeonRevokeGroupInvite(
            inboxAddress: link.metadata.inboxAddress))))
  }

  func requestGroupInviteJoin(_ link: GroupInviteLink) throws {
    guard isUnlocked, isPersistenceHealthy else { throw GroupInviteError.unavailable }
    try executeCore(
      PigeonCoreCommand(
        id: "start-group-invite-join:\(UUID().uuidString.lowercased())",
        body: .startGroupInviteJoin(
          PigeonStartGroupInviteJoin(
            ticket: link.ticket, nowMilliseconds: Self.milliseconds(.now)))))
  }

  func decideGroupInviteRequest(
    inboxAddress: Data, requestID: Data, approve: Bool
  ) throws {
    guard isUnlocked, isPersistenceHealthy else { throw GroupInviteError.unavailable }
    try executeCore(
      PigeonCoreCommand(
        id: "decide-group-invite-request:\(UUID().uuidString.lowercased())",
        body: .decideGroupInviteRequest(
          PigeonDecideGroupInviteRequest(
            inboxAddress: inboxAddress, requestID: requestID,
            approve: approve, nowMilliseconds: Self.milliseconds(.now)))))
  }

  func refreshGroupInvites() throws {
    guard isUnlocked, isPersistenceHealthy else { throw GroupInviteError.unavailable }
    _ = try executeCore(
      PigeonCoreCommand(
        id: "refresh-group-invites:\(UUID().uuidString.lowercased())",
        body: .refreshGroupInvites(
          PigeonRefreshGroupInvites(
            nowMilliseconds: Self.milliseconds(.now)))))
  }

  func makeGroupInviteRelay() -> GroupInviteRelayTransport {
    let transport = GroupInviteRelayTransport { [weak self] address, nonce in
      guard let coreClient = self?.coreClient else { throw GroupInviteError.unavailable }
      return try coreClient.inviteMailboxChallengeSignature(address: address, nonce: nonce)
    }
    transport.onEnvelope = { [weak self] address, ciphertext, requestID in
      self?.consumeGroupInviteEnvelope(
        address: address, ciphertext: ciphertext, requestID: requestID) ?? false
    }
    transport.onEffectDelivered = { [weak self] itemID in
      self?.acknowledgeCoreOutbound(itemID) ?? false
    }
    return transport
  }

  func reconfigureGroupInviteRelay(snapshot: PigeonCoreSnapshot) {
    guard ConnectivitySettings.isEnabled, isAppActive, isUnlocked, isPersistenceHealthy else {
      groupInviteRelay.disconnect()
      return
    }
    let issuerSubscriptions: [GroupInviteRelayTransport.Subscription] =
      groupInvites.compactMap { invite in
        guard let link = GroupInviteLink(ticket: invite.ticket),
          let relayURL = URL(string: link.metadata.relayUrl)
        else { return nil }
        return .init(relayURL: relayURL, address: link.metadata.inboxAddress)
      }
    let joinSubscriptions: [GroupInviteRelayTransport.Subscription] =
      groupInviteJoins.compactMap { join in
        guard join.progress == .pending || join.progress == .approved,
          let link = GroupInviteLink(
            ticket: join.ticket, now: Date(timeIntervalSince1970: 0)),
          let relayURL = URL(string: link.metadata.relayUrl)
        else { return nil }
        return .init(relayURL: relayURL, address: join.replyAddress)
      }
    let subscriptions = issuerSubscriptions + joinSubscriptions
    let effects = snapshot.pendingOutbound
    let outbound: [GroupInviteRelayTransport.Outbound] = effects.compactMap { item in
      switch item.kind {
      case .groupInviteRequest, .groupInviteReply, .groupInviteMaterial: break
      default: return nil
      }
      guard let relayURL = URL(string: item.relayURL) else { return nil }
      return .init(
        id: item.id, relayURL: relayURL,
        destination: item.destination, ciphertext: item.payload)
    }
    groupInviteRelay.reconfigure(subscriptions: subscriptions, outbound: outbound)
  }

  private func consumeGroupInviteEnvelope(
    address: Data, ciphertext: Data, requestID: String
  ) -> Bool {
    guard isUnlocked, isPersistenceHealthy else { return false }
    do {
      let issuerInbox = groupInvites.contains { invite in
        GroupInviteLink(ticket: invite.ticket)?.metadata.inboxAddress == address
      }
      let command: PigeonCoreCommand.Body
      if issuerInbox {
        command = .applyGroupInviteInboxEnvelope(
          PigeonApplyGroupInviteInboxEnvelope(
            inboxAddress: address, ciphertext: ciphertext,
            nowMilliseconds: Self.milliseconds(.now)))
      } else {
        command = .applyGroupInviteReply(
          PigeonApplyGroupInviteReply(
            replyAddress: address, ciphertext: ciphertext,
            nowMilliseconds: Self.milliseconds(.now)))
      }
      let output = try executeCore(
        PigeonCoreCommand(
          id: "group-invite-envelope:\(requestID)", body: command))
      return output.inviteEnvelopeOutcome != .unspecified
    } catch {
      return false
    }
  }

  private static func milliseconds(_ date: Date) -> Int64 {
    Int64(date.timeIntervalSince1970 * 1_000)
  }
}
