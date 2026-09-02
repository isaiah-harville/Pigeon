import Foundation
import PigeonFFI

/// Maps transport-neutral core effects onto the optional local group mesh.
/// The host never interprets MLS bytes; it only wraps the same ciphertext sent
/// to the selected group relay. `pigeon-core` authenticates and deduplicates it.
enum GroupMeshBridge {
  static func outboundEnvelopes(
    groups: [PigeonGroupState],
    items: [PigeonCoreOutboundItem],
    sender: Data,
    sentItemIDs: inout Set<String>
  ) -> [SessionEnvelope] {
    let pendingIDs = Set(items.map(\.id))
    sentItemIDs.formIntersection(pendingIDs)

    var envelopes: [SessionEnvelope] = []
    for item in items where item.kind == .groupMessage && !sentItemIDs.contains(item.id) {
      guard
        let group = groups.first(where: { group in
          group.coordinationID == item.destination
            && group.meshEnabled
            && !group.dissolved
            && group.memberIdentities.contains(sender)
        })
      else { continue }
      envelopes.append(
        SessionEnvelope(
          type: .groupMls,
          sender: sender,
          recipient: group.groupID,
          payload: item.payload))
      sentItemIDs.insert(item.id)
    }
    return envelopes
  }

  static func acceptsInbound(
    _ envelope: SessionEnvelope,
    groups: [PigeonGroupState],
    localIdentity: Data
  ) -> Bool {
    guard envelope.type == .groupMls else { return false }
    return groups.contains { group in
      group.groupID == envelope.recipient
        && group.meshEnabled
        && !group.dissolved
        && group.memberIdentities.contains(localIdentity)
    }
  }
}

extension SessionManager {
  func fanOutGroupMesh(snapshot: PigeonCoreSnapshot) {
    let envelopes = GroupMeshBridge.outboundEnvelopes(
      groups: snapshot.groups,
      items: snapshot.pendingOutbound,
      sender: myID,
      sentItemIDs: &meshedCoreOutboundIDs)
    for envelope in envelopes {
      mesh.send(envelope.encoded(), to: nil, over: TransportKind.local)
    }
  }

  func handleInboundGroupMesh(
    _ envelope: SessionEnvelope,
    encoded: Data,
    channel: TransportChannel
  ) -> TransportMessageDisposition {
    guard GroupMeshBridge.acceptsInbound(envelope, groups: groups, localIdentity: myID) else {
      return .consumed
    }
    guard isUnlocked else {
      bufferWhileLocked(encoded, channel: channel)
      return .retryAfterRestart
    }
    guard isPersistenceHealthy else { return .retryAfterRestart }
    let requestID = "group-mesh-\(InitiationReplayLedger.digest(encoded).hexEncoded)"
    return consumeGroupRelayMessage(envelope.payload, requestID: requestID)
      ? .consumed : .retryAfterRestart
  }
}
