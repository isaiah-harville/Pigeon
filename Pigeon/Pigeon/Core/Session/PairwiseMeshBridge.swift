import Foundation
import PigeonFFI

enum PairwiseMeshBridge {
  static func outboundEnvelopes(
    items: [PigeonCoreOutboundItem],
    sender: Data,
    sentItemIDs: inout Set<String>
  ) -> [SessionEnvelope] {
    sentItemIDs.formIntersection(Set(items.map(\.id)))
    var envelopes: [SessionEnvelope] = []
    for item in items
    where item.kind == .pairwise
      && item.localOnly
      && !sentItemIDs.contains(item.id)
      && !item.payload.isEmpty
    {
      envelopes.append(
        SessionEnvelope(
          type: .pairwise, sender: sender, recipient: item.destination,
          payload: item.payload))
      sentItemIDs.insert(item.id)
    }
    return envelopes
  }
}

extension SessionManager {
  func fanOutPairwiseMesh(snapshot: PigeonCoreSnapshot) {
    let envelopes = PairwiseMeshBridge.outboundEnvelopes(
      items: snapshot.pendingOutbound,
      sender: myID,
      sentItemIDs: &meshedPairwiseOutboundIDs)
    for envelope in envelopes {
      mesh.send(envelope.encoded(), to: envelope.recipient, over: TransportKind.local)
    }
  }
}
