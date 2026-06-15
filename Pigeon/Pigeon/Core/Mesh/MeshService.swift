//
//  MeshService.swift
//  Pigeon
//
//  Sits above the raw Bluetooth transport and applies the mesh envelope:
//  outbound messages get a unique packet id; inbound packets are deduplicated
//  (fixing the multi-path duplicate delivery) and relayed onward toward peers
//  out of direct range.
//

import Foundation
import PigeonMesh

/// The app-facing messaging surface for Phase 3b/4: send a message to the mesh,
/// receive each message exactly once. Wraps `PeerTransport` and a `MeshRouter`.
@MainActor
@Observable
final class MeshService {

  private let transport: PeerTransport
  private let router = MeshRouter()

  /// Delivered once per unique message that reaches this device.
  var onMessage: ((Data) -> Void)?

  // UI passthroughs so views don't need to know about the transport.
  var status: PeerTransport.Status { transport.status }
  var connectedPeerCount: Int { transport.connectedPeerCount }
  var log: [String] { transport.log }

  init() {
    transport = PeerTransport()
    transport.onMessage = { [weak self] data, _ in
      self?.handleInbound(data)
    }
  }

  /// Sends `message` into the mesh.
  func send(_ message: Data) {
    let packet = router.originate(message)
    transport.broadcast(packet.encoded())
  }

  private func handleInbound(_ data: Data) {
    guard let packet = try? MeshPacket(decoding: data) else { return }
    let reception = router.ingest(packet)
    if let payload = reception.deliver {
      onMessage?(payload)
    }
    // Forward toward peers we can reach that the sender may not (flood relay,
    // bounded by the seen-cache and TTL).
    if let relay = reception.relay {
      transport.broadcast(relay.encoded())
    }
  }
}
