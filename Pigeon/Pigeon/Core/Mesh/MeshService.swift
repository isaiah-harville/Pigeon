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

/// The app-facing messaging surface: send a message to the mesh, receive each
/// message exactly once. Wraps any `Transport` and a `MeshRouter`, so the mesh
/// runs unchanged over BLE, relay, or future transports.
@MainActor
@Observable
final class MeshService {

  private let transport: any Transport
  private let router = MeshRouter()

  /// Delivered once per unique message that reaches this device, along with the
  /// transport it arrived on (so the UI can show how a message travelled).
  var onMessage: ((Data, TransportChannel) -> Void)?

  /// Fired when an underlying link becomes usable (a peer connects, a relay
  /// authenticates), so the session layer can (re)drive establishment and flush
  /// pending sends on the event instead of polling (#82).
  var onConnectivity: (() -> Void)?

  // UI passthroughs so views don't need to know about the transport.
  var status: TransportStatus { transport.status }
  var connectedPeerCount: Int { transport.connectedPeerCount }
  var log: [String] { transport.log }

  /// Defaults to the BLE transport; inject another `Transport` to run the mesh
  /// over a different link (tests, Multipeer, relays, …).
  convenience init() {
    self.init(transport: PeerTransport())
  }

  init(transport: any Transport) {
    self.transport = transport
    transport.onMessage = { [weak self] data, peerID in
      self?.handleInbound(data, channel: TransportChannel(peerID: peerID))
    }
    transport.onConnectivity = { [weak self] in self?.onConnectivity?() }
  }

  /// Sends `message` into the mesh. `recipient` is the destination's identity
  /// key, passed to the transport as a delivery hint (used by the relay to
  /// address a mailbox; ignored by flood transports like BLE). `over` restricts
  /// the send to specific links (pass `TransportKind.all` for every link), e.g.
  /// relay-only for a chat the user switched off Bluetooth (#24).
  func send(_ message: Data, to recipient: Data?, over channels: Set<TransportKind>) {
    let packet = router.originate(message)
    transport.broadcast(packet.encoded(), to: recipient, over: channels)
  }

  /// Lets UI pull-to-refresh nudge the underlying links without exposing the
  /// concrete transports above the mesh layer.
  func refreshConnections() {
    transport.refreshConnections()
  }

  private func handleInbound(_ data: Data, channel: TransportChannel) {
    guard let packet = try? MeshPacket(decoding: data) else { return }
    let reception = router.ingest(packet)
    if let payload = reception.deliver {
      onMessage?(payload, channel)
    }
    // Forward toward peers we can reach that the sender may not (flood relay,
    // bounded by the seen-cache and TTL). This is address-less flooding — the
    // internet relay deliberately ignores it and only carries our own directly
    // addressed messages.
    if let relay = reception.relay {
      transport.broadcast(relay.encoded(), to: nil)
    }
  }
}
