//
//  CompositeTransport.swift
//  Pigeon
//
//  Runs the mesh over several transports at once (e.g. BLE + relay). It fans
//  every outbound broadcast to all of them and merges their inbound messages,
//  so `MeshService` stays a single-`Transport` consumer and the mesh's dedup
//  layer absorbs the same message arriving over more than one path.
//

import Foundation

@MainActor
final class CompositeTransport: Transport {
  /// The first transport is treated as primary for the headline `status`
  /// (BLE — the always-available local link).
  private let transports: [any Transport]

  init(_ transports: [any Transport]) {
    self.transports = transports
  }

  var onMessage: ((_ message: Data, _ peerID: String) -> Void)? {
    didSet {
      for transport in transports {
        transport.onMessage = onMessage
      }
    }
  }

  func broadcast(_ message: Data, to recipient: Data?) {
    for transport in transports {
      transport.broadcast(message, to: recipient)
    }
  }

  var status: TransportStatus { transports.first?.status ?? .idle }

  /// Connected *peers* — relays aren't peers and report 0, so this stays the
  /// count of directly-connected devices.
  var connectedPeerCount: Int {
    transports.reduce(0) { $0 + $1.connectedPeerCount }
  }

  var log: [String] { transports.flatMap(\.log) }
}
