import Foundation
import PigeonFFI
import XCTest

@testable import Pigeon

@MainActor
final class MeshRetryTests: XCTestCase {
  private final class RecordingTransport: Transport {
    var status: TransportStatus = .idle
    var connectedPeerCount = 0
    var log: [String] = []
    var onMessage: ((Data, String) -> TransportMessageDisposition)?
    var onConnectivity: (() -> Void)?
    var forwarded: [Data] = []

    func broadcast(_ message: Data, to _: Data?) { forwarded.append(message) }
    func receive(_ packet: MeshPacket) -> TransportMessageDisposition {
      onMessage?(packet.encoded(), "peer") ?? .retryAfterRestart
    }
  }

  func testLockedAndFailedSaveDeliveriesRemainRetryableUntilDurableConsumption() {
    let transport = RecordingTransport()
    let mesh = MeshService(transport: transport)
    let packet = MeshPacket(packetId: MeshPacket.randomID(), ttl: 3, payload: Data([7]))
    var attempts = 0
    var isLocked = true
    var canPersist = false
    mesh.onMessage = { _, _ in
      attempts += 1
      return isLocked || !canPersist ? .retryAfterRestart : .consumed
    }

    XCTAssertEqual(transport.receive(packet), .retryAfterRestart)
    isLocked = false
    XCTAssertEqual(transport.receive(packet), .retryAfterRestart)
    canPersist = true
    XCTAssertEqual(transport.receive(packet), .consumed)
    XCTAssertEqual(transport.receive(packet), .consumed)
    XCTAssertEqual(attempts, 3)
    XCTAssertEqual(transport.forwarded.count, 1)
  }
}
