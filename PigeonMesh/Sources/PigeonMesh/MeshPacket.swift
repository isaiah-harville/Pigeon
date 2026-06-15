//
//  MeshPacket.swift
//  PigeonMesh
//
//  The mesh envelope that rides inside transport messages: a unique packet id
//  for duplicate-suppression and a TTL for store-and-forward relaying.
//
//  This is the layer that fixes duplicate delivery: the same logical message
//  may reach a device over several BLE paths (and, later, several relay hops),
//  but it carries one packet id, so a seen-cache delivers it exactly once.
//

import Foundation

public enum MeshError: Error, Equatable {
  case malformedPacket
}

/// An end-to-end mesh packet. The `payload` is opaque to the mesh (it will be
/// ciphertext once encryption is wired in); the mesh only reads the header to
/// deduplicate and relay.
///
/// Wire layout (18-byte header): `version(1) ‖ ttl(1) ‖ packetID(16) ‖ payload`.
public struct MeshPacket: Equatable, Sendable {
  public static let version: UInt8 = 1
  public static let idSize = 16
  public static let headerSize = 18

  /// Unique per originated packet; the basis for dedup and loop prevention.
  public let packetID: Data
  /// Remaining hops. Decremented on each relay; a packet is not relayed at 0.
  public let ttl: UInt8
  public let payload: Data

  public init(packetID: Data, ttl: UInt8, payload: Data) {
    self.packetID = packetID
    self.ttl = ttl
    self.payload = payload
  }

  /// Generates a fresh random 16-byte packet id (UUID-backed; uniqueness, not
  /// secrecy, is what matters here).
  public static func randomID() -> Data {
    withUnsafeBytes(of: UUID().uuid) { Data($0) }
  }

  public func encoded() -> Data {
    var data = Data(capacity: Self.headerSize + payload.count)
    data.append(Self.version)
    data.append(ttl)
    data.append(packetID)
    data.append(payload)
    return data
  }

  public init(decoding data: Data) throws {
    guard data.count >= Self.headerSize else { throw MeshError.malformedPacket }
    let base = data.startIndex
    guard data[base] == Self.version else { throw MeshError.malformedPacket }
    self.ttl = data[base + 1]
    self.packetID = Data(data[(base + 2)..<(base + 18)])
    self.payload = Data(data[(base + 18)...])
  }

  /// Returns the packet to relay (one fewer hop), or `nil` if it has reached
  /// its hop limit and must not be forwarded.
  public func relayed() -> MeshPacket? {
    guard ttl > 1 else { return nil }
    return MeshPacket(packetID: packetID, ttl: ttl - 1, payload: payload)
  }
}

/// Bounded FIFO set of recently seen packet ids, used to drop duplicates and
/// prevent relay loops. When full, the oldest ids are forgotten (a re-seen old
/// packet may then be delivered again — an acceptable trade for bounded memory).
public final class SeenCache {
  private let capacity: Int
  private var order: [Data] = []
  private var members: Set<Data> = []

  public init(capacity: Int = 1024) {
    self.capacity = max(1, capacity)
  }

  /// Records `id`. Returns `true` if it was newly seen, `false` if a duplicate.
  @discardableResult
  public func insert(_ id: Data) -> Bool {
    guard !members.contains(id) else { return false }
    members.insert(id)
    order.append(id)
    if order.count > capacity {
      let evicted = order.removeFirst()
      members.remove(evicted)
    }
    return true
  }

  public func contains(_ id: Data) -> Bool { members.contains(id) }
}

/// Flood-based mesh routing: originate packets, and on reception decide whether
/// to deliver locally and/or relay onward, deduplicating by packet id.
public final class MeshRouter {

  /// The outcome of ingesting a packet.
  public struct Reception: Equatable {
    /// Payload to hand to the local app, or `nil` if this was a duplicate.
    public let deliver: Data?
    /// Packet to rebroadcast to other peers, or `nil` if not relayed.
    public let relay: MeshPacket?
  }

  public let defaultTTL: UInt8
  private let seen: SeenCache

  public init(defaultTTL: UInt8 = 8, seenCapacity: Int = 1024) {
    self.defaultTTL = defaultTTL
    self.seen = SeenCache(capacity: seenCapacity)
  }

  /// Wraps `payload` in a fresh packet for sending. The id is pre-marked as
  /// seen so our own packet echoing back through the mesh is ignored.
  public func originate(_ payload: Data) -> MeshPacket {
    let packet = MeshPacket(packetID: MeshPacket.randomID(), ttl: defaultTTL, payload: payload)
    seen.insert(packet.packetID)
    return packet
  }

  /// Processes an inbound packet. Duplicates yield no delivery and no relay.
  public func ingest(_ packet: MeshPacket) -> Reception {
    guard seen.insert(packet.packetID) else {
      return Reception(deliver: nil, relay: nil)
    }
    return Reception(deliver: packet.payload, relay: packet.relayed())
  }
}
