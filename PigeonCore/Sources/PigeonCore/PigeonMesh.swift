//
//  PigeonMesh.swift
//  PigeonCore
//
//  Ergonomic Swift facade over the generated mesh bindings (framing,
//  fragmentation, routing, envelope). The generated value types carry their
//  codecs as free functions and the binding spells the envelope tag `kind`;
//  these extensions re-present them with throwing `init(decoding:)` /
//  `encoded()` and the `type` spelling the app uses, so call sites read the same
//  whether the mesh is Swift or, as now, the shared Rust `pigeon-mesh` crate.
//

import Foundation

// MARK: - Value-type codecs

extension MeshPacket {
  /// Decodes a packet from wire bytes, throwing on malformed input.
  public init(decoding data: Data) throws { self = try decodeMeshPacket(data: data) }
  public func encoded() -> Data { encodeMeshPacket(packet: self) }
  /// The packet to relay (one fewer hop), or `nil` at the hop limit.
  public func relayed() -> MeshPacket? { relayMeshPacket(packet: self) }
  /// A fresh random 16-byte packet id.
  public static func randomID() -> Data { meshPacketRandomId() }
}

extension Fragment {
  public init(decoding data: Data) throws { self = try decodeFragment(data: data) }
  public func encoded() -> Data { encodeFragment(fragment: self) }
}

extension SessionEnvelope {
  public init(decoding data: Data) throws { self = try decodeSessionEnvelope(data: data) }
  public func encoded() -> Data { encodeSessionEnvelope(envelope: self) }

  /// The envelope's tag. The binding names this field `kind`; the app reads
  /// `type`, so expose both spellings.
  public var type: EnvelopeType { kind }

  public init(type: EnvelopeType, sender: Data, recipient: Data, payload: Data) {
    self.init(kind: type, sender: sender, recipient: recipient, payload: payload)
  }
}

// MARK: - Stateful objects

extension MeshRouter {
  public func originate(_ payload: Data) -> MeshPacket { originate(payload: payload) }
  public func ingest(_ packet: MeshPacket) -> Reception { ingest(packet: packet) }
}

extension Fragmenter {
  /// Fragments `message` into pieces of at most `maxPayloadPerFragment` bytes
  /// (the negotiated usable MTU minus the fragment header).
  public func fragment(_ message: Data, maxPayloadPerFragment: Int) throws -> [Fragment] {
    try fragment(message: message, maxPayloadPerFragment: UInt32(maxPayloadPerFragment))
  }
}

extension Reassembler {
  /// Feeds one fragment in; returns the whole message once it completes.
  public func ingest(_ fragment: Fragment) throws -> Data? { try ingest(fragment: fragment) }
}

// MARK: - Sendability

// The mesh value types are immutable bundles of bytes/scalars — safe to move
// across isolation boundaries, as the old PigeonMesh package's types were.
extension MeshPacket: @unchecked Sendable {}
extension Fragment: @unchecked Sendable {}
extension SessionEnvelope: @unchecked Sendable {}
extension Reception: @unchecked Sendable {}
extension EnvelopeType: @unchecked Sendable {}
