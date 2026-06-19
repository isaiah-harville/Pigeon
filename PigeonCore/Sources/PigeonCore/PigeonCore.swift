//
//  PigeonCore.swift
//  PigeonCore
//
//  A thin ergonomic layer over the generated UniFFI bindings (Generated/). The
//  generated types are already usable; these aliases just give the app
//  Pigeon-flavoured names and keep the `Ffi`-prefixed binding detail out of app
//  code. Anything richer (typed bundle wrappers, persistence helpers) is added
//  as the app actually needs it during the cutover.
//

import Foundation
import SwiftProtobuf

/// One device's cryptographic account: its long-term Ed25519 identity plus its
/// Olm account. See `FfiAccount` for the full API.
public typealias PigeonAccount = FfiAccount

/// One end of a pairwise end-to-end-encrypted session (Olm Double Ratchet).
public typealias PigeonSession = FfiSession

/// A device's public identity: its Ed25519 identity key, its Olm Curve25519
/// identity key, and the binding signature — the QR payload. Decoding verifies
/// the binding, so a value of this type is always authentic (the Curve key is
/// genuinely bound to the Ed25519 identity). Replaces the Swift
/// `PigeonCrypto.IdentityBundle`.
public struct PigeonIdentityBundle: Equatable, Sendable {
  /// The protobuf encoding, as transported in the QR card and persisted.
  public let encoded: Data
  /// Ed25519 identity public key (32 bytes) — the safety-number root / contact id.
  public let identityKey: Data
  /// Olm Curve25519 identity public key (32 bytes).
  public let curveIdentityKey: Data

  /// Decodes **and verifies** a protobuf identity bundle. Throws if it is
  /// malformed or its binding signature does not verify.
  public init(decoding data: Data) throws {
    let view = try parseIdentityBundle(encoded: data)
    self.encoded = Data(data)
    self.identityKey = view.identityKey
    self.curveIdentityKey = view.curveIdentityKey
  }
}

/// The schema-defined contact-card payload used by QR/paste exchange.
public struct PigeonContactCardPayload: Equatable, Sendable {
  public var version: UInt32
  public var identityBundle: Data
  public var name: String
  public var relayURLs: [String]
  public var relaySignature: Data
  public var prekeyBundle: Data

  public init(
    version: UInt32,
    identityBundle: Data,
    name: String,
    relayURLs: [String],
    relaySignature: Data,
    prekeyBundle: Data
  ) {
    self.version = version
    self.identityBundle = identityBundle
    self.name = name
    self.relayURLs = relayURLs
    self.relaySignature = relaySignature
    self.prekeyBundle = prekeyBundle
  }
}

public enum PigeonWireError: Error, Equatable, Sendable {
  case missingIdentity
}

public func encodeContactCardPayload(_ payload: PigeonContactCardPayload) throws -> Data {
  var card = Pigeon_Wire_V1_ContactCard()
  card.version = payload.version
  card.identity = try Pigeon_Wire_V1_IdentityBundle(serializedBytes: payload.identityBundle)
  card.name = payload.name
  card.relayUrls = payload.relayURLs
  card.relaySignature = payload.relaySignature
  card.prekeyBundle = payload.prekeyBundle
  return try card.serializedData()
}

public func decodeContactCardPayload(_ data: Data) throws -> PigeonContactCardPayload {
  let card = try Pigeon_Wire_V1_ContactCard(serializedBytes: data)
  guard card.hasIdentity else {
    throw PigeonWireError.missingIdentity
  }
  return try PigeonContactCardPayload(
    version: card.version,
    identityBundle: card.identity.serializedData(),
    name: card.name,
    relayURLs: card.relayUrls,
    relaySignature: card.relaySignature,
    prekeyBundle: card.prekeyBundle
  )
}

/// A published prekey bundle (identity + one signed Curve25519 prekey) a peer
/// uses to open a session asynchronously. Decoding verifies the identity binding
/// and the prekey signature. Replaces the Swift `PigeonCrypto.X3DHPrekeyBundle`.
public struct PigeonPrekeyBundle: Equatable, Sendable {
  /// The full encoding, as transported in the QR card and persisted.
  public let encoded: Data
  /// Ed25519 identity public key (32 bytes) the bundle is bound to.
  public let identityKey: Data
  /// Olm Curve25519 identity public key (32 bytes).
  public let curveIdentityKey: Data
  /// The Curve25519 prekey public key (32 bytes).
  public let prekey: Data
  /// `true` if the prekey is a (replay-defended) one-time key, `false` if the
  /// long-lived fallback (signed) prekey.
  public let oneTime: Bool

  /// Decodes **and verifies** a prekey bundle (binding + prekey signature).
  /// Throws if malformed or any signature does not verify.
  public init(decoding data: Data) throws {
    let view = try parsePrekeyBundle(encoded: data)
    self.encoded = Data(data)
    self.identityKey = view.identityKey
    self.curveIdentityKey = view.curveIdentityKey
    self.prekey = view.prekey
    self.oneTime = view.oneTime
  }
}
