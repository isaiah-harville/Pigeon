//
//  IdentityBundle.swift
//  PigeonCrypto
//
//  Binds a device's long-term Noise static key (X25519) to its Ed25519
//  identity key, so that authenticating the identity (via the in-person
//  safety-number comparison) also authenticates the encrypted channel.
//
//  Without this binding, the Noise handshake proves possession of *some*
//  X25519 static key, but nothing ties that key to the Ed25519 identity a
//  user actually verified. The fix: the identity key signs the static key,
//  and peers check that signature.
//

import CryptoKit
import Foundation

public enum IdentityError: Error, Equatable {
  case malformedBundle
}

/// The public, shareable identity of a device: its Ed25519 identity key, its
/// X25519 Noise static key, and the identity key's signature over the static
/// key. This is the payload exchanged in person via QR.
public struct IdentityBundle: Equatable, Sendable {
  public static let size = 128  // 32 + 32 + 64

  /// Ed25519 identity public key (32 bytes). Root of trust / safety number.
  public let identityKey: Data
  /// X25519 Noise static public key (32 bytes) used by the handshake.
  public let staticKey: Data
  /// Ed25519 signature (64 bytes) by `identityKey` over `staticKey`.
  public let signature: Data

  public init(identityKey: Data, staticKey: Data, signature: Data) {
    self.identityKey = identityKey
    self.staticKey = staticKey
    self.signature = signature
  }

  /// Verifies the static key is genuinely bound to the identity key.
  /// A handshake's `remoteStaticKey` should be checked to equal `staticKey`
  /// of a bundle for which this returns `true`.
  public func isValid() -> Bool {
    guard let identity = try? Curve25519.Signing.PublicKey(rawRepresentation: identityKey) else {
      return false
    }
    return identity.isValidSignature(signature, for: staticKey)
  }

  /// Fixed 128-byte encoding: `identityKey(32) ‖ staticKey(32) ‖ signature(64)`.
  public func encoded() -> Data {
    identityKey + staticKey + signature
  }

  public init(decoding data: Data) throws {
    guard data.count == Self.size else { throw IdentityError.malformedBundle }
    let base = data.startIndex
    self.identityKey = Data(data[base..<base + 32])
    self.staticKey = Data(data[base + 32..<base + 64])
    self.signature = Data(data[base + 64..<base + 128])
  }
}
