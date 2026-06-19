//
//  ContactCard.swift
//  Pigeon
//
//  What a QR code encodes: a device's signed identity bundle, the display name
//  its owner chose, and the relay endpoints it can be reached at off-Bluetooth.
//
//  Wire format: base64-encoded `pigeon.wire.v1.ContactCard`.
//
//  The identity bundle carries the Ed25519 ↔ Olm Curve25519 binding. Relay URLs
//  are also signed by the identity key: a scanner honours them only if that
//  signature verifies, otherwise it drops them and falls back to Bluetooth-only.
//

import Foundation
import PigeonCore

struct ContactCard {
  let name: String
  let bundle: PigeonIdentityBundle
  let relayURLs: [URL]
  /// Identity signature over `relayPayload(relayURLs)`. Empty when no URLs are
  /// advertised (or for a received card whose URL signature didn't verify).
  let relaySignature: Data
  /// Olm prekey bundle for async first contact (SECURITY_MODEL.md §5.7). Lets a
  /// scanner open a session and send a first message while this device is
  /// offline. `nil` when not published; a received bundle is honoured only if it
  /// verifies and is bound to this same identity.
  let prekeyBundle: PigeonPrekeyBundle?

  private static let version: UInt8 = 0x03

  init(
    name: String, bundle: PigeonIdentityBundle, relayURLs: [URL], relaySignature: Data,
    prekeyBundle: PigeonPrekeyBundle?
  ) {
    self.name = name
    self.bundle = bundle
    self.relayURLs = relayURLs
    self.relaySignature = relaySignature
    self.prekeyBundle = prekeyBundle
  }

  /// The canonical bytes signed/verified for a set of relay URLs.
  static func relayPayload(_ urls: [URL]) -> Data {
    Data(urls.map(\.absoluteString).joined(separator: "\n").utf8)
  }

  /// Encodes the card as a base64 QR payload.
  func encoded() -> String {
    let payload = PigeonContactCardPayload(
      version: UInt32(Self.version),
      identityBundle: bundle.encoded,
      name: name,
      relayURLs: relayURLs.map(\.absoluteString),
      relaySignature: relaySignature,
      prekeyBundle: prekeyBundle?.encoded ?? Data())
    return (try? encodeContactCardPayload(payload).base64EncodedString()) ?? ""
  }

  /// Parses a scanned QR string, or returns nil if it isn't a Pigeon card.
  init?(scanned string: String) {
    let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
    guard let raw = Data(base64Encoded: trimmed),
      let payload = try? decodeContactCardPayload(raw),
      payload.version == UInt32(Self.version),
      let bundle = try? PigeonIdentityBundle(decoding: payload.identityBundle)
    else {
      return nil
    }
    self.bundle = bundle

    self.name = payload.name

    // Honour the advertised relays only if signed by this very identity.
    let urlField = Self.relayPayload(payload.relayURLs.compactMap(URL.init(string:)))
    if !payload.relaySignature.isEmpty,
      let identity = try? IdentityPublicKey(rawRepresentation: bundle.identityKey),
      identity.isValidSignature(payload.relaySignature, for: urlField)
    {
      self.relayURLs = payload.relayURLs.compactMap(URL.init(string:))
      self.relaySignature = payload.relaySignature
    } else {
      self.relayURLs = []
      self.relaySignature = Data()
    }

    // Honour the prekey bundle only if internally valid (self-signed) and bound
    // to the *same* identity as this card, so a tampered card can at worst deny
    // async delivery, never redirect trust.
    if !payload.prekeyBundle.isEmpty,
      let parsed = try? PigeonPrekeyBundle(decoding: payload.prekeyBundle),
      parsed.identityKey == bundle.identityKey
    {
      self.prekeyBundle = parsed
    } else {
      self.prekeyBundle = nil
    }
  }
}
