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
import PigeonFFI

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
  private static let shareScheme = "pigeon"
  private static let shareHost = "contact"
  static let maximumRelayCount = 8
  private static let maximumRelayURLLength = 2_048

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

  /// A tappable contact link suitable for sharing with someone who is not
  /// physically present. The link contains only the same signed public material
  /// as the QR card; private keys never leave this device.
  var shareURL: URL? {
    var components = URLComponents()
    components.scheme = Self.shareScheme
    components.host = Self.shareHost
    components.queryItems = [URLQueryItem(name: "card", value: Self.base64URL(encoded()))]
    return components.url
  }

  /// Parses a scanned QR payload, pasted code, or shared Pigeon contact link.
  /// Returns nil if the input is not a valid, self-consistent contact card.
  init?(scanned string: String) {
    let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
    let encoded = Self.cardPayload(from: trimmed) ?? trimmed
    guard let raw = Data(base64Encoded: Self.base64Standard(encoded)),
      let payload = try? decodeContactCardPayload(raw),
      payload.version == UInt32(Self.version),
      let bundle = try? PigeonIdentityBundle(decoding: payload.identityBundle)
    else {
      return nil
    }
    self.bundle = bundle

    self.name = payload.name

    // Honour a small, syntactically valid WebSocket relay set only if signed by
    // this identity. Incoming requests do not activate these endpoints until
    // the recipient accepts, preventing pre-consent network connections.
    let parsedRelayURLs = payload.relayURLs.compactMap(URL.init(string:))
    let relaysAreValid =
      payload.relayURLs.count <= Self.maximumRelayCount
      && parsedRelayURLs.count == payload.relayURLs.count
      && parsedRelayURLs.allSatisfy(Self.isValidRelayURL)
    let urlField = Self.relayPayload(parsedRelayURLs)
    if relaysAreValid, !payload.relaySignature.isEmpty,
      let identity = try? IdentityPublicKey(rawRepresentation: bundle.identityKey),
      identity.isValidSignature(payload.relaySignature, for: urlField)
    {
      self.relayURLs = parsedRelayURLs
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

  private static func isValidRelayURL(_ url: URL) -> Bool {
    guard url.absoluteString.utf8.count <= maximumRelayURLLength,
      let scheme = url.scheme?.lowercased(), scheme == "ws" || scheme == "wss",
      let host = url.host, !host.isEmpty,
      url.user == nil, url.password == nil
    else { return false }
    return true
  }

  private static func cardPayload(from string: String) -> String? {
    guard let components = URLComponents(string: string),
      components.scheme?.lowercased() == shareScheme,
      components.host?.lowercased() == shareHost
    else {
      return nil
    }
    return components.queryItems?.first { $0.name == "card" }?.value
  }

  /// Base64 uses `+` and `/`, which survive a `URLComponents` round trip but are
  /// mangled by any intermediary that form-decodes a query (`+` becomes a space).
  /// Links travel through channels we don't control, so they carry base64url.
  private static func base64URL(_ base64: String) -> String {
    base64
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  /// Restores standard base64 (with padding) from base64url. Standard base64
  /// contains neither `-` nor `_`, so scanned QR payloads pass through unchanged.
  private static func base64Standard(_ encoded: String) -> String {
    var standard =
      encoded
      .replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    let remainder = standard.count % 4
    if remainder > 0 { standard += String(repeating: "=", count: 4 - remainder) }
    return standard
  }
}
