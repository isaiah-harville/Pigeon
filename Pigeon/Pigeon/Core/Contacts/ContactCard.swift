//
//  ContactCard.swift
//  Pigeon
//
//  What a QR code encodes: a device's signed identity bundle, the display name
//  its owner chose, and the relay endpoints it can be reached at off-Bluetooth.
//
//  Wire format (base64), all fields uint16-BE length-prefixed:
//    bundle (128 bytes, signed)  ‖  0x02 version  ‖  name (UTF-8)  ‖
//    relay URLs (UTF-8, newline-separated)  ‖  identity signature over the URLs
//
//  Only the 128-byte bundle carries the identity ↔ Noise-static binding. The
//  relay URLs are *also* signed by the identity key (a separate signature, so
//  the crypto package is untouched): a scanner honours them only if that
//  signature verifies, otherwise it drops them and falls back to Bluetooth-only.
//  This means a tamperer who edits the URLs (e.g. in a pasted card) can cause at
//  worst a denial of delivery, never a metadata leak to a relay they chose, and
//  never anything affecting confidentiality or trust. A missing version byte is
//  a legacy (name-only) card.
//

import Foundation
import PigeonCrypto

struct ContactCard {
  let name: String
  let bundle: IdentityBundle
  let relayURLs: [URL]
  /// Identity signature over `relayPayload(relayURLs)`. Empty when no URLs are
  /// advertised (or for a received card whose URL signature didn't verify).
  let relaySignature: Data

  private static let version: UInt8 = 0x02

  init(
    name: String, bundle: IdentityBundle, relayURLs: [URL] = [], relaySignature: Data = Data()
  ) {
    self.name = name
    self.bundle = bundle
    self.relayURLs = relayURLs
    self.relaySignature = relaySignature
  }

  /// The canonical bytes signed/verified for a set of relay URLs.
  static func relayPayload(_ urls: [URL]) -> Data {
    Data(urls.map(\.absoluteString).joined(separator: "\n").utf8)
  }

  /// Encodes the card as a base64 QR payload.
  func encoded() -> String {
    var data = bundle.encoded()
    data.append(Self.version)
    Self.appendField(&data, Data(name.utf8))
    Self.appendField(&data, Self.relayPayload(relayURLs))
    Self.appendField(&data, relaySignature)
    return data.base64EncodedString()
  }

  /// Parses a scanned QR string, or returns nil if it isn't a Pigeon card.
  init?(scanned string: String) {
    let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
    guard let raw = Data(base64Encoded: trimmed), raw.count >= IdentityBundle.size,
      let bundle = try? IdentityBundle(decoding: raw.prefix(IdentityBundle.size))
    else {
      return nil
    }
    self.bundle = bundle

    // A fresh, zero-based copy so field math is straightforward.
    let body = Data(raw.dropFirst(IdentityBundle.size))
    guard body.first == Self.version else {
      // Legacy card: everything after the bundle is the name; no relays.
      self.name = String(decoding: body, as: UTF8.self)
      self.relayURLs = []
      self.relaySignature = Data()
      return
    }

    var cursor = 1  // past the version byte
    guard let nameField = Self.readField(body, &cursor),
      let urlField = Self.readField(body, &cursor),
      let signatureField = Self.readField(body, &cursor)
    else { return nil }

    self.name = String(decoding: nameField, as: UTF8.self)
    // Honour the advertised relays only if signed by this very identity.
    if !signatureField.isEmpty,
      let identity = try? IdentityPublicKey(rawRepresentation: bundle.identityKey),
      identity.isValidSignature(signatureField, for: urlField)
    {
      self.relayURLs = String(decoding: urlField, as: UTF8.self)
        .split(separator: "\n").compactMap { URL(string: String($0)) }
      self.relaySignature = signatureField
    } else {
      self.relayURLs = []
      self.relaySignature = Data()
    }
  }

  // MARK: - uint16-BE length-prefixed fields

  private static func appendField(_ data: inout Data, _ field: Data) {
    let length = UInt16(min(field.count, 0xFFFF))
    data.append(UInt8(length >> 8))
    data.append(UInt8(length & 0xFF))
    data.append(field.prefix(Int(length)))
  }

  private static func readField(_ data: Data, _ cursor: inout Int) -> Data? {
    guard cursor + 2 <= data.count else { return nil }
    let length = Int(data[cursor]) << 8 | Int(data[cursor + 1])
    cursor += 2
    guard cursor + length <= data.count else { return nil }
    let field = data.subdata(in: cursor..<(cursor + length))
    cursor += length
    return field
  }
}
