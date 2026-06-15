//
//  ContactCard.swift
//  Pigeon
//
//  What a QR code encodes: a device's signed identity bundle plus the display
//  name its owner chose for themselves, so a scanner auto-populates the name.
//

import Foundation
import PigeonCrypto

struct ContactCard {
  let name: String
  let bundle: IdentityBundle

  init(name: String, bundle: IdentityBundle) {
    self.name = name
    self.bundle = bundle
  }

  /// Base64 of `bundle(128 bytes) ‖ name-utf8`, suitable for a QR payload.
  func encoded() -> String {
    (bundle.encoded() + Data(name.utf8)).base64EncodedString()
  }

  /// Parses a scanned QR string, or returns nil if it isn't a Pigeon card.
  init?(scanned string: String) {
    let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
    guard let data = Data(base64Encoded: trimmed), data.count >= IdentityBundle.size,
      let bundle = try? IdentityBundle(decoding: data.prefix(IdentityBundle.size))
    else {
      return nil
    }
    self.bundle = bundle
    self.name = String(decoding: data.dropFirst(IdentityBundle.size), as: UTF8.self)
  }
}
