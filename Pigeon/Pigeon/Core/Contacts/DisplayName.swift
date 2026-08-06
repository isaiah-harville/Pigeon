//
//  DisplayName.swift
//  Pigeon
//
//  Sanitizes the human-readable names that reach the UI.
//
//  A contact's name arrives inside a scanned or pasted card, which is attacker-
//  controlled: the identity binding proves who the key belongs to, never that
//  the name attached to it is reasonable. An unclamped name is rendered in the
//  chats list, the contacts book, alerts, and notifications, so a hostile card
//  could otherwise use length or Unicode direction overrides to distort or spoof
//  what those surfaces read as — the classic "Alice\u{202E}…" trick that makes
//  one identity display as another.
//
//  Our own name gets the same treatment: it travels in our card and lands on
//  someone else's screen, so it deserves the same hygiene at the source.
//

import Foundation

enum DisplayName {

  /// Longest name kept. Comfortably past any real name while bounding what a
  /// single card can push into a list row or a notification.
  static let maxLength = 64

  /// Strips characters that let text lie about its own shape — line breaks, and
  /// the Unicode bidirectional overrides/isolates — collapses runs of
  /// whitespace, trims, and clamps the length. Returns an empty string if
  /// nothing legible survives; callers substitute their own placeholder.
  static func sanitize(_ raw: String) -> String {
    let stripped = raw.unicodeScalars
      .filter { !isDisallowed($0) }
      .reduce(into: "") { $0.unicodeScalars.append($1) }
    let collapsed = stripped.split(whereSeparator: \.isWhitespace).joined(separator: " ")
    return String(collapsed.prefix(maxLength))
  }

  /// Drops the formatting scalars (bidi overrides and isolates, zero-width
  /// joiners) and the non-whitespace control characters. Whitespace controls —
  /// newline, tab, carriage return — are deliberately *kept* here so they
  /// survive as separators for the collapse step: a name spanning two lines
  /// should read "Ada Lovelace", not "AdaLovelace".
  private static func isDisallowed(_ scalar: Unicode.Scalar) -> Bool {
    if scalar.properties.generalCategory == .format { return true }
    return scalar.properties.generalCategory == .control && !scalar.properties.isWhitespace
  }
}
