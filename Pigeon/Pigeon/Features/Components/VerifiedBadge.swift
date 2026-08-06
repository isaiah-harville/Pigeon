//
//  VerifiedBadge.swift
//  Pigeon
//
//  The trust cue: whether this contact's safety number was compared face to
//  face. Deliberately separate from the lock (encryption) cue — every chat is
//  end-to-end encrypted, including with contacts added from a pasted code, so
//  the lock says nothing about *who* is on the other end. This badge does.
//

import SwiftUI

/// A small shield showing a contact's verification state: a green checkmark
/// shield when the safety number was confirmed in person, an orange
/// exclamation shield when it wasn't. Shown next to the contact's name.
struct VerifiedBadge: View {
  let verified: Bool
  /// The badge's type size, so it can sit next to a headline or a caption.
  var font: Font = .caption

  var body: some View {
    Image(systemName: verified ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
      .font(font)
      .foregroundStyle(verified ? Color.green : Color.orange)
      .accessibilityLabel(verified ? "Verified in person" : "Not verified in person")
  }
}

/// The badge plus its wording, for headers and rows with space to explain the
/// state rather than just flag it.
struct VerifiedLabel: View {
  let verified: Bool

  var body: some View {
    HStack(spacing: 5) {
      VerifiedBadge(verified: verified, font: .caption2)
      Text(verified ? "Verified in person" : "Not verified in person")
        .foregroundStyle(verified ? Color.green : Color.orange)
    }
    .accessibilityElement(children: .combine)
  }
}

#Preview {
  VStack(alignment: .leading, spacing: 12) {
    HStack {
      Text("Ada").font(.headline)
      VerifiedBadge(verified: true)
    }
    HStack {
      Text("Grace").font(.headline)
      VerifiedBadge(verified: false)
    }
    VerifiedLabel(verified: true).font(.footnote)
    VerifiedLabel(verified: false).font(.footnote)
  }
  .padding()
}
