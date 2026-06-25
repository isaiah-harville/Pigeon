//
//  Contact.swift
//  Pigeon
//
//  A peer whose identity we have verified in person (via QR + safety number).
//

import Foundation
import PigeonFFI

/// A verified peer. The `bundle` carries their Ed25519 identity, Olm Curve25519
/// identity key, and the signature binding them; decoding a `PigeonIdentityBundle`
/// already verified that binding before it could become a Contact.
struct Contact: Identifiable, Equatable {
  let bundle: PigeonIdentityBundle
  var displayName: String
  /// Relay endpoints this contact advertised (from their QR card). Where we
  /// deposit ciphertext for them when they're out of Bluetooth range. Empty for
  /// contacts added before relay support, or who run no relay.
  var relayURLs: [URL] = []
  /// The relay the user prefers for this conversation, chosen from `relayURLs`.
  /// `nil` means automatic (use all advertised relays). Delivery falls back to
  /// the contact's other advertised relays, then our own, if this one is down.
  var preferredRelayURL: URL?
  /// The contact's published prekey bundle (their signed/fallback Olm prekey),
  /// learned from their QR card. Required to open a session: the initiator runs
  /// `establishOutbound` against it. `nil` only for cards without one (which then
  /// cannot be reached, since Olm is async-first with no interactive fallback).
  var prekeyBundle: PigeonPrekeyBundle?
  /// Whether this contact was added by scanning their QR **in person** (so the
  /// safety number was exchanged face to face) rather than pasted from a code
  /// shared over some other channel. Drives the "not verified in person" cue.
  /// Defaults true so contacts added before this distinction read as verified.
  var verifiedInPerson: Bool = true

  /// Identity public key, used as the stable contact id.
  var id: Data { bundle.identityKey }
}
