//
//  Contact.swift
//  Pigeon
//
//  A peer whose identity we have verified in person (via QR + safety number).
//

import Foundation
import PigeonCrypto

/// A verified peer. The `bundle` carries their Ed25519 identity, X25519 Noise
/// static key, and the signature binding them; it must have passed
/// `bundle.isValid()` before becoming a Contact.
struct Contact: Identifiable, Equatable {
  let bundle: IdentityBundle
  var displayName: String
  /// Relay endpoints this contact advertised (from their QR card). Where we
  /// deposit ciphertext for them when they're out of Bluetooth range. Empty for
  /// contacts added before relay support, or who run no relay.
  var relayURLs: [URL] = []
  /// The relay the user prefers for this conversation, chosen from `relayURLs`.
  /// `nil` means automatic (use all advertised relays). Delivery falls back to
  /// the contact's other advertised relays, then our own, if this one is down
  /// (#18).
  var preferredRelayURL: URL?
  /// The contact's published X3DH prekey bundle, learned from their QR card.
  /// Present enables async first contact (messaging them while they're offline);
  /// `nil` for legacy cards, where we fall back to the interactive handshake.
  var prekeyBundle: X3DHPrekeyBundle?
  /// Whether this contact was added by scanning their QR **in person** (so the
  /// safety number was exchanged face to face) rather than pasted from a code
  /// shared over some other channel. Drives the "not verified in person" cue.
  /// Defaults true so contacts added before this distinction read as verified.
  var verifiedInPerson: Bool = true

  /// Identity public key, used as the stable contact id.
  var id: Data { bundle.identityKey }
}
