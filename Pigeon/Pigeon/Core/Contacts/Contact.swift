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

    /// Identity public key, used as the stable contact id.
    var id: Data { bundle.identityKey }
}
