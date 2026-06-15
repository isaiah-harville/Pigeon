//
//  IdentityManager.swift
//  Pigeon
//
//  Owns the device's long-term identity key: generation, persistence, signing.
//

import Foundation
import CryptoKit

/// Creates and holds the device's long-term Ed25519 identity key.
///
/// The private key is generated on first launch and stored in the Keychain
/// (`KeychainStore`). It never leaves the device. The public half — exchanged
/// in person via QR — is what other peers use to address and verify us.
///
/// Curve25519/Ed25519 (rather than Secure Enclave's P-256) is used deliberately:
/// it is the curve required by the Noise + Double Ratchet stack we build on top.
@Observable
final class IdentityManager {

    /// Keychain account under which the identity private key is stored.
    private static let identityAccount = "identity.ed25519.private"

    private let store: KeychainStore
    private var privateKey: Curve25519.Signing.PrivateKey

    /// The public identity safe to share with peers.
    var publicKey: IdentityPublicKey {
        IdentityPublicKey(signingKey: privateKey.publicKey)
    }

    /// Loads the existing identity, generating and persisting a new one if none exists.
    init(store: KeychainStore = KeychainStore(account: IdentityManager.identityAccount)) throws {
        self.store = store

        if let existing = try store.get() {
            self.privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: existing)
        } else {
            let fresh = Curve25519.Signing.PrivateKey()
            try store.set(fresh.rawRepresentation)
            self.privateKey = fresh
        }
    }

    /// Signs `data` with the identity key. Used to authenticate ephemeral
    /// session keys (e.g. the static key offered during the Noise handshake).
    func sign(_ data: Data) throws -> Data {
        try privateKey.signature(for: data)
    }

    /// Destroys the current identity and generates a fresh one.
    /// Irreversible: all existing trust relationships become invalid.
    func resetIdentity() throws {
        let fresh = Curve25519.Signing.PrivateKey()
        try store.set(fresh.rawRepresentation)
        self.privateKey = fresh
    }
}
