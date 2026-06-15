//
//  IdentityKey.swift
//  Pigeon
//
//  The device's long-term cryptographic identity.
//

import Foundation
import CryptoKit

/// A peer's public identity — everything needed to address and verify them,
/// with no private material. This is what gets exchanged via QR code.
struct IdentityPublicKey: Equatable, Sendable {
    /// Ed25519 public key used to verify this identity's signatures.
    let signingKey: Curve25519.Signing.PublicKey

    /// Raw 32-byte representation, suitable for wire encoding / QR payloads.
    var rawRepresentation: Data { signingKey.rawRepresentation }

    init(signingKey: Curve25519.Signing.PublicKey) {
        self.signingKey = signingKey
    }

    init(rawRepresentation: Data) throws {
        self.signingKey = try Curve25519.Signing.PublicKey(rawRepresentation: rawRepresentation)
    }

    static func == (lhs: IdentityPublicKey, rhs: IdentityPublicKey) -> Bool {
        lhs.rawRepresentation == rhs.rawRepresentation
    }

    /// Verifies that `signature` over `data` was produced by this identity.
    func isValidSignature(_ signature: Data, for data: Data) -> Bool {
        signingKey.isValidSignature(signature, for: data)
    }

    /// SHA-256 of the public key — a stable, collision-resistant handle for
    /// this identity. Displayed as a fingerprint and used for the safety number.
    var fingerprintBytes: Data {
        Data(SHA256.hash(data: rawRepresentation))
    }

    /// Human-readable fingerprint, e.g. `A1B2 C3D4 … 7F80` (first/last bytes).
    /// Full comparison should always use the safety number; this is a glance aid.
    var shortFingerprint: String {
        let hex = fingerprintBytes.map { String(format: "%02X", $0) }
        let head = hex.prefix(4).joined()
        let tail = hex.suffix(4).joined()
        return "\(head)…\(tail)"
    }

    /// The full fingerprint as hex grouped in 4-character blocks (for copy/compare).
    var fingerprint: String {
        let hex = fingerprintBytes.map { String(format: "%02X", $0) }.joined()
        return stride(from: 0, to: hex.count, by: 4).map { offset in
            let start = hex.index(hex.startIndex, offsetBy: offset)
            let end = hex.index(start, offsetBy: 4, limitedBy: hex.endIndex) ?? hex.endIndex
            return String(hex[start..<end])
        }.joined(separator: " ")
    }
}
