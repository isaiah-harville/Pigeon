//
//  SecureSession.swift
//  PigeonCrypto
//
//  Ties the Noise handshake to the Double Ratchet into one usable object:
//  drive the handshake, then encrypt/decrypt application messages as wire
//  bytes. This is the single seam the Bluetooth/mesh layers build against.
//

import Foundation
import CryptoKit

public enum SessionError: Error, Equatable {
    case notEstablished
    case alreadyEstablished
    case malformedMessage
}

/// One end of an end-to-end-encrypted conversation.
///
/// Lifecycle:
/// 1. Create with `initiator(localStatic:)` or `responder(localStatic:)`.
/// 2. Pump handshake messages with `writeHandshakeMessage` / `readHandshakeMessage`
///    following the XX order (initiator writes first, then alternates) until
///    `isEstablished` is true.
/// 3. Verify `remoteStaticKey` against the peer's QR identity.
/// 4. Exchange traffic with `encrypt` / `decrypt`.
public final class SecureSession {

    /// Domain-separated derivation of the ratchet's root secret from the Noise
    /// transcript hash, which both ends share once the handshake completes.
    private static let ratchetRootInfo = Data("Pigeon.SessionRoot".utf8)

    private let isInitiator: Bool
    private let handshake: NoiseHandshakeState

    /// The responder's initial ratchet key pair, generated up front so its
    /// public half can ride in handshake message 2. `nil` on the initiator.
    private let responderRatchetKey: DHKeyPair?
    /// The responder ratchet public key the initiator learns from message 2.
    private var remoteRatchetKey: Data?

    private var ratchet: DoubleRatchetSession?
    private var result: NoiseHandshakeResult?

    private init(isInitiator: Bool, staticKey: DHKeyPair) {
        self.isInitiator = isInitiator
        self.handshake = NoiseHandshakeState(initiator: isInitiator, staticKey: staticKey)
        self.responderRatchetKey = isInitiator ? nil : DHKeyPair()
    }

    public static func initiator(localStatic: DHKeyPair) -> SecureSession {
        SecureSession(isInitiator: true, staticKey: localStatic)
    }

    public static func responder(localStatic: DHKeyPair) -> SecureSession {
        SecureSession(isInitiator: false, staticKey: localStatic)
    }

    /// True once the ratchet is ready and `encrypt`/`decrypt` may be used.
    public var isEstablished: Bool { ratchet != nil }

    /// The peer's long-term static public key — verify this against the
    /// identity exchanged in person before trusting the channel.
    public var remoteStaticKey: Data? { result?.remoteStaticKey }

    // MARK: - Handshake pump

    /// Produces the next handshake message. The responder embeds its initial
    /// ratchet public key in message 2's (encrypted) payload.
    public func writeHandshakeMessage() throws -> Data {
        guard !isEstablished else { throw SessionError.alreadyEstablished }
        let payload = (!isInitiator) ? (responderRatchetKey?.publicKey.rawRepresentation ?? Data()) : Data()
        let message = try handshake.writeMessage(payload: payload)
        try finishIfReady()
        return message
    }

    /// Consumes a handshake message. The initiator extracts the responder's
    /// ratchet public key from message 2's payload.
    public func readHandshakeMessage(_ data: Data) throws {
        guard !isEstablished else { throw SessionError.alreadyEstablished }
        let payload = try handshake.readMessage(data)
        if isInitiator, !payload.isEmpty, remoteRatchetKey == nil {
            remoteRatchetKey = payload
        }
        try finishIfReady()
    }

    /// Once the Noise handshake completes, derive the shared root secret and
    /// stand up the appropriate Double Ratchet end.
    private func finishIfReady() throws {
        guard handshake.isComplete, ratchet == nil else { return }
        let res = try handshake.finish()
        result = res

        let rootSecret = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: res.handshakeHash),
            info: Self.ratchetRootInfo,
            outputByteCount: 32
        ).withUnsafeBytes { Data($0) }

        if isInitiator {
            guard let remote = remoteRatchetKey else { throw SessionError.malformedMessage }
            let remoteKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: remote)
            ratchet = try DoubleRatchetSession.initiator(sharedSecret: rootSecret, remotePublicKey: remoteKey)
        } else {
            guard let myRatchetKey = responderRatchetKey else { throw SessionError.malformedMessage }
            ratchet = DoubleRatchetSession.responder(sharedSecret: rootSecret, selfKeyPair: myRatchetKey)
        }
    }

    // MARK: - Application traffic

    /// Encrypts `plaintext` into wire bytes: 40-byte ratchet header ‖ ciphertext.
    public func encrypt(_ plaintext: Data) throws -> Data {
        guard let ratchet else { throw SessionError.notEstablished }
        let message = try ratchet.encrypt(plaintext)
        return message.header.encoded() + message.ciphertext
    }

    /// Decrypts wire bytes produced by a peer's `encrypt`.
    public func decrypt(_ wire: Data) throws -> Data {
        guard let ratchet else { throw SessionError.notEstablished }
        guard wire.count >= 40 else { throw SessionError.malformedMessage }
        let header = try RatchetHeader(decoding: wire.prefix(40))
        let ciphertext = wire.dropFirst(40)
        return try ratchet.decrypt(RatchetMessage(header: header, ciphertext: Data(ciphertext)))
    }
}
