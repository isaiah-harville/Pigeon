//
//  NoiseHandshake.swift
//  PigeonCrypto
//
//  Clean-room implementation of the Noise Protocol Framework handshake,
//  instantiated as Noise_XX_25519_ChaChaPoly_SHA256.
//  Spec: https://noiseprotocol.org/noise.html
//
//  XX gives mutual authentication without either side pre-knowing the other's
//  static key; both static keys are exchanged (the initiator's encrypted) and
//  can be checked against the identity keys swapped in person via QR. The
//  output seeds the Double Ratchet.
//
//  As with the rest of PigeonCrypto, all cryptographic math is delegated to
//  CryptoKit; this file only implements the protocol's state machine.
//
//  NOTE: validated here for self-consistency (both ends interoperate). Cross-
//  validation against the official Noise test vectors is a tracked follow-up
//  and is required before the security audit.
//

import Foundation
import CryptoKit

public enum NoiseError: Error, Equatable {
    case decryptionFailed
    case messageTooShort
    case notYourTurn
    case handshakeNotFinished
    case handshakeAlreadyFinished
}

// MARK: - Noise HKDF

/// Noise's HKDF: HMAC-SHA256 extract over `chainingKey`, then 1–3 expand blocks.
/// Equivalent to HKDF-Expand with empty info, but written out so the spec
/// correspondence is auditable and empty IKM (used by Split) is handled directly.
private func noiseHKDF(chainingKey: Data, inputKeyMaterial: Data, outputs: Int) -> [Data] {
    let tempKey = HMAC<SHA256>.authenticationCode(for: inputKeyMaterial, using: SymmetricKey(data: chainingKey))
    let tk = SymmetricKey(data: Data(tempKey))

    let o1 = Data(HMAC<SHA256>.authenticationCode(for: Data([0x01]), using: tk))
    if outputs == 1 { return [o1] }

    let o2 = Data(HMAC<SHA256>.authenticationCode(for: o1 + Data([0x02]), using: tk))
    if outputs == 2 { return [o1, o2] }

    let o3 = Data(HMAC<SHA256>.authenticationCode(for: o2 + Data([0x03]), using: tk))
    return [o1, o2, o3]
}

// MARK: - CipherState

/// A keyed AEAD cipher with a monotonically increasing nonce, per the Noise
/// `CipherState` object. Backs both handshake encryption and the post-handshake
/// transport ciphers returned by `split()`.
public final class NoiseCipherState {
    private let key: SymmetricKey
    private var nonce: UInt64 = 0

    init(key: Data) { self.key = SymmetricKey(data: key) }

    /// ChaCha20-Poly1305 nonce: 4 zero bytes ‖ 64-bit little-endian counter.
    private func formatNonce(_ n: UInt64) throws -> ChaChaPoly.Nonce {
        var bytes = Data(repeating: 0, count: 4)
        bytes.append(contentsOf: withUnsafeBytes(of: n.littleEndian, Array.init))
        return try ChaChaPoly.Nonce(data: bytes)
    }

    /// Encrypts with the current nonce (binding `ad`) and advances the counter.
    /// Returns ciphertext ‖ 16-byte tag (the nonce is implicit).
    public func encrypt(plaintext: Data, ad: Data) throws -> Data {
        let box = try ChaChaPoly.seal(plaintext, using: key, nonce: try formatNonce(nonce), authenticating: ad)
        nonce &+= 1
        return box.ciphertext + box.tag
    }

    /// Decrypts ciphertext ‖ tag with the current nonce, advancing on success.
    public func decrypt(ciphertext: Data, ad: Data) throws -> Data {
        guard ciphertext.count >= 16 else { throw NoiseError.messageTooShort }
        let tag = ciphertext.suffix(16)
        let ct = ciphertext.prefix(ciphertext.count - 16)
        do {
            let box = try ChaChaPoly.SealedBox(nonce: try formatNonce(nonce), ciphertext: ct, tag: tag)
            let plaintext = try ChaChaPoly.open(box, using: key, authenticating: ad)
            nonce &+= 1
            return plaintext
        } catch {
            throw NoiseError.decryptionFailed
        }
    }
}

// MARK: - SymmetricState

/// The Noise `SymmetricState`: chaining key + transcript hash, plus an optional
/// handshake cipher once a key has been mixed in.
private final class SymmetricState {
    private(set) var chainingKey: Data
    private(set) var hash: Data
    private var cipherKey: Data?
    private var nonce: UInt64 = 0

    /// Whether a cipher key has been mixed in yet. Controls whether a static
    /// key in a message is encrypted (and so carries an extra 16-byte tag).
    var hasCipherKey: Bool { cipherKey != nil }

    init(protocolName: String) {
        let nameBytes = Data(protocolName.utf8)
        // Protocol name is exactly 32 bytes here, so it is used verbatim as h.
        precondition(nameBytes.count == 32, "protocol name must be HASHLEN bytes for this build")
        self.hash = nameBytes
        self.chainingKey = nameBytes
    }

    func mixHash(_ data: Data) {
        hash = Data(SHA256.hash(data: hash + data))
    }

    func mixKey(_ inputKeyMaterial: Data) {
        let out = noiseHKDF(chainingKey: chainingKey, inputKeyMaterial: inputKeyMaterial, outputs: 2)
        chainingKey = out[0]
        cipherKey = out[1]
        nonce = 0
    }

    private func formatNonce(_ n: UInt64) throws -> ChaChaPoly.Nonce {
        var bytes = Data(repeating: 0, count: 4)
        bytes.append(contentsOf: withUnsafeBytes(of: n.littleEndian, Array.init))
        return try ChaChaPoly.Nonce(data: bytes)
    }

    func encryptAndHash(_ plaintext: Data) throws -> Data {
        guard let key = cipherKey else {
            mixHash(plaintext) // no key yet: plaintext travels in the clear
            return plaintext
        }
        let box = try ChaChaPoly.seal(plaintext, using: SymmetricKey(data: key),
                                      nonce: try formatNonce(nonce), authenticating: hash)
        nonce &+= 1
        let ciphertext = box.ciphertext + box.tag
        mixHash(ciphertext)
        return ciphertext
    }

    func decryptAndHash(_ ciphertext: Data) throws -> Data {
        guard let key = cipherKey else {
            mixHash(ciphertext)
            return ciphertext
        }
        guard ciphertext.count >= 16 else { throw NoiseError.messageTooShort }
        let tag = ciphertext.suffix(16)
        let ct = ciphertext.prefix(ciphertext.count - 16)
        let plaintext: Data
        do {
            let box = try ChaChaPoly.SealedBox(nonce: try formatNonce(nonce), ciphertext: ct, tag: tag)
            plaintext = try ChaChaPoly.open(box, using: SymmetricKey(data: key), authenticating: hash)
        } catch {
            throw NoiseError.decryptionFailed
        }
        nonce &+= 1
        mixHash(ciphertext)
        return plaintext
    }

    /// Derives the two transport ciphers once the handshake completes.
    func split() -> (NoiseCipherState, NoiseCipherState) {
        let out = noiseHKDF(chainingKey: chainingKey, inputKeyMaterial: Data(), outputs: 2)
        return (NoiseCipherState(key: out[0]), NoiseCipherState(key: out[1]))
    }
}

// MARK: - HandshakeState

/// The completed handshake: directional transport ciphers, the peer's static
/// public key (to verify against their QR identity), and the handshake hash
/// (a unique channel binding usable to seed the Double Ratchet).
public struct NoiseHandshakeResult {
    public let send: NoiseCipherState
    public let receive: NoiseCipherState
    public let remoteStaticKey: Data
    public let handshakeHash: Data
}

/// Drives the Noise_XX handshake. Create with the local long-term static key
/// pair, then alternate `writeMessage` / `readMessage` per the XX pattern:
/// initiator writes messages 0 and 2, responder writes message 1.
public final class NoiseHandshakeState {

    private static let protocolName = "Noise_XX_25519_ChaChaPoly_SHA256"
    private static let patterns: [[String]] = [["e"], ["e", "ee", "s", "es"], ["s", "se"]]
    private static let dhLen = 32

    private let isInitiator: Bool
    private let s: DHKeyPair          // local static
    private var e: DHKeyPair?         // local ephemeral
    private var rs: Data?             // remote static (raw)
    private var re: Data?             // remote ephemeral (raw)
    private let sym: SymmetricState
    private var messageIndex = 0

    public init(initiator: Bool, staticKey: DHKeyPair) {
        self.isInitiator = initiator
        self.s = staticKey
        self.sym = SymmetricState(protocolName: Self.protocolName)
        sym.mixHash(Data()) // empty prologue
    }

    /// True once both transport ciphers are ready.
    public var isComplete: Bool { messageIndex >= Self.patterns.count }

    private var isMyTurn: Bool {
        guard !isComplete else { return false }
        let initiatorWrites = (messageIndex % 2 == 0)
        return initiatorWrites == isInitiator
    }

    private func dh(_ keyPair: DHKeyPair, _ remote: Data) throws -> Data {
        try keyPair.sharedSecret(with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: remote))
    }

    /// Produces the next handshake message containing `payload` (often empty).
    public func writeMessage(payload: Data = Data()) throws -> Data {
        guard !isComplete else { throw NoiseError.handshakeAlreadyFinished }
        guard isMyTurn else { throw NoiseError.notYourTurn }

        var buffer = Data()
        for token in Self.patterns[messageIndex] {
            switch token {
            case "e":
                let ephemeral = DHKeyPair()
                e = ephemeral
                buffer.append(ephemeral.publicKey.rawRepresentation)
                sym.mixHash(ephemeral.publicKey.rawRepresentation)
            case "s":
                buffer.append(try sym.encryptAndHash(s.publicKey.rawRepresentation))
            default:
                try mixDH(token)
            }
        }
        buffer.append(try sym.encryptAndHash(payload))
        messageIndex += 1
        return buffer
    }

    /// Consumes a handshake message, returning its (decrypted) payload.
    public func readMessage(_ message: Data) throws -> Data {
        guard !isComplete else { throw NoiseError.handshakeAlreadyFinished }
        guard !isMyTurn else { throw NoiseError.notYourTurn }

        var rest = message
        for token in Self.patterns[messageIndex] {
            switch token {
            case "e":
                guard rest.count >= Self.dhLen else { throw NoiseError.messageTooShort }
                let key = rest.prefix(Self.dhLen)
                re = Data(key)
                sym.mixHash(Data(key))
                rest = rest.dropFirst(Self.dhLen)
            case "s":
                let length = sym.hasCipherKey ? Self.dhLen + 16 : Self.dhLen
                guard rest.count >= length else { throw NoiseError.messageTooShort }
                let chunk = rest.prefix(length)
                rs = try sym.decryptAndHash(Data(chunk))
                rest = rest.dropFirst(length)
            default:
                try mixDH(token)
            }
        }
        let payload = try sym.decryptAndHash(Data(rest))
        messageIndex += 1
        return payload
    }

    private func mixDH(_ token: String) throws {
        switch token {
        case "ee":
            sym.mixKey(try dh(e!, re!))
        case "es":
            sym.mixKey(isInitiator ? try dh(e!, rs!) : try dh(s, re!))
        case "se":
            sym.mixKey(isInitiator ? try dh(s, re!) : try dh(e!, rs!))
        case "ss":
            sym.mixKey(try dh(s, rs!))
        default:
            break
        }
    }

    /// Finalizes the handshake into transport ciphers + peer identity binding.
    /// For the initiator, `send` is the first split cipher; for the responder
    /// the roles are swapped so both ends agree on direction.
    public func finish() throws -> NoiseHandshakeResult {
        guard isComplete else { throw NoiseError.handshakeNotFinished }
        guard let remoteStatic = rs else { throw NoiseError.handshakeNotFinished }
        let (c1, c2) = sym.split()
        let send = isInitiator ? c1 : c2
        let receive = isInitiator ? c2 : c1
        return NoiseHandshakeResult(send: send, receive: receive,
                                    remoteStaticKey: remoteStatic,
                                    handshakeHash: sym.hash)
    }
}
