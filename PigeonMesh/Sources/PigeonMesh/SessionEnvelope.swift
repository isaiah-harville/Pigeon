//
//  SessionEnvelope.swift
//  PigeonMesh
//
//  Identity-addressed envelope carried inside a mesh packet's payload.
//
//  The mesh itself is broadcast/flood: a packet reaches many devices. This
//  envelope says who a message is from and for, and whether it is a handshake
//  or an application message, so the right device routes it to the right
//  session. It carries opaque bytes; it performs no cryptography.
//

import Foundation

public enum EnvelopeError: Error, Equatable {
    case malformedEnvelope
}

/// What an envelope carries.
public enum EnvelopeType: UInt8, Sendable {
    /// A Noise handshake message establishing a session.
    case handshake = 1
    /// An application message (ratchet ciphertext) for an established session.
    case message = 2
    /// A request asking the peer (the initiator) to (re)start a handshake —
    /// used to recover when one side has lost its session (e.g. after restart).
    case rehandshakeRequest = 3
    /// A delivery acknowledgement: the (encrypted) id of a received message,
    /// so the sender knows it landed and can stop retrying.
    case ack = 4
    /// An (encrypted) control/state-sync message, e.g. toggling ephemeral mode.
    case control = 5
}

/// An identity-addressed envelope. `sender`/`recipient` are 32-byte identity
/// public keys; `payload` is handshake bytes or ratchet ciphertext.
///
/// Wire layout (66-byte header): `version(1) ‖ type(1) ‖ sender(32) ‖
/// recipient(32) ‖ payload`.
public struct SessionEnvelope: Equatable, Sendable {
    public static let version: UInt8 = 1
    public static let idSize = 32
    public static let headerSize = 66

    public let type: EnvelopeType
    public let sender: Data
    public let recipient: Data
    public let payload: Data

    public init(type: EnvelopeType, sender: Data, recipient: Data, payload: Data) {
        self.type = type
        self.sender = sender
        self.recipient = recipient
        self.payload = payload
    }

    public func encoded() -> Data {
        var data = Data(capacity: Self.headerSize + payload.count)
        data.append(Self.version)
        data.append(type.rawValue)
        data.append(sender)
        data.append(recipient)
        data.append(payload)
        return data
    }

    public init(decoding data: Data) throws {
        guard data.count >= Self.headerSize, data[data.startIndex] == Self.version else {
            throw EnvelopeError.malformedEnvelope
        }
        let base = data.startIndex
        guard let type = EnvelopeType(rawValue: data[base + 1]) else {
            throw EnvelopeError.malformedEnvelope
        }
        self.type = type
        self.sender = Data(data[(base + 2) ..< (base + 34)])
        self.recipient = Data(data[(base + 34) ..< (base + 66)])
        self.payload = Data(data[(base + 66)...])
    }
}
