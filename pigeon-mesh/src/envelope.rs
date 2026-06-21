//! Identity-addressed envelope carried inside a mesh packet's payload.
//!
//! The mesh itself is broadcast/flood: a packet reaches many devices. This
//! envelope says who a message is from and for, and whether it is a handshake
//! or an application message, so the right device routes it to the right
//! session. It carries opaque bytes; it performs no cryptography.

/// Protocol version byte at the head of every envelope.
pub const VERSION: u8 = 1;
/// Length of a sender/recipient identity key, in bytes.
pub const ID_SIZE: usize = 32;
/// Fixed header size: `version(1) ‖ type(1) ‖ sender(32) ‖ recipient(32)`.
pub const HEADER_SIZE: usize = 66;

/// A malformed envelope could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The bytes were too short, the version unknown, or the type byte invalid.
    MalformedEnvelope,
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("malformed session envelope")
    }
}

impl std::error::Error for EnvelopeError {}

/// What an envelope carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EnvelopeType {
    /// A handshake message establishing a session.
    Handshake = 1,
    /// An application message (ratchet ciphertext) for an established session.
    Message = 2,
    /// A request asking the peer (the initiator) to (re)start a handshake —
    /// used to recover when one side has lost its session (e.g. after restart).
    RehandshakeRequest = 3,
    /// A delivery acknowledgement: the (encrypted) id of a received message,
    /// so the sender knows it landed and can stop retrying.
    Ack = 4,
    /// An (encrypted) control/state-sync message, e.g. toggling ephemeral mode.
    Control = 5,
    /// An X3DH async first-contact initiation header (cleartext prekey/identity
    /// metadata) sent by the initiator ahead of the first `message`, so a peer
    /// who was offline can reconstruct the session.
    X3dhInit = 6,
}

impl EnvelopeType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Handshake),
            2 => Some(Self::Message),
            3 => Some(Self::RehandshakeRequest),
            4 => Some(Self::Ack),
            5 => Some(Self::Control),
            6 => Some(Self::X3dhInit),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// An identity-addressed envelope. `sender`/`recipient` are 32-byte identity
/// public keys; `payload` is handshake bytes or ratchet ciphertext.
///
/// Wire layout (66-byte header): `version(1) ‖ type(1) ‖ sender(32) ‖
/// recipient(32) ‖ payload`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionEnvelope {
    pub kind: EnvelopeType,
    pub sender: Vec<u8>,
    pub recipient: Vec<u8>,
    pub payload: Vec<u8>,
}

impl SessionEnvelope {
    pub fn new(kind: EnvelopeType, sender: Vec<u8>, recipient: Vec<u8>, payload: Vec<u8>) -> Self {
        Self {
            kind,
            sender,
            recipient,
            payload,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE + self.payload.len());
        out.push(VERSION);
        out.push(self.kind.as_u8());
        out.extend_from_slice(&self.sender);
        out.extend_from_slice(&self.recipient);
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, EnvelopeError> {
        if data.len() < HEADER_SIZE || data[0] != VERSION {
            return Err(EnvelopeError::MalformedEnvelope);
        }
        let kind = EnvelopeType::from_u8(data[1]).ok_or(EnvelopeError::MalformedEnvelope)?;
        Ok(Self {
            kind,
            sender: data[2..34].to_vec(),
            recipient: data[34..66].to_vec(),
            payload: data[66..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> Vec<u8> {
        vec![byte; ID_SIZE]
    }

    #[test]
    fn round_trip_handshake() {
        let env = SessionEnvelope::new(
            EnvelopeType::Handshake,
            id(0xA1),
            id(0xB2),
            b"e,ee,s,es".to_vec(),
        );
        let decoded = SessionEnvelope::decode(&env.encode()).unwrap();
        assert_eq!(decoded, env);
        assert_eq!(decoded.kind, EnvelopeType::Handshake);
    }

    #[test]
    fn round_trip_message() {
        let env = SessionEnvelope::new(
            EnvelopeType::Message,
            id(0x11),
            id(0x22),
            b"ciphertext".to_vec(),
        );
        let decoded = SessionEnvelope::decode(&env.encode()).unwrap();
        assert_eq!(decoded.sender, id(0x11));
        assert_eq!(decoded.recipient, id(0x22));
        assert_eq!(decoded.payload, b"ciphertext");
    }

    #[test]
    fn empty_payload_is_valid() {
        let env = SessionEnvelope::new(EnvelopeType::Handshake, id(1), id(2), Vec::new());
        let decoded = SessionEnvelope::decode(&env.encode()).unwrap();
        assert_eq!(decoded.payload, Vec::<u8>::new());
        assert_eq!(env.encode().len(), HEADER_SIZE);
    }

    #[test]
    fn decode_rejects_short() {
        assert_eq!(
            SessionEnvelope::decode(&[1u8; 10]),
            Err(EnvelopeError::MalformedEnvelope)
        );
    }

    #[test]
    fn decode_rejects_bad_version() {
        let mut bytes =
            SessionEnvelope::new(EnvelopeType::Message, id(1), id(2), Vec::new()).encode();
        bytes[0] = 0x09;
        assert_eq!(
            SessionEnvelope::decode(&bytes),
            Err(EnvelopeError::MalformedEnvelope)
        );
    }

    #[test]
    fn decode_rejects_bad_type() {
        let mut bytes =
            SessionEnvelope::new(EnvelopeType::Message, id(1), id(2), Vec::new()).encode();
        bytes[1] = 0x07; // not a valid EnvelopeType
        assert_eq!(
            SessionEnvelope::decode(&bytes),
            Err(EnvelopeError::MalformedEnvelope)
        );
    }
}
