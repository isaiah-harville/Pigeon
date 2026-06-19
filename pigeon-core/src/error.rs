use core::fmt;

use vodozemac::olm::{DecryptionError, EncryptionError, SessionCreationError};

/// Everything pigeon-core can fail with. Authentication-style failures
/// ([`Error::InvalidSignature`], [`Error::Decryption`]) are deliberately not
/// papered over with retries or fallbacks — a failed binding or AEAD check is a
/// hard stop.
#[derive(Debug)]
pub enum Error {
    /// A key (Ed25519 identity or Curve25519) was not a valid point/length.
    InvalidKey,
    /// An identity-binding or prekey signature did not verify under the
    /// advertised identity key.
    InvalidSignature,
    /// A bundle's byte encoding was the wrong length or otherwise malformed.
    MalformedBundle,
    /// Inbound establishment was handed an Olm message that was not a pre-key
    /// message (only a pre-key message can start a session).
    NotAPreKeyMessage,
    /// The OS entropy source failed while generating the identity key.
    Entropy,
    /// Olm could not create the session (e.g. a stale/consumed one-time key).
    SessionCreation(SessionCreationError),
    /// Olm encryption failed.
    Encryption(EncryptionError),
    /// Olm decryption/authentication failed (tampering, wrong key, or replay).
    Decryption(DecryptionError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidKey => write!(f, "invalid key"),
            Error::InvalidSignature => write!(f, "signature did not verify"),
            Error::MalformedBundle => write!(f, "malformed bundle encoding"),
            Error::NotAPreKeyMessage => write!(f, "expected an Olm pre-key message"),
            Error::Entropy => write!(f, "OS entropy source failed"),
            Error::SessionCreation(e) => write!(f, "session creation failed: {e}"),
            Error::Encryption(e) => write!(f, "encryption failed: {e}"),
            Error::Decryption(e) => write!(f, "decryption failed: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::SessionCreation(e) => Some(e),
            Error::Encryption(e) => Some(e),
            Error::Decryption(e) => Some(e),
            _ => None,
        }
    }
}

impl From<SessionCreationError> for Error {
    fn from(e: SessionCreationError) -> Self {
        Error::SessionCreation(e)
    }
}

impl From<EncryptionError> for Error {
    fn from(e: EncryptionError) -> Self {
        Error::Encryption(e)
    }
}

impl From<DecryptionError> for Error {
    fn from(e: DecryptionError) -> Self {
        Error::Decryption(e)
    }
}
