use core::fmt;

use vodozemac::olm::{DecryptionError, EncryptionError, SessionCreationError};

use crate::group::PolicyError;
use crate::identity::IdentityError;
use crate::storage::StorageError;

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
    /// Persisted pairwise state could not be serialized or decoded.
    Serialization,
    /// An input exceeded a named, pre-cryptographic resource limit.
    ResourceLimit(&'static str),
    /// A versioned cross-language object is not supported by this core.
    UnsupportedVersion { kind: &'static str, version: u32 },
    /// Durable checkpoint replacement failed.
    Persistence(StorageError),
    /// The platform secure-identity operation failed.
    Identity(IdentityError),
    /// Authenticated group policy rejected a requested or received transition.
    GroupPolicy(PolicyError),
    /// OpenMLS rejected an operation or persisted group state.
    Mls(&'static str),
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
            Error::Serialization => write!(f, "pairwise state serialization failed"),
            Error::ResourceLimit(name) => write!(f, "resource limit exceeded: {name}"),
            Error::UnsupportedVersion { kind, version } => {
                write!(f, "unsupported {kind} version {version}")
            }
            Error::Persistence(error) => write!(f, "checkpoint persistence failed: {error}"),
            Error::Identity(error) => write!(f, "secure identity failed: {error}"),
            Error::GroupPolicy(error) => write!(f, "{error}"),
            Error::Mls(operation) => write!(f, "MLS operation failed: {operation}"),
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
            Error::Persistence(error) => Some(error),
            Error::Identity(error) => Some(error),
            Error::GroupPolicy(error) => Some(error),
            _ => None,
        }
    }
}

impl From<StorageError> for Error {
    fn from(error: StorageError) -> Self {
        Self::Persistence(error)
    }
}

impl From<IdentityError> for Error {
    fn from(error: IdentityError) -> Self {
        Self::Identity(error)
    }
}

impl From<PolicyError> for Error {
    fn from(error: PolicyError) -> Self {
        Self::GroupPolicy(error)
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
