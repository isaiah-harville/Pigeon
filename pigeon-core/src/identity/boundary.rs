//! Platform-backed signing boundary. Private identity material never crosses it.

use core::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityPurpose {
    Root,
    Mls,
    Relay,
    GroupCapability([u8; 32]),
    GroupRecovery([u8; 32]),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityError {
    Unavailable,
    SigningFailed,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("secure identity is unavailable"),
            Self::SigningFailed => formatter.write_str("secure identity signing failed"),
        }
    }
}

impl std::error::Error for IdentityError {}

pub trait SecureIdentity: Send + Sync {
    fn ensure_public_key(&self, purpose: IdentityPurpose) -> Result<[u8; 32], IdentityError>;
    fn sign(&self, purpose: IdentityPurpose, message: &[u8]) -> Result<[u8; 64], IdentityError>;
}
