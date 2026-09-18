//! UniFFI surface for `pigeon-core` — the seam the Swift app calls across.
//!
//! Protocol behavior crosses through the transactional [`FfiClient`] as opaque
//! command/output bytes. Identity keys, pairwise ratchets, and MLS state remain
//! inside `pigeon-core`, which stays free of UniFFI coupling.

use pigeon_core::{IdentityBundle, PrekeyBundle};

uniffi::setup_scaffolding!();

mod client;
pub use client::{
    Checkpoint, CheckpointStore, FfiClient, IdentityPurposeKind, IdentityPurposeRequest,
    PlatformError, PlatformIdentity,
};

/// The transport-agnostic mesh surface (framing, fragmentation, routing,
/// envelope), wrapping `pigeon-mesh`. Carries opaque bytes only — no crypto.
mod mesh;

/// Everything the FFI can fail with. Mirrors [`pigeon_core::Error`] plus the
/// serialization and persistence boundaries owned by this crate.
#[derive(Debug, uniffi::Error)]
pub enum PigeonError {
    InvalidKey,
    InvalidSignature,
    MalformedBundle,
    NotAPreKeyMessage,
    Entropy,
    SessionCreation,
    Encryption,
    Decryption,
    Serialization,
    ResourceLimit,
    UnsupportedVersion,
    Persistence,
    Identity,
    GroupPolicy,
    Mls,
}

impl std::fmt::Display for PigeonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            PigeonError::InvalidKey => "invalid key",
            PigeonError::InvalidSignature => "signature did not verify",
            PigeonError::MalformedBundle => "malformed bundle or message encoding",
            PigeonError::NotAPreKeyMessage => "expected an Olm pre-key message",
            PigeonError::Entropy => "OS entropy source failed",
            PigeonError::SessionCreation => "session creation failed",
            PigeonError::Encryption => "encryption failed",
            PigeonError::Decryption => "decryption failed",
            PigeonError::Serialization => "state serialization failed",
            PigeonError::ResourceLimit => "resource limit exceeded",
            PigeonError::UnsupportedVersion => "unsupported protocol version",
            PigeonError::Persistence => "checkpoint persistence failed",
            PigeonError::Identity => "secure identity operation failed",
            PigeonError::GroupPolicy => "group policy rejected the transition",
            PigeonError::Mls => "MLS operation failed",
        };
        f.write_str(message)
    }
}

impl std::error::Error for PigeonError {}

impl From<pigeon_core::Error> for PigeonError {
    fn from(error: pigeon_core::Error) -> Self {
        use pigeon_core::Error as CoreError;
        match error {
            CoreError::InvalidKey => PigeonError::InvalidKey,
            CoreError::InvalidSignature => PigeonError::InvalidSignature,
            CoreError::MalformedBundle => PigeonError::MalformedBundle,
            CoreError::NotAPreKeyMessage => PigeonError::NotAPreKeyMessage,
            CoreError::Entropy => PigeonError::Entropy,
            CoreError::Serialization => PigeonError::Serialization,
            CoreError::ResourceLimit(_) => PigeonError::ResourceLimit,
            CoreError::UnsupportedVersion { .. } => PigeonError::UnsupportedVersion,
            CoreError::Persistence(_) => PigeonError::Persistence,
            CoreError::Identity(_) => PigeonError::Identity,
            CoreError::SessionCreation(_) => PigeonError::SessionCreation,
            CoreError::Encryption(_) => PigeonError::Encryption,
            CoreError::Decryption(_) => PigeonError::Decryption,
            CoreError::GroupPolicy(_) => PigeonError::GroupPolicy,
            CoreError::Mls(_) => PigeonError::Mls,
        }
    }
}

/// Verified public fields from an encoded [`pigeon_core::IdentityBundle`].
#[derive(uniffi::Record)]
pub struct IdentityBundleView {
    pub identity_key: Vec<u8>,
    pub curve_identity_key: Vec<u8>,
}

/// Verified public fields from an encoded [`pigeon_core::PrekeyBundle`].
#[derive(uniffi::Record)]
pub struct PrekeyBundleView {
    pub identity_key: Vec<u8>,
    pub curve_identity_key: Vec<u8>,
    pub prekey: Vec<u8>,
    pub one_time: bool,
}

/// Decodes and verifies an identity binding before returning public fields.
#[uniffi::export]
pub fn parse_identity_bundle(encoded: Vec<u8>) -> Result<IdentityBundleView, PigeonError> {
    let bundle = IdentityBundle::decode(&encoded)?;
    bundle.verify()?;
    Ok(IdentityBundleView {
        identity_key: bundle.identity_key.to_vec(),
        curve_identity_key: bundle.curve_identity_key.to_vec(),
    })
}

/// Decodes and verifies an identity binding and signed prekey before returning
/// public fields.
#[uniffi::export]
pub fn parse_prekey_bundle(encoded: Vec<u8>) -> Result<PrekeyBundleView, PigeonError> {
    let bundle = PrekeyBundle::decode(&encoded)?;
    bundle.verify()?;
    Ok(PrekeyBundleView {
        identity_key: bundle.identity.identity_key.to_vec(),
        curve_identity_key: bundle.identity.curve_identity_key.to_vec(),
        prekey: bundle.prekey.to_vec(),
        one_time: bundle.one_time,
    })
}
