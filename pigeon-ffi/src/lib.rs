//! UniFFI surface for `pigeon-core` — the seam the Swift app calls across.
//!
//! Protocol behavior crosses through the transactional [`FfiClient`] as opaque
//! command/output bytes. Identity keys, pairwise ratchets, and MLS state remain
//! inside `pigeon-core`, which stays free of UniFFI coupling.

use pigeon_core::{GroupInviteMode, GroupInviteTicket, IdentityBundle, PrekeyBundle};

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
            CoreError::FutureEpochBufferFull => PigeonError::ResourceLimit,
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

/// Public, validated fields of a shareable invite. The bearer secret remains
/// in the original ticket bytes; callers must keep those bytes in a URL fragment.
#[derive(uniffi::Record)]
pub struct GroupInviteTicketView {
    pub group_id: Vec<u8>,
    pub coordination_id: Vec<u8>,
    pub coordinator_public_key: Vec<u8>,
    pub relay_url: String,
    pub inbox_address: Vec<u8>,
    pub public_mode: bool,
    pub expires_at_ms: i64,
}

#[uniffi::export]
pub fn parse_group_invite_ticket(
    encoded: Vec<u8>,
    now_ms: i64,
) -> Result<GroupInviteTicketView, PigeonError> {
    let ticket = GroupInviteTicket::decode(&encoded)?;
    ticket.validate(now_ms)?;
    Ok(GroupInviteTicketView {
        group_id: ticket.group_id().as_bytes().to_vec(),
        coordination_id: ticket.coordination_id().to_vec(),
        coordinator_public_key: ticket.coordinator_public_key().to_vec(),
        relay_url: ticket.relay_url().to_owned(),
        inbox_address: ticket.inbox_address().to_vec(),
        public_mode: ticket.mode() == GroupInviteMode::Public,
        expires_at_ms: ticket.expires_at_ms(),
    })
}

#[cfg(test)]
mod invite_ticket_tests {
    use super::*;
    use pigeon_core::{GroupId, GroupInviteTicket};

    #[test]
    fn ffi_parser_exposes_only_valid_public_fields() {
        let ticket = GroupInviteTicket::new(
            GroupId::from_bytes([1; 32]),
            [2; 32],
            [3; 32],
            "wss://relay.example/group".to_owned(),
            [4; 32],
            [5; 32],
            [6; 32],
            GroupInviteMode::Private,
            1_800_000_000_000,
        )
        .unwrap();
        let encoded = ticket.encode();
        let parsed = parse_group_invite_ticket(encoded.clone(), 1_700_000_000_000).unwrap();
        assert_eq!(parsed.group_id, vec![1; 32]);
        assert_eq!(parsed.inbox_address, vec![4; 32]);
        assert!(!parsed.public_mode);
        assert!(parse_group_invite_ticket(encoded, 1_800_000_000_000).is_err());
    }
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
