//! The public prekey material a recipient publishes so an initiator can open a
//! session without the recipient being online — the async-first-contact path.
//!
//! This is the Olm analogue of the Swift `X3DHPrekeyBundle`. Olm offers two
//! kinds of Curve25519 prekey, which map onto Pigeon's existing notions:
//!
//! - a **fallback key** — long-lived, rotated periodically, never deleted on
//!   use. Always available. Equivalent to the X3DH *signed prekey* (SPK): it
//!   keeps async contact working, but on its own gives no replay defence.
//! - a **one-time key** — consumed (deleted) by the recipient the first time it
//!   is used. Equivalent to the X3DH *one-time prekey* (OPK): it is the replay
//!   defence, so a replayed initiation derives a different session and fails.
//!
//! Both kinds are signed by the identity key (bound to the `one_time` flag) so a
//! relay or mesh forwarder cannot substitute its own key or downgrade a
//! one-time prekey to the fallback.

use crate::error::Error;
use crate::identity::{IdentityBundle, verify_prekey_signature};

/// A published prekey bundle: the recipient's identity plus one signed
/// Curve25519 prekey. The host app distributes these (QR / mesh / relay); a
/// recipient typically publishes one fallback-backed bundle plus a batch of
/// one-time-key bundles, and each initiator consumes a distinct one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrekeyBundle {
    /// Identity key + Olm Curve25519 identity key + binding signature.
    pub identity: IdentityBundle,
    /// The Curve25519 prekey public key (32 bytes) the initiator runs DH with.
    pub prekey: [u8; 32],
    /// Ed25519 signature by the identity key over `(one_time ‖ prekey)`.
    pub prekey_signature: [u8; 64],
    /// `true` if `prekey` is a one-time key (replay-defended, deleted on first
    /// use); `false` if it is the long-lived fallback key.
    pub one_time: bool,
}

impl PrekeyBundle {
    /// Fixed encoding length: `identity(128) ‖ one_time(1) ‖ prekey(32) ‖ sig(64)`.
    pub const SIZE: usize = IdentityBundle::SIZE + 1 + 32 + 64;

    /// Verifies the identity binding and the prekey signature. Returns `Ok` only
    /// if the whole bundle is authentic under the advertised identity key. Must
    /// hold before [`crate::Session::establish_outbound`] trusts the bundle.
    pub fn verify(&self) -> Result<(), Error> {
        self.identity.verify()?;
        verify_prekey_signature(
            &self.identity.identity_key,
            self.one_time,
            &self.prekey,
            &self.prekey_signature,
        )
    }

    /// Deterministic fixed-length encoding (to be replaced by protobuf, #81).
    pub fn encode(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[0..IdentityBundle::SIZE].copy_from_slice(&self.identity.encode());
        let mut cursor = IdentityBundle::SIZE;
        out[cursor] = self.one_time as u8;
        cursor += 1;
        out[cursor..cursor + 32].copy_from_slice(&self.prekey);
        cursor += 32;
        out[cursor..cursor + 64].copy_from_slice(&self.prekey_signature);
        out
    }

    /// Decodes [`Self::encode`]. Does **not** verify; call [`Self::verify`].
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != Self::SIZE {
            return Err(Error::MalformedBundle);
        }
        let identity = IdentityBundle::decode(&bytes[0..IdentityBundle::SIZE])?;
        let mut cursor = IdentityBundle::SIZE;
        let one_time = match bytes[cursor] {
            0 => false,
            1 => true,
            _ => return Err(Error::MalformedBundle),
        };
        cursor += 1;
        let mut prekey = [0u8; 32];
        let mut prekey_signature = [0u8; 64];
        prekey.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;
        prekey_signature.copy_from_slice(&bytes[cursor..cursor + 64]);
        Ok(Self {
            identity,
            prekey,
            prekey_signature,
            one_time,
        })
    }
}
