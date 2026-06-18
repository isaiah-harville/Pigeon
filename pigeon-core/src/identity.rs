//! The long-term Ed25519 identity and the binding that ties it to an Olm
//! Curve25519 identity key.
//!
//! This mirrors the Swift `IdentityBundle`: an Ed25519 identity key signs the
//! Curve25519 key the transport authenticates, so verifying the identity (via
//! the in-person safety-number comparison) also authenticates the channel.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use vodozemac::Curve25519PublicKey;
use zeroize::Zeroize;

use crate::error::Error;

/// Domain-separation prefix for the identity binding signature. Every KDF/sig
/// context in Pigeon is explicitly separated (see CLAUDE.md security invariants).
const BINDING_CONTEXT: &[u8] = b"Pigeon.IdentityBinding.v1";
/// Domain-separation prefix for prekey signatures. The signed message also
/// covers the one-time flag so an attacker cannot downgrade a one-time prekey
/// (replay-defended) to the fallback or vice versa.
const PREKEY_CONTEXT: &[u8] = b"Pigeon.Prekey.v1";

fn binding_message(curve_identity_key: &[u8; 32]) -> Vec<u8> {
    let mut message = BINDING_CONTEXT.to_vec();
    message.extend_from_slice(curve_identity_key);
    message
}

pub(crate) fn prekey_message(one_time: bool, key: &[u8; 32]) -> Vec<u8> {
    let mut message = PREKEY_CONTEXT.to_vec();
    message.push(one_time as u8);
    message.extend_from_slice(key);
    message
}

/// Verifies a prekey signature under an Ed25519 identity key. Shared by
/// [`crate::PrekeyBundle::verify`].
pub(crate) fn verify_prekey_signature(
    identity_key: &[u8; 32],
    one_time: bool,
    key: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), Error> {
    let verifying = VerifyingKey::from_bytes(identity_key).map_err(|_| Error::InvalidKey)?;
    let signature = Signature::from_bytes(signature);
    verifying
        .verify_strict(&prekey_message(one_time, key), &signature)
        .map_err(|_| Error::InvalidSignature)
}

/// A device's long-term Ed25519 identity key pair — the root of trust and the
/// seed of its safety number. Persisted (encrypted) by the host app; never
/// synced to iCloud/backups. Held separately from the Olm account so Olm key
/// churn never changes the identity.
pub struct IdentityKeypair {
    signing: SigningKey,
}

impl IdentityKeypair {
    /// Generates a fresh identity from OS entropy.
    pub fn generate() -> Result<Self, Error> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|_| Error::Entropy)?;
        let signing = SigningKey::from_bytes(&seed);
        seed.zeroize();
        Ok(Self { signing })
    }

    /// Reconstructs an identity from its 32-byte seed (e.g. loaded from the
    /// host app's encrypted store / Keychain). The caller-owned `seed` is wiped.
    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        seed.zeroize();
        Self { signing }
    }

    /// The 32-byte private seed, for the host app to persist securely. The
    /// returned buffer zeroizes on drop; treat it as secret.
    pub fn seed(&self) -> zeroize::Zeroizing<[u8; 32]> {
        zeroize::Zeroizing::new(self.signing.to_bytes())
    }

    /// The 32-byte Ed25519 public identity key (the safety-number root).
    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub(crate) fn sign_binding(&self, curve_identity_key: &[u8; 32]) -> [u8; 64] {
        self.signing
            .sign(&binding_message(curve_identity_key))
            .to_bytes()
    }

    pub(crate) fn sign_prekey(&self, one_time: bool, key: &[u8; 32]) -> [u8; 64] {
        self.signing.sign(&prekey_message(one_time, key)).to_bytes()
    }
}

/// The public, shareable identity of a device: its Ed25519 identity key, its
/// Olm Curve25519 identity key, and the identity key's signature over the
/// Curve25519 key. Exchanged in person via QR (the safety-number comparison)
/// and carried in an [`crate::Initiation`] so a responder can authenticate it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityBundle {
    /// Ed25519 identity public key (32 bytes). Root of trust / safety number.
    pub identity_key: [u8; 32],
    /// Olm Curve25519 identity public key (32 bytes) the session uses.
    pub curve_identity_key: [u8; 32],
    /// Ed25519 signature (64 bytes) by `identity_key` over `curve_identity_key`.
    pub binding_signature: [u8; 64],
}

impl IdentityBundle {
    /// Fixed encoding length: `identity_key(32) ‖ curve_identity_key(32) ‖ sig(64)`.
    pub const SIZE: usize = 128;

    /// Verifies the Curve25519 identity key is genuinely bound to the Ed25519
    /// identity key. Uses strict verification (rejects malleable/non-canonical
    /// signatures). Must hold before a session derived from this bundle is
    /// trusted.
    pub fn verify(&self) -> Result<(), Error> {
        let verifying =
            VerifyingKey::from_bytes(&self.identity_key).map_err(|_| Error::InvalidKey)?;
        let signature = Signature::from_bytes(&self.binding_signature);
        verifying
            .verify_strict(&binding_message(&self.curve_identity_key), &signature)
            .map_err(|_| Error::InvalidSignature)
    }

    /// The Curve25519 identity key as a vodozemac key (used for Olm session
    /// creation). Infallible: any 32 bytes are a valid X25519 public key.
    pub(crate) fn curve25519(&self) -> Curve25519PublicKey {
        Curve25519PublicKey::from_bytes(self.curve_identity_key)
    }

    /// Deterministic fixed-length encoding (to be replaced by protobuf, #81).
    pub fn encode(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[0..32].copy_from_slice(&self.identity_key);
        out[32..64].copy_from_slice(&self.curve_identity_key);
        out[64..128].copy_from_slice(&self.binding_signature);
        out
    }

    /// Decodes [`Self::encode`]. Does **not** verify; call [`Self::verify`].
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != Self::SIZE {
            return Err(Error::MalformedBundle);
        }
        let mut identity_key = [0u8; 32];
        let mut curve_identity_key = [0u8; 32];
        let mut binding_signature = [0u8; 64];
        identity_key.copy_from_slice(&bytes[0..32]);
        curve_identity_key.copy_from_slice(&bytes[32..64]);
        binding_signature.copy_from_slice(&bytes[64..128]);
        Ok(Self {
            identity_key,
            curve_identity_key,
            binding_signature,
        })
    }
}
