//! A device's cryptographic account: its long-term Ed25519 identity plus its
//! Olm account (Curve25519 identity key, one-time keys, fallback key).

use vodozemac::olm::{Account as OlmAccount, AccountPickle};

use crate::error::Error;
use crate::identity::{IdentityBundle, IdentityKeypair};
use crate::prekey::PrekeyBundle;

/// How many one-time keys [`Account::new`] generates up front, capped by Olm's
/// maximum. A modest pool: prekeys can be replenished with
/// [`Account::replenish_one_time_keys`].
const INITIAL_ONE_TIME_KEYS: usize = 50;

/// One device's account. Owns the Ed25519 identity (the safety-number root) and
/// the Olm account; the two are kept separate so re-pickling or rotating the
/// Olm side never changes the identity.
pub struct Account {
    olm: OlmAccount,
    identity: IdentityKeypair,
    /// The current fallback (signed-prekey) public key. Tracked explicitly
    /// because Olm's `fallback_key()` only reports the *unpublished* key, so it
    /// goes empty after publishing and cannot be recovered after a pickle
    /// round-trip. These bytes are public, so persisting them is safe.
    fallback_key: [u8; 32],
}

impl Account {
    /// Creates a brand-new account: a fresh identity, a fresh Olm account, an
    /// initial pool of one-time keys, and a fallback key.
    pub fn new() -> Result<Self, Error> {
        let identity = IdentityKeypair::generate()?;
        let mut olm = OlmAccount::new();
        let count = INITIAL_ONE_TIME_KEYS.min(olm.max_number_of_one_time_keys());
        olm.generate_one_time_keys(count);
        olm.generate_fallback_key();
        let fallback_key = current_fallback_key(&olm);
        Ok(Self {
            olm,
            identity,
            fallback_key,
        })
    }

    /// Reconstructs an account from its persisted parts: the identity seed, the
    /// Olm pickle, and the current fallback public key (from
    /// [`Account::export_fallback_key`]). The host app stores the seed and Olm
    /// pickle encrypted; the `identity_seed` is private and is wiped after use.
    pub fn import(
        identity_seed: [u8; 32],
        olm_pickle: AccountPickle,
        fallback_key: [u8; 32],
    ) -> Self {
        Self {
            olm: OlmAccount::from_pickle(olm_pickle),
            identity: IdentityKeypair::from_seed(identity_seed),
            fallback_key,
        }
    }

    /// The 32-byte Ed25519 public identity key (the safety-number root).
    pub fn identity_public_key(&self) -> [u8; 32] {
        self.identity.public_key()
    }

    /// This device's signed identity bundle (identity key + Olm Curve25519
    /// identity key + binding signature).
    ///
    /// Note: Olm also has its own Ed25519 key (`olm.ed25519_key()`), which we
    /// intentionally **do not use**. Pigeon's root of trust is the separate,
    /// long-term [`IdentityKeypair`] so the identity (and thus the safety
    /// number) survives rebuilding the Olm account, and so a future master
    /// identity can sign multiple devices' keys (cross-signing). The Olm
    /// Ed25519 key plays no role in Olm's session security (that rests on the
    /// Curve25519 3DH), so ignoring it costs nothing.
    pub fn identity_bundle(&self) -> IdentityBundle {
        let curve_identity_key = self.olm.curve25519_key().to_bytes();
        let binding_signature = self.identity.sign_binding(&curve_identity_key);
        IdentityBundle {
            identity_key: self.identity.public_key(),
            curve_identity_key,
            binding_signature,
        }
    }

    /// A prekey bundle backed by the long-lived **fallback** key. Always
    /// available; keeps async first-contact working but offers no replay
    /// defence on its own. Analogous to an X3DH signed-prekey bundle.
    pub fn signed_prekey_bundle(&self) -> PrekeyBundle {
        self.sign_bundle(self.fallback_key, false)
    }

    /// Wraps every currently-unpublished **one-time** key into its own bundle
    /// and marks the account's keys as published. Each returned bundle is
    /// replay-defended (its key is deleted on first use), so a recipient hands
    /// out a distinct one per initiator. Returns empty once the pool is spent —
    /// call [`Account::replenish_one_time_keys`] then publish again.
    pub fn take_one_time_prekey_bundles(&mut self) -> Vec<PrekeyBundle> {
        let bundles: Vec<PrekeyBundle> = self
            .olm
            .one_time_keys()
            .into_values()
            .map(|key| self.sign_bundle(key.to_bytes(), true))
            .collect();
        self.olm.mark_keys_as_published();
        bundles
    }

    /// Refills the one-time-key pool up to Olm's maximum. Call before
    /// [`Account::take_one_time_prekey_bundles`] when the pool is low.
    pub fn replenish_one_time_keys(&mut self) {
        let target = self.olm.max_number_of_one_time_keys();
        self.olm.generate_one_time_keys(target);
    }

    /// Rotates the fallback (signed) prekey. Call periodically to bound the
    /// exposure window of the no-one-time-key path. The previous fallback stays
    /// usable for inbound for one rotation, per Olm.
    pub fn rotate_fallback_key(&mut self) {
        self.olm.generate_fallback_key();
        self.fallback_key = current_fallback_key(&self.olm);
    }

    /// The private identity seed, for the host app to persist securely (wiped on
    /// drop). Pair with [`Account::export_olm_pickle`] / [`Account::export_fallback_key`].
    pub fn export_identity_seed(&self) -> zeroize::Zeroizing<[u8; 32]> {
        self.identity.seed()
    }

    /// The Olm account pickle, for the host app to persist (encrypted). Contains
    /// secret key material.
    pub fn export_olm_pickle(&self) -> AccountPickle {
        self.olm.pickle()
    }

    /// The current fallback public key, for the host app to persist (public,
    /// safe in the clear). Needed by [`Account::import`] because Olm cannot
    /// report it after publishing.
    pub fn export_fallback_key(&self) -> [u8; 32] {
        self.fallback_key
    }

    fn sign_bundle(&self, prekey: [u8; 32], one_time: bool) -> PrekeyBundle {
        let prekey_signature = self.identity.sign_prekey(one_time, &prekey);
        PrekeyBundle {
            identity: self.identity_bundle(),
            prekey,
            prekey_signature,
            one_time,
        }
    }

    pub(crate) fn olm(&self) -> &OlmAccount {
        &self.olm
    }

    pub(crate) fn olm_mut(&mut self) -> &mut OlmAccount {
        &mut self.olm
    }
}

/// Reads the freshly generated (still unpublished) fallback public key. Must be
/// called right after `generate_fallback_key()` and before publishing.
fn current_fallback_key(olm: &OlmAccount) -> [u8; 32] {
    olm.fallback_key()
        .into_values()
        .next()
        .expect("a fallback key was just generated and not yet published")
        .to_bytes()
}
