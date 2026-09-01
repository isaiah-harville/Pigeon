//! A device's cryptographic account: its long-term Ed25519 identity plus its
//! Olm account (Curve25519 identity key, one-time keys, fallback key).

use vodozemac::olm::{Account as OlmAccount, AccountPickle};

use crate::error::Error;
use crate::identity::boundary::{IdentityPurpose, SecureIdentity};
use crate::identity::root::{IdentityBundle, IdentityKeypair, binding_message, prekey_message};

use super::prekey::PrekeyBundle;

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

/// Olm account state owned by the high-level client. Root identity operations
/// stay behind [`SecureIdentity`], so this type never receives private seed
/// bytes and cannot export them through bindings.
pub(crate) struct PlatformAccount {
    olm: OlmAccount,
    fallback_key: [u8; 32],
}

impl PlatformAccount {
    pub(crate) fn new() -> Self {
        let mut olm = OlmAccount::new();
        let count = INITIAL_ONE_TIME_KEYS.min(olm.max_number_of_one_time_keys());
        olm.generate_one_time_keys(count);
        olm.generate_fallback_key();
        let fallback_key = current_fallback_key(&olm);
        Self { olm, fallback_key }
    }

    pub(crate) fn import(state: &[u8], fallback_key: [u8; 32]) -> Result<Self, Error> {
        let pickle: AccountPickle =
            serde_json::from_slice(state).map_err(|_| Error::Serialization)?;
        Ok(Self {
            olm: OlmAccount::from_pickle(pickle),
            fallback_key,
        })
    }

    pub(crate) fn identity_bundle<I: SecureIdentity + ?Sized>(
        &self,
        identity: &I,
    ) -> Result<IdentityBundle, Error> {
        let identity_key = identity.ensure_public_key(IdentityPurpose::Root)?;
        let curve_identity_key = self.olm.curve25519_key().to_bytes();
        let binding_signature =
            identity.sign(IdentityPurpose::Root, &binding_message(&curve_identity_key))?;
        Ok(IdentityBundle {
            identity_key,
            curve_identity_key,
            binding_signature,
        })
    }

    pub(crate) fn signed_prekey_bundle<I: SecureIdentity + ?Sized>(
        &self,
        identity: &I,
    ) -> Result<PrekeyBundle, Error> {
        let identity_bundle = self.identity_bundle(identity)?;
        let prekey_signature = identity.sign(
            IdentityPurpose::Root,
            &prekey_message(false, &self.fallback_key),
        )?;
        Ok(PrekeyBundle {
            identity: identity_bundle,
            prekey: self.fallback_key,
            prekey_signature,
            one_time: false,
        })
    }

    pub(crate) fn export_state(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(&self.olm.pickle()).map_err(|_| Error::Serialization)
    }

    pub(crate) fn export_fallback_key(&self) -> [u8; 32] {
        self.fallback_key
    }
}

impl Account {
    /// Creates a brand-new account: a fresh identity, a fresh Olm account, an
    /// initial pool of one-time keys, and a fallback key.
    pub fn new() -> Result<Self, Error> {
        Ok(Self::with_identity(IdentityKeypair::generate()?))
    }

    /// Creates a new Olm account bound to an **existing** Ed25519 identity (the
    /// 32-byte seed), rather than minting a fresh identity like [`Account::new`].
    /// The host app uses this on first launch to attach an Olm account to the
    /// long-term identity it already holds in the Keychain, so the safety number
    /// is unchanged. The caller-owned `identity_seed` is wiped after use.
    pub fn from_identity_seed(identity_seed: [u8; 32]) -> Self {
        Self::with_identity(IdentityKeypair::from_seed(identity_seed))
    }

    /// Shared builder: a fresh Olm account (initial one-time keys + fallback)
    /// under the given identity.
    fn with_identity(identity: IdentityKeypair) -> Self {
        let mut olm = OlmAccount::new();
        let count = INITIAL_ONE_TIME_KEYS.min(olm.max_number_of_one_time_keys());
        olm.generate_one_time_keys(count);
        olm.generate_fallback_key();
        let fallback_key = current_fallback_key(&olm);
        Self {
            olm,
            identity,
            fallback_key,
        }
    }

    /// Reconstructs an account from its persisted parts: the identity seed, the
    /// opaque pairwise state, and the current fallback public key (from
    /// [`Account::export_fallback_key`]). The host app stores the seed and Olm
    /// state encrypted; the `identity_seed` is private and is wiped after use.
    pub fn import_pairwise_state(
        identity_seed: [u8; 32],
        state: &[u8],
        fallback_key: [u8; 32],
    ) -> Result<Self, Error> {
        let olm_pickle: AccountPickle =
            serde_json::from_slice(state).map_err(|_| Error::Serialization)?;
        Ok(Self {
            olm: OlmAccount::from_pickle(olm_pickle),
            identity: IdentityKeypair::from_seed(identity_seed),
            fallback_key,
        })
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
    /// drop). Pair with [`Account::export_pairwise_state`] and
    /// [`Account::export_fallback_key`].
    pub fn export_identity_seed(&self) -> zeroize::Zeroizing<[u8; 32]> {
        self.identity.seed()
    }

    /// Opaque serialized pairwise account state for the host app to seal and
    /// persist. Contains secret key material. Its encoding is owned by core and
    /// must never be interpreted by an FFI or application client.
    pub fn export_pairwise_state(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(&self.olm.pickle()).map_err(|_| Error::Serialization)
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

#[cfg(test)]
mod platform_account_tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::PlatformAccount;
    use crate::identity::{IdentityError, IdentityPurpose, SecureIdentity};

    struct TestIdentity(SigningKey);

    impl SecureIdentity for TestIdentity {
        fn ensure_public_key(&self, purpose: IdentityPurpose) -> Result<[u8; 32], IdentityError> {
            assert_eq!(purpose, IdentityPurpose::Root);
            Ok(self.0.verifying_key().to_bytes())
        }

        fn sign(
            &self,
            purpose: IdentityPurpose,
            message: &[u8],
        ) -> Result<[u8; 64], IdentityError> {
            assert_eq!(purpose, IdentityPurpose::Root);
            Ok(self.0.sign(message).to_bytes())
        }
    }

    #[test]
    fn platform_account_binds_olm_keys_without_receiving_the_root_seed() {
        let identity = TestIdentity(SigningKey::from_bytes(&[7; 32]));
        let account = PlatformAccount::new();

        let identity_bundle = account.identity_bundle(&identity).unwrap();
        let prekey_bundle = account.signed_prekey_bundle(&identity).unwrap();

        identity_bundle.verify().unwrap();
        prekey_bundle.verify().unwrap();
        assert_eq!(
            identity_bundle.identity_key,
            identity.0.verifying_key().to_bytes()
        );
    }

    #[test]
    fn platform_account_state_round_trip_preserves_the_olm_identity() {
        let identity = TestIdentity(SigningKey::from_bytes(&[9; 32]));
        let account = PlatformAccount::new();
        let expected = account.identity_bundle(&identity).unwrap();

        let restored = PlatformAccount::import(
            &account.export_state().unwrap(),
            account.export_fallback_key(),
        )
        .unwrap();

        assert_eq!(restored.identity_bundle(&identity).unwrap(), expected);
    }
}
