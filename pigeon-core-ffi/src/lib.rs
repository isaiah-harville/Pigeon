//! UniFFI surface for `pigeon-core` — the seam the Swift app calls across.
//!
//! This crate is deliberately thin and **byte-oriented**: every bundle and Olm
//! message crosses the FFI as opaque bytes, and the only objects with identity
//! are [`FfiAccount`] and [`FfiSession`]. Keeping the surface bytes-and-objects
//! lets `pigeon-core` stay free of any UniFFI coupling (and of any licensing or
//! audit-surface entanglement with the bindings layer).
//!
//! The trust model is unchanged from `pigeon-core`: the identity binding and
//! prekey signatures are verified inside `establish_*`, so a session is only
//! ever handed back for a peer whose Ed25519 identity authenticated the channel.
//! Nothing secret is logged here; key material only ever leaves as the explicit
//! `export_*` accessors the host app persists (sealed) itself.

use std::sync::{Arc, Mutex};

use pigeon_core::{Account, IdentityBundle, OlmMessage, PrekeyBundle, Session};
use vodozemac::olm::AccountPickle;

uniffi::setup_scaffolding!();

/// Everything the FFI can fail with. Mirrors [`pigeon_core::Error`] plus the
/// (de)serialization the FFI seam owns. Authentication-style failures are
/// surfaced as hard errors — never papered over — matching pigeon-core.
#[derive(Debug, uniffi::Error)]
pub enum PigeonError {
    /// A key was not a valid length/point.
    InvalidKey,
    /// An identity-binding or prekey signature did not verify.
    InvalidSignature,
    /// A bundle or message byte encoding was malformed.
    MalformedBundle,
    /// Inbound establishment was given a non-pre-key Olm message.
    NotAPreKeyMessage,
    /// The OS entropy source failed while generating the identity.
    Entropy,
    /// Olm could not create the session (e.g. a consumed one-time key).
    SessionCreation,
    /// Olm encryption failed.
    Encryption,
    /// Olm decryption/authentication failed (tampering, wrong key, or replay).
    Decryption,
    /// Failed to (de)serialize the persisted Olm account pickle.
    Serialization,
}

impl std::fmt::Display for PigeonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            PigeonError::InvalidKey => "invalid key",
            PigeonError::InvalidSignature => "signature did not verify",
            PigeonError::MalformedBundle => "malformed bundle or message encoding",
            PigeonError::NotAPreKeyMessage => "expected an Olm pre-key message",
            PigeonError::Entropy => "OS entropy source failed",
            PigeonError::SessionCreation => "session creation failed",
            PigeonError::Encryption => "encryption failed",
            PigeonError::Decryption => "decryption failed",
            PigeonError::Serialization => "account pickle (de)serialization failed",
        };
        f.write_str(s)
    }
}

impl std::error::Error for PigeonError {}

impl From<pigeon_core::Error> for PigeonError {
    fn from(e: pigeon_core::Error) -> Self {
        use pigeon_core::Error as E;
        match e {
            E::InvalidKey => PigeonError::InvalidKey,
            E::InvalidSignature => PigeonError::InvalidSignature,
            E::MalformedBundle => PigeonError::MalformedBundle,
            E::NotAPreKeyMessage => PigeonError::NotAPreKeyMessage,
            E::Entropy => PigeonError::Entropy,
            E::SessionCreation(_) => PigeonError::SessionCreation,
            E::Encryption(_) => PigeonError::Encryption,
            E::Decryption(_) => PigeonError::Decryption,
        }
    }
}

/// Result of opening an outbound session: the live session plus the
/// [`pigeon_core::Initiation`] to transmit (the sender's encoded identity bundle
/// and the first Olm pre-key message, both as bytes).
#[derive(uniffi::Record)]
pub struct OutboundResult {
    pub session: Arc<FfiSession>,
    /// The initiator's identity bundle, encoded (128 bytes).
    pub initiation_identity: Vec<u8>,
    /// The first Olm pre-key message, encoded (see [`olm_message_to_bytes`]).
    pub message: Vec<u8>,
}

/// Result of accepting an inbound initiation: the live session and the first
/// plaintext recovered from the pre-key message.
#[derive(uniffi::Record)]
pub struct InboundResult {
    pub session: Arc<FfiSession>,
    pub plaintext: Vec<u8>,
}

/// The verified, readable view of an [`pigeon_core::IdentityBundle`]: the two
/// public keys, available only after the binding signature verified.
#[derive(uniffi::Record)]
pub struct IdentityBundleView {
    /// Ed25519 identity public key (32 bytes) — the safety-number root.
    pub identity_key: Vec<u8>,
    /// Olm Curve25519 identity public key (32 bytes).
    pub curve_identity_key: Vec<u8>,
}

/// The verified, readable view of a [`pigeon_core::PrekeyBundle`].
#[derive(uniffi::Record)]
pub struct PrekeyBundleView {
    /// Ed25519 identity public key (32 bytes).
    pub identity_key: Vec<u8>,
    /// Olm Curve25519 identity public key (32 bytes).
    pub curve_identity_key: Vec<u8>,
    /// The Curve25519 prekey public key (32 bytes).
    pub prekey: Vec<u8>,
    /// `true` if `prekey` is a (replay-defended) one-time key.
    pub one_time: bool,
}

/// Decodes **and verifies** an encoded identity bundle, returning its public
/// keys. Errors if the encoding is malformed or the binding signature is
/// invalid — so a successful return means the Curve25519 key is genuinely bound
/// to the Ed25519 identity. Replaces the Swift `IdentityBundle.isValid()`.
#[uniffi::export]
pub fn parse_identity_bundle(encoded: Vec<u8>) -> Result<IdentityBundleView, PigeonError> {
    let bundle = IdentityBundle::decode(&encoded)?;
    bundle.verify()?;
    Ok(IdentityBundleView {
        identity_key: bundle.identity_key.to_vec(),
        curve_identity_key: bundle.curve_identity_key.to_vec(),
    })
}

/// Decodes **and verifies** an encoded prekey bundle (identity binding + prekey
/// signature), returning its fields. A successful return means the whole bundle
/// is authentic under the advertised identity key. Replaces the Swift
/// `X3DHPrekeyBundle.isValid()`.
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

/// One device's account (Ed25519 identity + Olm account). Wraps
/// [`pigeon_core::Account`] behind a `Mutex` so the UniFFI object can expose the
/// account's mutating operations (key consumption, prekey rotation) through
/// `&self` methods.
#[derive(uniffi::Object)]
pub struct FfiAccount {
    inner: Mutex<Account>,
}

#[uniffi::export]
impl FfiAccount {
    /// Creates a brand-new account (fresh identity, Olm account, prekeys).
    #[uniffi::constructor]
    pub fn generate() -> Result<Arc<Self>, PigeonError> {
        Ok(Arc::new(Self {
            inner: Mutex::new(Account::new()?),
        }))
    }

    /// Creates a new Olm account bound to an **existing** 32-byte Ed25519
    /// identity seed (the host app's long-term Keychain identity), rather than
    /// minting a fresh identity like [`Self::generate`]. Used on first launch so
    /// the Olm account attaches to the identity the safety number is built from.
    #[uniffi::constructor]
    pub fn from_identity_seed(seed: Vec<u8>) -> Result<Arc<Self>, PigeonError> {
        let seed = to_array32(&seed)?;
        Ok(Arc::new(Self {
            inner: Mutex::new(Account::from_identity_seed(seed)),
        }))
    }

    /// Reconstructs an account from the host app's persisted parts: the 32-byte
    /// Ed25519 seed, the serialized Olm pickle (from [`Self::export_olm_pickle`]),
    /// and the fallback public key (from [`Self::export_fallback_key`]).
    #[uniffi::constructor]
    pub fn import(
        seed: Vec<u8>,
        olm_pickle: Vec<u8>,
        fallback_key: Vec<u8>,
    ) -> Result<Arc<Self>, PigeonError> {
        let seed = to_array32(&seed)?;
        let fallback = to_array32(&fallback_key)?;
        let pickle: AccountPickle =
            serde_json::from_slice(&olm_pickle).map_err(|_| PigeonError::Serialization)?;
        Ok(Arc::new(Self {
            inner: Mutex::new(Account::import(seed, pickle, fallback)),
        }))
    }

    /// The 32-byte Ed25519 public identity key (the safety-number root).
    pub fn identity_public_key(&self) -> Vec<u8> {
        self.inner.lock().unwrap().identity_public_key().to_vec()
    }

    /// This device's signed identity bundle, encoded (128 bytes).
    pub fn identity_bundle(&self) -> Vec<u8> {
        self.inner
            .lock()
            .unwrap()
            .identity_bundle()
            .encode()
            .to_vec()
    }

    /// The long-lived fallback (signed-prekey) bundle, encoded. Always available;
    /// no per-session replay defence on its own.
    pub fn signed_prekey_bundle(&self) -> Vec<u8> {
        self.inner
            .lock()
            .unwrap()
            .signed_prekey_bundle()
            .encode()
            .to_vec()
    }

    /// Takes every currently-unpublished one-time prekey bundle (each encoded)
    /// and marks the account's keys published. Empty once the pool is spent.
    pub fn take_one_time_prekey_bundles(&self) -> Vec<Vec<u8>> {
        self.inner
            .lock()
            .unwrap()
            .take_one_time_prekey_bundles()
            .iter()
            .map(|b| b.encode().to_vec())
            .collect()
    }

    /// Refills the one-time-key pool up to Olm's maximum.
    pub fn replenish_one_time_keys(&self) {
        self.inner.lock().unwrap().replenish_one_time_keys();
    }

    /// Rotates the fallback (signed) prekey.
    pub fn rotate_fallback_key(&self) {
        self.inner.lock().unwrap().rotate_fallback_key();
    }

    /// Opens an outbound session against a peer's encoded prekey bundle,
    /// encrypting `first_plaintext` into the first pre-key message. Verifies the
    /// peer's identity binding and prekey signature before trusting the bundle.
    pub fn establish_outbound(
        &self,
        peer_bundle: Vec<u8>,
        first_plaintext: Vec<u8>,
    ) -> Result<OutboundResult, PigeonError> {
        let bundle = PrekeyBundle::decode(&peer_bundle)?;
        let account = self.inner.lock().unwrap();
        let (session, initiation) =
            Session::establish_outbound(&account, &bundle, &first_plaintext)?;
        Ok(OutboundResult {
            session: Arc::new(FfiSession::new(session)),
            initiation_identity: initiation.identity.encode().to_vec(),
            message: olm_message_to_bytes(&initiation.message),
        })
    }

    /// Accepts an inbound initiation: verifies the initiator's encoded identity
    /// bundle, then creates the inbound session from the first pre-key message
    /// and returns the recovered first plaintext. Consumes the matching one-time
    /// key (the replay defence).
    pub fn establish_inbound(
        &self,
        identity_bundle: Vec<u8>,
        message: Vec<u8>,
    ) -> Result<InboundResult, PigeonError> {
        let identity = IdentityBundle::decode(&identity_bundle)?;
        let message = olm_message_from_bytes(&message)?;
        let mut account = self.inner.lock().unwrap();
        let (session, plaintext) = Session::establish_inbound(&mut account, &identity, &message)?;
        Ok(InboundResult {
            session: Arc::new(FfiSession::new(session)),
            plaintext,
        })
    }

    /// The 32-byte private identity seed, for the host app to persist securely.
    pub fn export_seed(&self) -> Vec<u8> {
        self.inner.lock().unwrap().export_identity_seed().to_vec()
    }

    /// The serialized Olm account pickle (secret), for the host app to seal and
    /// persist. Re-export after any operation that mutates the account
    /// (inbound establishment, prekey take/replenish/rotate).
    pub fn export_olm_pickle(&self) -> Result<Vec<u8>, PigeonError> {
        serde_json::to_vec(&self.inner.lock().unwrap().export_olm_pickle())
            .map_err(|_| PigeonError::Serialization)
    }

    /// The current fallback public key (public; safe in the clear), needed by
    /// [`Self::import`].
    pub fn export_fallback_key(&self) -> Vec<u8> {
        self.inner.lock().unwrap().export_fallback_key().to_vec()
    }
}

/// One end of a pairwise session. Wraps [`pigeon_core::Session`] behind a
/// `Mutex` so the ratchet's mutating encrypt/decrypt are reachable via `&self`.
#[derive(uniffi::Object)]
pub struct FfiSession {
    inner: Mutex<Session>,
}

impl FfiSession {
    fn new(session: Session) -> Self {
        Self {
            inner: Mutex::new(session),
        }
    }
}

#[uniffi::export]
impl FfiSession {
    /// Encrypts `plaintext`, advancing the ratchet; returns the encoded Olm
    /// message bytes.
    pub fn encrypt(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, PigeonError> {
        let message = self.inner.lock().unwrap().encrypt(&plaintext)?;
        Ok(olm_message_to_bytes(&message))
    }

    /// Decrypts an encoded Olm message from the peer.
    pub fn decrypt(&self, message: Vec<u8>) -> Result<Vec<u8>, PigeonError> {
        let message = olm_message_from_bytes(&message)?;
        Ok(self.inner.lock().unwrap().decrypt(&message)?)
    }

    /// The peer's Ed25519 identity key, verified out of band at establishment.
    /// Compare this against the contact's safety-number identity.
    pub fn remote_identity_key(&self) -> Vec<u8> {
        self.inner.lock().unwrap().remote_identity_key().to_vec()
    }

    /// Olm's session id (stable, shared by both ends once converged).
    pub fn session_id(&self) -> String {
        self.inner.lock().unwrap().session_id()
    }
}

// --- wire helpers (a #81 stopgap: the FFI boundary needs bytes today) ---------

/// Encodes an [`OlmMessage`] as `type(1) ‖ ciphertext`, where `type` is Olm's
/// message type (`0` = pre-key, `1` = normal). #81 moves this into pigeon-core's
/// protobuf wire layer.
fn olm_message_to_bytes(message: &OlmMessage) -> Vec<u8> {
    let (message_type, ciphertext) = message.to_parts();
    let mut out = Vec::with_capacity(ciphertext.len() + 1);
    out.push(message_type as u8);
    out.extend_from_slice(&ciphertext);
    out
}

/// Inverse of [`olm_message_to_bytes`].
fn olm_message_from_bytes(bytes: &[u8]) -> Result<OlmMessage, PigeonError> {
    let (message_type, ciphertext) = bytes.split_first().ok_or(PigeonError::MalformedBundle)?;
    OlmMessage::from_parts(*message_type as usize, ciphertext)
        .map_err(|_| PigeonError::MalformedBundle)
}

fn to_array32(bytes: &[u8]) -> Result<[u8; 32], PigeonError> {
    bytes.try_into().map_err(|_| PigeonError::InvalidKey)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Swift round-trip in PigeonCoreTests mirrors this; keeping a Rust copy
    /// here proves the byte-seam (bundle encode/decode, Olm message framing,
    /// pickle round-trip) independently of the bindings build.
    #[test]
    fn first_contact_and_traffic_through_the_ffi_seam() {
        let alice = FfiAccount::generate().unwrap();
        let bob = FfiAccount::generate().unwrap();

        let bundle = bob.take_one_time_prekey_bundles().pop().unwrap();
        let outbound = alice
            .establish_outbound(bundle, b"hello bob".to_vec())
            .unwrap();

        let inbound = bob
            .establish_inbound(outbound.initiation_identity, outbound.message)
            .unwrap();
        assert_eq!(inbound.plaintext, b"hello bob");

        // The session reports the verified peer identity for the safety check.
        assert_eq!(
            outbound.session.remote_identity_key(),
            bob.identity_public_key()
        );
        assert_eq!(
            inbound.session.remote_identity_key(),
            alice.identity_public_key()
        );

        // Traffic both ways after convergence.
        let reply = inbound.session.encrypt(b"hi alice".to_vec()).unwrap();
        assert_eq!(outbound.session.decrypt(reply).unwrap(), b"hi alice");
    }

    #[test]
    fn parse_verifies_and_reads_bundles() {
        let account = FfiAccount::generate().unwrap();

        let identity = parse_identity_bundle(account.identity_bundle()).unwrap();
        assert_eq!(identity.identity_key, account.identity_public_key());
        assert_eq!(identity.identity_key.len(), 32);
        assert_eq!(identity.curve_identity_key.len(), 32);

        let prekey_encoded = account.take_one_time_prekey_bundles().pop().unwrap();
        let prekey = parse_prekey_bundle(prekey_encoded).unwrap();
        assert!(prekey.one_time);
        assert_eq!(prekey.identity_key, account.identity_public_key());

        // A tampered binding must fail verification, not return a view.
        let mut bad = account.identity_bundle();
        bad[64] ^= 0x01; // first byte of the binding signature
        assert!(matches!(
            parse_identity_bundle(bad),
            Err(PigeonError::InvalidSignature)
        ));
    }

    #[test]
    fn account_pickle_round_trips() {
        let bob = FfiAccount::generate().unwrap();
        let seed = bob.export_seed();
        let pickle = bob.export_olm_pickle().unwrap();
        let fallback = bob.export_fallback_key();
        let identity_before = bob.identity_public_key();

        let reloaded = FfiAccount::import(seed, pickle, fallback).unwrap();
        assert_eq!(reloaded.identity_public_key(), identity_before);
    }

    #[test]
    fn from_identity_seed_keeps_the_identity_but_makes_a_fresh_olm_account() {
        // Same seed -> same Ed25519 identity (so the safety number is stable),
        // but a fresh Olm account each time (different Curve25519 identity key).
        let original = FfiAccount::generate().unwrap();
        let seed = original.export_seed();

        let rebuilt = FfiAccount::from_identity_seed(seed.clone()).unwrap();
        assert_eq!(
            rebuilt.identity_public_key(),
            original.identity_public_key()
        );

        let again = FfiAccount::from_identity_seed(seed).unwrap();
        assert_eq!(again.identity_public_key(), original.identity_public_key());
        // Distinct Olm accounts -> distinct identity bundles (different Curve key).
        assert_ne!(rebuilt.identity_bundle(), again.identity_bundle());

        // The rebuilt account can still be a session peer under that identity.
        let alice = FfiAccount::generate().unwrap();
        let outbound = alice
            .establish_outbound(rebuilt.signed_prekey_bundle(), b"hi".to_vec())
            .unwrap();
        let inbound = rebuilt
            .establish_inbound(outbound.initiation_identity, outbound.message)
            .unwrap();
        assert_eq!(inbound.plaintext, b"hi");
    }
}
