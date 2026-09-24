//! One end of a pairwise end-to-end-encrypted conversation: a thin, trust-aware
//! wrapper over a vodozemac Olm [`vodozemac::olm::Session`].
//!
//! The wrapper's job is to enforce Pigeon's identity binding at establishment —
//! a session is never handed back unless the peer's [`IdentityBundle`] (and, for
//! the initiator, the [`PrekeyBundle`]) verified under the peer's Ed25519
//! identity key. After that, [`Session::encrypt`]/[`Session::decrypt`] are
//! straight Olm: the Double Ratchet, forward secrecy, post-compromise security,
//! and out-of-order / skipped-message handling all come from vodozemac.

use vodozemac::olm::{OlmMessage, Session as OlmSession, SessionConfig, SessionPickle};

use crate::error::Error;
use crate::identity::root::IdentityBundle;

use super::account::{Account, PlatformAccount};
use super::prekey::PrekeyBundle;

/// What an initiator sends ahead of (and including) its first message so the
/// recipient can stand up the matching session: the initiator's identity bundle
/// (for safety-number verification) and the first Olm pre-key message.
#[derive(Clone, Debug)]
pub struct Initiation {
    /// The initiator's identity bundle — the recipient verifies this against the
    /// initiator's safety number before trusting the session.
    pub identity: IdentityBundle,
    /// The first Olm message; always an [`OlmMessage::PreKey`].
    pub message: OlmMessage,
}

/// An established pairwise session.
pub struct Session {
    olm: OlmSession,
    /// The peer's Ed25519 identity key, captured from the bundle the local side
    /// verified out of band. The host app compares this against the contact's
    /// safety number — the same role the Swift `remoteStaticKey` played.
    remote_identity_key: [u8; 32],
}

/// Ratchet state owned by the high-level client. It accepts root-identity
/// operations only through [`crate::identity::SecureIdentity`] and remains
/// private to `pigeon-core`.
pub(crate) struct PlatformSession {
    olm: OlmSession,
    remote_identity_key: [u8; 32],
}

impl PlatformSession {
    pub(crate) fn establish_outbound<I: crate::identity::SecureIdentity + ?Sized>(
        local: &PlatformAccount,
        identity: &I,
        peer: &PrekeyBundle,
        first_plaintext: &[u8],
    ) -> Result<(Self, Initiation), Error> {
        peer.verify()?;
        let mut olm = local.olm().create_outbound_session(
            SessionConfig::default(),
            peer.identity.curve25519(),
            vodozemac::Curve25519PublicKey::from_bytes(peer.prekey),
        )?;
        let message = olm.encrypt(first_plaintext)?;
        Ok((
            Self {
                olm,
                remote_identity_key: peer.identity.identity_key,
            },
            Initiation {
                identity: local.identity_bundle(identity)?,
                message,
            },
        ))
    }

    pub(crate) fn establish_inbound(
        local: &mut PlatformAccount,
        identity: &IdentityBundle,
        message: &OlmMessage,
    ) -> Result<(Self, Vec<u8>), Error> {
        identity.verify()?;
        let OlmMessage::PreKey(prekey_message) = message else {
            return Err(Error::NotAPreKeyMessage);
        };
        let result = local.olm_mut().create_inbound_session(
            SessionConfig::default(),
            identity.curve25519(),
            prekey_message,
        )?;
        Ok((
            Self {
                olm: result.session,
                remote_identity_key: identity.identity_key,
            },
            result.plaintext,
        ))
    }

    pub(crate) fn encrypt(&mut self, plaintext: &[u8]) -> Result<OlmMessage, Error> {
        Ok(self.olm.encrypt(plaintext)?)
    }

    pub(crate) fn decrypt(&mut self, message: &OlmMessage) -> Result<Vec<u8>, Error> {
        Ok(self.olm.decrypt(message)?)
    }

    pub(crate) fn export(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(&self.olm.pickle()).map_err(|_| Error::Serialization)
    }

    pub(crate) fn import(state: &[u8], remote_identity_key: [u8; 32]) -> Result<Self, Error> {
        let pickle: SessionPickle =
            serde_json::from_slice(state).map_err(|_| Error::Serialization)?;
        Ok(Self {
            olm: OlmSession::from_pickle(pickle),
            remote_identity_key,
        })
    }

    pub(crate) fn remote_identity_key(&self) -> [u8; 32] {
        self.remote_identity_key
    }
}

impl Session {
    /// Initiator side. Verifies `peer` (identity binding + prekey signature),
    /// opens an outbound Olm session against the peer's Curve25519 identity and
    /// prekey, and encrypts `first_plaintext` into the first pre-key message.
    ///
    /// Returns the session plus the [`Initiation`] to transmit. Verify the
    /// peer's safety number (`peer.identity.identity_key`) before trusting it.
    pub fn establish_outbound(
        local: &Account,
        peer: &PrekeyBundle,
        first_plaintext: &[u8],
    ) -> Result<(Self, Initiation), Error> {
        peer.verify()?;

        let their_identity = peer.identity.curve25519();
        let their_prekey = vodozemac::Curve25519PublicKey::from_bytes(peer.prekey);

        let mut olm = local.olm().create_outbound_session(
            SessionConfig::default(),
            their_identity,
            their_prekey,
        )?;
        let message = olm.encrypt(first_plaintext)?;

        let session = Self {
            olm,
            remote_identity_key: peer.identity.identity_key,
        };
        let initiation = Initiation {
            identity: local.identity_bundle(),
            message,
        };
        Ok((session, initiation))
    }

    /// Responder side. Verifies the initiator's `identity` binding, then creates
    /// an inbound Olm session from the first pre-key `message`, returning the
    /// session and the decrypted first plaintext.
    ///
    /// `message` must be an [`OlmMessage::PreKey`]. The matching one-time key (if
    /// the initiator used one) is consumed from `local` here — that consumption
    /// is the replay defence, so a replayed one-time-prekey initiation will fail.
    /// Olm deliberately permits fallback-key reuse; callers must durably reject
    /// fallback initiations they have already accepted.
    ///
    /// Verify the initiator's safety number (`identity.identity_key`) before
    /// trusting the session.
    pub fn establish_inbound(
        local: &mut Account,
        identity: &IdentityBundle,
        message: &OlmMessage,
    ) -> Result<(Self, Vec<u8>), Error> {
        identity.verify()?;

        let prekey_message = match message {
            OlmMessage::PreKey(prekey_message) => prekey_message,
            OlmMessage::Normal(_) => return Err(Error::NotAPreKeyMessage),
        };

        let their_identity = identity.curve25519();
        let result = local.olm_mut().create_inbound_session(
            SessionConfig::default(),
            their_identity,
            prekey_message,
        )?;

        let session = Self {
            olm: result.session,
            remote_identity_key: identity.identity_key,
        };
        Ok((session, result.plaintext))
    }

    /// Encrypts `plaintext`, advancing the ratchet. Until the peer has replied,
    /// this yields pre-key messages (carrying the session setup); afterwards,
    /// normal messages.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<OlmMessage, Error> {
        Ok(self.olm.encrypt(plaintext)?)
    }

    /// Decrypts a message from the peer. Tolerates out-of-order and skipped
    /// messages; fails closed (`Error::Decryption`) on tampering, wrong key, or
    /// a replayed message.
    pub fn decrypt(&mut self, message: &OlmMessage) -> Result<Vec<u8>, Error> {
        Ok(self.olm.decrypt(message)?)
    }

    /// The peer's Ed25519 identity key, verified out of band at establishment.
    pub fn remote_identity_key(&self) -> [u8; 32] {
        self.remote_identity_key
    }

    /// Opaque ratchet state (secret), for the host app to seal and persist so
    /// the session — and thus the conversation's forward-secret state — survives
    /// app relaunch instead of forcing a fresh handshake every cold start.
    ///
    /// The peer's Ed25519 identity key is **not** in this state (Olm only knows
    /// the Curve25519 keys); persist it alongside and pass it back to
    /// [`Session::import_state`]. The host app already holds it as the contact id.
    pub fn export_state(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(&self.olm.pickle()).map_err(|_| Error::Serialization)
    }

    /// Restores a session from persisted opaque state plus the peer's
    /// Ed25519 identity key (the contact id the host app keyed the session by).
    /// The binding was verified when the session was first established; restoring
    /// re-attaches that already-verified identity to the ratchet state.
    pub fn import_state(state: &[u8], remote_identity_key: [u8; 32]) -> Result<Self, Error> {
        let pickle: SessionPickle =
            serde_json::from_slice(state).map_err(|_| Error::Serialization)?;
        Ok(Self {
            olm: OlmSession::from_pickle(pickle),
            remote_identity_key,
        })
    }

    /// Olm's session id (stable, shared by both ends once converged).
    pub fn session_id(&self) -> String {
        self.olm.session_id()
    }
}

#[cfg(test)]
mod platform_session_tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::PlatformSession;
    use crate::identity::pairwise::PlatformAccount;
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
    fn platform_sessions_establish_without_exporting_identity_seeds() {
        let alice_identity = TestIdentity(SigningKey::from_bytes(&[1; 32]));
        let bob_identity = TestIdentity(SigningKey::from_bytes(&[2; 32]));
        let alice = PlatformAccount::new();
        let mut bob = PlatformAccount::new();
        let bob_prekey = bob.signed_prekey_bundle(&bob_identity).unwrap();

        let (mut alice_session, initiation) = PlatformSession::establish_outbound(
            &alice,
            &alice_identity,
            &bob_prekey,
            b"group bootstrap",
        )
        .unwrap();
        let (mut bob_session, plaintext) =
            PlatformSession::establish_inbound(&mut bob, &initiation.identity, &initiation.message)
                .unwrap();

        assert_eq!(plaintext, b"group bootstrap");
        let reply = bob_session.encrypt(b"accepted").unwrap();
        assert_eq!(alice_session.decrypt(&reply).unwrap(), b"accepted");
    }

    #[test]
    fn platform_session_state_round_trip_keeps_ratcheting() {
        let alice_identity = TestIdentity(SigningKey::from_bytes(&[3; 32]));
        let bob_identity = TestIdentity(SigningKey::from_bytes(&[4; 32]));
        let alice = PlatformAccount::new();
        let mut bob = PlatformAccount::new();
        let bob_prekey = bob.signed_prekey_bundle(&bob_identity).unwrap();
        let (mut alice_session, initiation) =
            PlatformSession::establish_outbound(&alice, &alice_identity, &bob_prekey, b"first")
                .unwrap();
        let (mut bob_session, _) =
            PlatformSession::establish_inbound(&mut bob, &initiation.identity, &initiation.message)
                .unwrap();
        let reply = bob_session.encrypt(b"settle").unwrap();
        alice_session.decrypt(&reply).unwrap();

        let alice_remote = alice_session.remote_identity_key();
        let bob_remote = bob_session.remote_identity_key();
        let mut alice_restored =
            PlatformSession::import(&alice_session.export().unwrap(), alice_remote).unwrap();
        let mut bob_restored =
            PlatformSession::import(&bob_session.export().unwrap(), bob_remote).unwrap();

        let message = alice_restored.encrypt(b"after reload").unwrap();
        assert_eq!(bob_restored.decrypt(&message).unwrap(), b"after reload");
    }
}
