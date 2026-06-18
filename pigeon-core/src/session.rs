//! One end of a pairwise end-to-end-encrypted conversation: a thin, trust-aware
//! wrapper over a vodozemac Olm [`vodozemac::olm::Session`].
//!
//! The wrapper's job is to enforce Pigeon's identity binding at establishment —
//! a session is never handed back unless the peer's [`IdentityBundle`] (and, for
//! the initiator, the [`PrekeyBundle`]) verified under the peer's Ed25519
//! identity key. After that, [`Session::encrypt`]/[`Session::decrypt`] are
//! straight Olm: the Double Ratchet, forward secrecy, post-compromise security,
//! and out-of-order / skipped-message handling all come from vodozemac.

use vodozemac::olm::{OlmMessage, Session as OlmSession, SessionConfig};

use crate::account::Account;
use crate::error::Error;
use crate::identity::IdentityBundle;
use crate::prekey::PrekeyBundle;

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
    /// is the replay defence, so a replayed initiation will fail.
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

    /// Olm's session id (stable, shared by both ends once converged).
    pub fn session_id(&self) -> String {
        self.olm.session_id()
    }
}
