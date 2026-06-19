//! Protocol Buffer wire encodings shared with clients.

use prost::Message;
use vodozemac::olm::OlmMessage;

use crate::error::Error;
use crate::identity::IdentityBundle;
use crate::prekey::PrekeyBundle;
use crate::session::Initiation;

#[allow(dead_code)]
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/pigeon.wire.v1.rs"));
}

impl IdentityBundle {
    /// Encodes this bundle as `pigeon.wire.v1.IdentityBundle`.
    pub fn encode(&self) -> Vec<u8> {
        self.to_pb().encode_to_vec()
    }

    /// Decodes `pigeon.wire.v1.IdentityBundle`. Does **not** verify; call
    /// [`Self::verify`].
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let decoded = pb::IdentityBundle::decode(bytes).map_err(|_| Error::MalformedBundle)?;
        Self::from_pb(decoded)
    }

    fn to_pb(&self) -> pb::IdentityBundle {
        pb::IdentityBundle {
            identity_key: self.identity_key.to_vec(),
            curve_identity_key: self.curve_identity_key.to_vec(),
            binding_signature: self.binding_signature.to_vec(),
        }
    }

    fn from_pb(decoded: pb::IdentityBundle) -> Result<Self, Error> {
        Ok(Self {
            identity_key: vec_to_array32(decoded.identity_key)?,
            curve_identity_key: vec_to_array32(decoded.curve_identity_key)?,
            binding_signature: vec_to_array64(decoded.binding_signature)?,
        })
    }
}

impl PrekeyBundle {
    /// Encodes this bundle as `pigeon.wire.v1.PrekeyBundle`.
    pub fn encode(&self) -> Vec<u8> {
        pb::PrekeyBundle {
            identity: Some(self.identity.to_pb()),
            prekey: self.prekey.to_vec(),
            prekey_signature: self.prekey_signature.to_vec(),
            one_time: self.one_time,
        }
        .encode_to_vec()
    }

    /// Decodes `pigeon.wire.v1.PrekeyBundle`. Does **not** verify; call
    /// [`Self::verify`].
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let decoded = pb::PrekeyBundle::decode(bytes).map_err(|_| Error::MalformedBundle)?;
        let identity = decoded.identity.ok_or(Error::MalformedBundle)?;
        Ok(Self {
            identity: IdentityBundle::from_pb(identity)?,
            prekey: vec_to_array32(decoded.prekey)?,
            prekey_signature: vec_to_array64(decoded.prekey_signature)?,
            one_time: decoded.one_time,
        })
    }
}

impl Initiation {
    /// Encodes this initiation as a single `pigeon.wire.v1.Initiation` blob — the
    /// identity bundle plus the first Olm pre-key message.
    pub fn encode(&self) -> Vec<u8> {
        pb::Initiation {
            identity: Some(self.identity.to_pb()),
            message: Some(olm_message_to_pb(&self.message)),
        }
        .encode_to_vec()
    }

    /// Decodes `pigeon.wire.v1.Initiation`. Does **not** verify the identity
    /// binding; [`crate::Session::establish_inbound`] does that.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let decoded = pb::Initiation::decode(bytes).map_err(|_| Error::MalformedBundle)?;
        let identity = decoded.identity.ok_or(Error::MalformedBundle)?;
        let message = decoded.message.ok_or(Error::MalformedBundle)?;
        Ok(Self {
            identity: IdentityBundle::from_pb(identity)?,
            message: olm_message_from_pb(message)?,
        })
    }
}

/// Encodes an Olm message as `pigeon.wire.v1.OlmMessage`.
pub fn encode_olm_message(message: &OlmMessage) -> Vec<u8> {
    olm_message_to_pb(message).encode_to_vec()
}

/// Decodes `pigeon.wire.v1.OlmMessage`.
pub fn decode_olm_message(bytes: &[u8]) -> Result<OlmMessage, Error> {
    let decoded = pb::OlmMessage::decode(bytes).map_err(|_| Error::MalformedBundle)?;
    olm_message_from_pb(decoded)
}

fn olm_message_to_pb(message: &OlmMessage) -> pb::OlmMessage {
    let (message_type, ciphertext) = message.to_parts();
    pb::OlmMessage {
        message_type: message_type as u32,
        ciphertext: ciphertext.to_vec(),
    }
}

fn olm_message_from_pb(decoded: pb::OlmMessage) -> Result<OlmMessage, Error> {
    OlmMessage::from_parts(decoded.message_type as usize, &decoded.ciphertext)
        .map_err(|_| Error::MalformedBundle)
}

fn vec_to_array32(bytes: Vec<u8>) -> Result<[u8; 32], Error> {
    bytes.try_into().map_err(|_| Error::MalformedBundle)
}

fn vec_to_array64(bytes: Vec<u8>) -> Result<[u8; 64], Error> {
    bytes.try_into().map_err(|_| Error::MalformedBundle)
}
