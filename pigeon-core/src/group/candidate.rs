use prost::Message;

use crate::Error;
use crate::wire::{MAX_MLS_OBJECT_BYTES, MAX_PROPOSAL_CANDIDATES, PROTOCOL_VERSION, proto};

/// A coordinator-sequenced MLS commit plus every referenced proposal needed to
/// process it. The relay treats these bytes as opaque.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupMutationCandidate {
    proposals: Vec<Vec<u8>>,
    commit: Vec<u8>,
}

impl GroupMutationCandidate {
    pub fn new(proposals: Vec<Vec<u8>>, commit: Vec<u8>) -> Result<Self, Error> {
        let candidate = Self { proposals, commit };
        candidate.validate()?;
        Ok(candidate)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_MLS_OBJECT_BYTES {
            return Err(Error::ResourceLimit("group mutation candidate bytes"));
        }
        let decoded =
            proto::GroupMutationCandidate::decode(bytes).map_err(|_| Error::MalformedBundle)?;
        if decoded.version != PROTOCOL_VERSION {
            return Err(Error::UnsupportedVersion {
                kind: "group mutation candidate",
                version: decoded.version,
            });
        }
        let candidate = Self {
            proposals: decoded.proposals,
            commit: decoded.commit,
        };
        candidate.validate()?;
        Ok(candidate)
    }

    pub fn encode(&self) -> Vec<u8> {
        proto::GroupMutationCandidate {
            version: PROTOCOL_VERSION,
            proposals: self.proposals.clone(),
            commit: self.commit.clone(),
        }
        .encode_to_vec()
    }

    pub fn proposals(&self) -> &[Vec<u8>] {
        &self.proposals
    }

    pub fn commit(&self) -> &[u8] {
        &self.commit
    }

    fn validate(&self) -> Result<(), Error> {
        if self.commit.is_empty() {
            return Err(Error::MalformedBundle);
        }
        if self.proposals.len() > MAX_PROPOSAL_CANDIDATES {
            return Err(Error::ResourceLimit("MLS proposal candidates"));
        }
        if self.commit.len() > MAX_MLS_OBJECT_BYTES {
            return Err(Error::ResourceLimit("MLS commit bytes"));
        }
        for proposal in &self.proposals {
            if proposal.is_empty() {
                return Err(Error::MalformedBundle);
            }
            if proposal.len() > MAX_MLS_OBJECT_BYTES {
                return Err(Error::ResourceLimit("MLS proposal bytes"));
            }
        }
        let encoded_len = proto::GroupMutationCandidate {
            version: PROTOCOL_VERSION,
            proposals: self.proposals.clone(),
            commit: self.commit.clone(),
        }
        .encoded_len();
        if encoded_len > MAX_MLS_OBJECT_BYTES {
            return Err(Error::ResourceLimit("group mutation candidate bytes"));
        }
        Ok(())
    }
}
