//! Pigeon's cryptographic identity boundary.
//!
//! Root identity and every protocol derived from it live here. Pairwise Olm
//! details remain private so bindings and applications can only use the stable,
//! identity-aware core API.

mod pairwise;
mod root;

pub use pairwise::{
    Account, Initiation, PrekeyBundle, Session, decode_olm_message, encode_olm_message,
};
pub use root::{IdentityBundle, IdentityKeypair};
