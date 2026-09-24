//! Pigeon's cryptographic identity boundary.
//!
//! Root identity and every protocol derived from it live here. Pairwise Olm
//! details remain private so bindings and applications can only use the stable,
//! identity-aware core API.

mod boundary;
mod group;
mod mls;
mod pairwise;
mod root;

pub use boundary::{IdentityError, IdentityPurpose, SecureIdentity};
pub use group::{GroupJoinMaterial, GroupJoinRequest, GroupMemberKeys};
pub(crate) use mls::{CIPHERSUITE, POLICY_EXTENSION_TYPE_ID, PlatformMlsSigner};
pub use mls::{KeyPackagePool, MlsIdentityBinding, ReservedKeyPackage};
pub use pairwise::{
    Account, Initiation, PrekeyBundle, Session, decode_olm_message, encode_olm_message,
};
pub(crate) use pairwise::{PlatformAccount, PlatformSession};
pub use root::{IdentityBundle, IdentityKeypair};
