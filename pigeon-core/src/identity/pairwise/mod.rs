//! Identity-bound pairwise messaging implemented with Olm via `vodozemac`.

mod account;
mod prekey;
mod session;
mod wire;

pub use account::Account;
pub(crate) use account::PlatformAccount;
pub use prekey::PrekeyBundle;
pub(crate) use session::PlatformSession;
pub use session::{Initiation, Session};
pub use wire::{decode_olm_message, encode_olm_message};
