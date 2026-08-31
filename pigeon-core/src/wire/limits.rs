//! Named protocol resource limits. These are checked before expensive crypto.

pub const PROTOCOL_VERSION: u32 = 1;
pub const IDENTITY_KEY_BYTES: usize = 32;
pub const GROUP_ID_BYTES: usize = 32;
pub const MAX_CLIENT_COMMAND_BYTES: usize = 256 * 1024;
pub const MAX_MLS_OBJECT_BYTES: usize = 1024 * 1024;
pub const MAX_GROUP_APPLICATION_BYTES: usize = 64 * 1024;
pub const MAX_GROUP_MEMBERS: usize = 128;
pub const MAX_GROUP_NAME_BYTES: usize = 256;
pub const MAX_GROUP_NAME_SCALARS: usize = 64;
pub const MAX_RELAY_URL_BYTES: usize = 2 * 1024;
pub const MAX_POLICY_STRING_BYTES: usize = MAX_RELAY_URL_BYTES;
pub const MAX_STABLE_ID_BYTES: usize = 128;
pub const MAX_FUTURE_EPOCHS: usize = 8;
pub const MAX_FUTURE_EPOCH_BUFFER_BYTES: usize = 2 * MAX_MLS_OBJECT_BYTES;
pub const MAX_PROPOSAL_CANDIDATES: usize = 256;
pub const MAX_PENDING_OUTBOUND_ENTRIES: usize = 1024;
pub const MAX_PENDING_EFFECT_BYTES: usize = 16 * 1024 * 1024;
