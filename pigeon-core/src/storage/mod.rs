//! Atomic checkpoint storage boundary.

mod memory;
mod openmls;

use core::fmt;

pub use memory::MemoryStateStore;
pub use openmls::TransactionalOpenMlsStorage;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedCheckpoint {
    pub generation: u64,
    pub bytes: Vec<u8>,
    pub sha256: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StorageError {
    Conflict,
    Unavailable,
    Corrupt,
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict => formatter.write_str("checkpoint generation conflict"),
            Self::Unavailable => formatter.write_str("checkpoint storage unavailable"),
            Self::Corrupt => formatter.write_str("checkpoint is corrupt"),
        }
    }
}

impl std::error::Error for StorageError {}

pub trait StateStore: Send {
    /// Loads and authenticates the latest checkpoint. Production stores must
    /// unseal bytes inside this boundary; callers never receive storage keys.
    fn load(&self) -> Result<Option<SealedCheckpoint>, StorageError>;
    /// Atomically seals and replaces the checkpoint, returning only after the
    /// new generation is durable. Failure must leave the prior generation
    /// readable and unchanged.
    fn replace(
        &mut self,
        expected_generation: u64,
        next: SealedCheckpoint,
    ) -> Result<(), StorageError>;
}
