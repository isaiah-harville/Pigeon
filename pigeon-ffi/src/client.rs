use std::fmt::Debug;
use std::sync::{Arc, Mutex};

use pigeon_core::{
    ClientCommand, IdentityError, IdentityPurpose, PigeonClient, SealedCheckpoint, SecureIdentity,
    StateStore, StorageError,
};

use crate::PigeonError;

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum IdentityPurposeKind {
    Root,
    Mls,
    Relay,
    GroupCapability,
    GroupRecovery,
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct IdentityPurposeRequest {
    pub kind: IdentityPurposeKind,
    /// Exactly 32 bytes for group-scoped purposes; empty otherwise.
    pub group_id: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct Checkpoint {
    pub generation: u64,
    /// Opaque core state. The host must seal these bytes before durable storage.
    pub bytes: Vec<u8>,
    pub sha256: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Error)]
pub enum PlatformError {
    Unavailable,
    Conflict,
    Corrupt,
    SigningFailed,
    InvalidOutput,
}

impl std::fmt::Display for PlatformError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "platform service unavailable",
            Self::Conflict => "checkpoint generation conflict",
            Self::Corrupt => "checkpoint is corrupt",
            Self::SigningFailed => "platform signing failed",
            Self::InvalidOutput => "platform returned invalid output",
        })
    }
}

impl std::error::Error for PlatformError {}

impl From<uniffi::UnexpectedUniFFICallbackError> for PlatformError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Unavailable
    }
}

/// Platform-backed public-key lookup and signing. Private key material never
/// crosses into Rust or out through this interface.
#[uniffi::export(with_foreign)]
pub trait PlatformIdentity: Send + Sync + Debug {
    fn ensure_public_key(&self, purpose: IdentityPurposeRequest) -> Result<Vec<u8>, PlatformError>;
    fn sign(
        &self,
        purpose: IdentityPurposeRequest,
        message: Vec<u8>,
    ) -> Result<Vec<u8>, PlatformError>;
}

/// Atomic storage boundary. `replace` must seal and durably replace the
/// checkpoint before returning success.
#[uniffi::export(with_foreign)]
pub trait CheckpointStore: Send + Sync + Debug {
    fn load(&self) -> Result<Option<Checkpoint>, PlatformError>;
    fn replace(&self, expected_generation: u64, next: Checkpoint) -> Result<(), PlatformError>;
}

#[derive(Clone, Debug)]
struct ForeignIdentity {
    platform: Arc<dyn PlatformIdentity>,
}

impl SecureIdentity for ForeignIdentity {
    fn ensure_public_key(&self, purpose: IdentityPurpose) -> Result<[u8; 32], IdentityError> {
        self.platform
            .ensure_public_key(purpose_request(purpose))
            .map_err(|_| IdentityError::Unavailable)?
            .try_into()
            .map_err(|_| IdentityError::Unavailable)
    }

    fn sign(&self, purpose: IdentityPurpose, message: &[u8]) -> Result<[u8; 64], IdentityError> {
        self.platform
            .sign(purpose_request(purpose), message.to_vec())
            .map_err(|_| IdentityError::SigningFailed)?
            .try_into()
            .map_err(|_| IdentityError::SigningFailed)
    }
}

#[derive(Clone, Debug)]
struct ForeignStore {
    platform: Arc<dyn CheckpointStore>,
}

impl StateStore for ForeignStore {
    fn load(&self) -> Result<Option<SealedCheckpoint>, StorageError> {
        self.platform
            .load()
            .map_err(storage_error)?
            .map(checkpoint_from_ffi)
            .transpose()
    }

    fn replace(
        &mut self,
        expected_generation: u64,
        next: SealedCheckpoint,
    ) -> Result<(), StorageError> {
        self.platform
            .replace(expected_generation, checkpoint_to_ffi(next))
            .map_err(storage_error)
    }
}

/// Transactional, byte-oriented application client. Commands and outputs are
/// versioned protobuf bytes; all cryptographic state stays behind core APIs.
#[derive(uniffi::Object)]
pub struct FfiClient {
    inner: Mutex<PigeonClient<ForeignStore, ForeignIdentity>>,
}

#[uniffi::export]
impl FfiClient {
    #[uniffi::constructor]
    pub fn new(
        identity: Arc<dyn PlatformIdentity>,
        store: Arc<dyn CheckpointStore>,
    ) -> Result<Arc<Self>, PigeonError> {
        let client = PigeonClient::new(
            ForeignStore { platform: store },
            ForeignIdentity { platform: identity },
        )?;
        Ok(Arc::new(Self {
            inner: Mutex::new(client),
        }))
    }

    pub fn execute(&self, command: Vec<u8>) -> Result<Vec<u8>, PigeonError> {
        let command = ClientCommand::decode(&command)?;
        let output = self
            .inner
            .lock()
            .map_err(|_| PigeonError::Persistence)?
            .execute(command)?;
        Ok(output.encode())
    }

    pub fn checkpoint_generation(&self) -> Result<u64, PigeonError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| PigeonError::Persistence)?
            .checkpoint_generation())
    }
}

fn purpose_request(purpose: IdentityPurpose) -> IdentityPurposeRequest {
    let (kind, group_id) = match purpose {
        IdentityPurpose::Root => (IdentityPurposeKind::Root, Vec::new()),
        IdentityPurpose::Mls => (IdentityPurposeKind::Mls, Vec::new()),
        IdentityPurpose::Relay => (IdentityPurposeKind::Relay, Vec::new()),
        IdentityPurpose::GroupCapability(group_id) => {
            (IdentityPurposeKind::GroupCapability, group_id.to_vec())
        }
        IdentityPurpose::GroupRecovery(group_id) => {
            (IdentityPurposeKind::GroupRecovery, group_id.to_vec())
        }
    };
    IdentityPurposeRequest { kind, group_id }
}

fn checkpoint_from_ffi(checkpoint: Checkpoint) -> Result<SealedCheckpoint, StorageError> {
    Ok(SealedCheckpoint {
        generation: checkpoint.generation,
        bytes: checkpoint.bytes,
        sha256: checkpoint
            .sha256
            .try_into()
            .map_err(|_| StorageError::Corrupt)?,
    })
}

fn checkpoint_to_ffi(checkpoint: SealedCheckpoint) -> Checkpoint {
    Checkpoint {
        generation: checkpoint.generation,
        bytes: checkpoint.bytes,
        sha256: checkpoint.sha256.to_vec(),
    }
}

fn storage_error(error: PlatformError) -> StorageError {
    match error {
        PlatformError::Conflict => StorageError::Conflict,
        PlatformError::Corrupt | PlatformError::InvalidOutput => StorageError::Corrupt,
        PlatformError::Unavailable | PlatformError::SigningFailed => StorageError::Unavailable,
    }
}
