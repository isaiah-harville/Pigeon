use super::{SealedCheckpoint, StateStore, StorageError};

/// Non-sealing state store for tests and non-secret fixtures only.
#[derive(Default)]
pub struct MemoryStateStore {
    checkpoint: Option<SealedCheckpoint>,
    fail_replace: bool,
}

impl MemoryStateStore {
    pub fn failing_on_replace() -> Self {
        Self {
            checkpoint: None,
            fail_replace: true,
        }
    }
}

impl StateStore for MemoryStateStore {
    fn load(&self) -> Result<Option<SealedCheckpoint>, StorageError> {
        Ok(self.checkpoint.clone())
    }

    fn replace(
        &mut self,
        expected_generation: u64,
        next: SealedCheckpoint,
    ) -> Result<(), StorageError> {
        if self.fail_replace {
            return Err(StorageError::Unavailable);
        }
        let current_generation = self
            .checkpoint
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.generation);
        if current_generation != expected_generation || next.generation != expected_generation + 1 {
            return Err(StorageError::Conflict);
        }
        self.checkpoint = Some(next);
        Ok(())
    }
}
