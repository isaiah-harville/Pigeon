// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! The terminal client's long-term identity and its sealed checkpoint store.
//!
//! The Ed25519 root key is Pigeon's identity: the safety-number root, the
//! signer of Olm's Curve25519 identity binding, and the relay mailbox address.
//! It lives only inside the passphrase-sealed vault and is handed to
//! `pigeon-core` through the same `SecureIdentity` boundary the iOS Keychain
//! implements, so core never sees the seed.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use pigeon_core::{
    IdentityError, IdentityPurpose, SealedCheckpoint, SecureIdentity, StateStore, StorageError,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::vault::{Vault, VaultError};

const IDENTITY_LABEL: &str = "identity";
const CHECKPOINT_LABEL: &str = "checkpoint";

#[derive(Clone)]
pub struct CliIdentity {
    key: Arc<SigningKey>,
}

impl std::fmt::Debug for CliIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CliIdentity")
            .field("public", &hex::encode(self.public()))
            .finish()
    }
}

impl CliIdentity {
    /// Generates a fresh identity and seals it. Never overwrites an existing one.
    pub fn create(vault: &Vault) -> Result<Self, VaultError> {
        if vault.load(IDENTITY_LABEL)?.is_some() {
            return Err(VaultError::AlreadyExists);
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(seed.as_mut()).map_err(|_| VaultError::Kdf)?;
        vault.store(IDENTITY_LABEL, seed.as_ref())?;
        Ok(Self::from_seed(&seed))
    }

    /// Unseals the identity; this is also the vault's passphrase check.
    pub fn load(vault: &Vault) -> Result<Self, VaultError> {
        let seed = vault
            .load(IDENTITY_LABEL)?
            .ok_or(VaultError::NotInitialized)?;
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
            seed.as_slice()
                .try_into()
                .map_err(|_| VaultError::Corrupt("identity seed length"))?,
        );
        Ok(Self::from_seed(&seed))
    }

    fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: Arc::new(SigningKey::from_bytes(seed)),
        }
    }

    pub fn public(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.key.sign(message).to_bytes()
    }
}

/// The root key serves the root and relay purposes, matching the iOS
/// `CoreIdentityProvider`. MLS and group-scoped keys are not provisioned: the
/// terminal client does direct messaging only, so group operations fail closed.
impl SecureIdentity for CliIdentity {
    fn ensure_public_key(&self, purpose: IdentityPurpose) -> Result<[u8; 32], IdentityError> {
        match purpose {
            IdentityPurpose::Root | IdentityPurpose::Relay => Ok(self.public()),
            _ => Err(IdentityError::Unavailable),
        }
    }

    fn sign(&self, purpose: IdentityPurpose, message: &[u8]) -> Result<[u8; 64], IdentityError> {
        match purpose {
            IdentityPurpose::Root | IdentityPurpose::Relay => Ok(CliIdentity::sign(self, message)),
            _ => Err(IdentityError::Unavailable),
        }
    }
}

/// Seals the core checkpoint (Olm account, sessions, pending effects) in the
/// vault. `replace` returns only after the new generation is durable.
pub struct SealedCheckpointStore {
    vault: Arc<Vault>,
}

impl SealedCheckpointStore {
    pub fn new(vault: Arc<Vault>) -> Self {
        Self { vault }
    }

    fn read(&self) -> Result<Option<SealedCheckpoint>, StorageError> {
        let Some(plain) = self
            .vault
            .load(CHECKPOINT_LABEL)
            .map_err(|_| StorageError::Unavailable)?
        else {
            return Ok(None);
        };
        if plain.len() < 8 + 32 {
            return Err(StorageError::Corrupt);
        }
        let generation = u64::from_be_bytes(plain[..8].try_into().unwrap());
        let sha256: [u8; 32] = plain[8..40].try_into().unwrap();
        let bytes = plain[40..].to_vec();
        if Sha256::digest(&bytes).as_slice() != sha256 {
            return Err(StorageError::Corrupt);
        }
        Ok(Some(SealedCheckpoint {
            generation,
            bytes,
            sha256,
        }))
    }
}

impl StateStore for SealedCheckpointStore {
    fn load(&self) -> Result<Option<SealedCheckpoint>, StorageError> {
        self.read()
    }

    fn replace(
        &mut self,
        expected_generation: u64,
        next: SealedCheckpoint,
    ) -> Result<(), StorageError> {
        let current = self.read()?.map_or(0, |checkpoint| checkpoint.generation);
        if current != expected_generation {
            return Err(StorageError::Conflict);
        }
        let mut plain = Zeroizing::new(Vec::with_capacity(40 + next.bytes.len()));
        plain.extend_from_slice(&next.generation.to_be_bytes());
        plain.extend_from_slice(&next.sha256);
        plain.extend_from_slice(&next.bytes);
        self.vault
            .store(CHECKPOINT_LABEL, &plain)
            .map_err(|_| StorageError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::TEST_COST;

    #[test]
    fn identity_persists_and_is_never_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let public = {
            let vault = Vault::create(dir.path(), "pw", TEST_COST).unwrap();
            let identity = CliIdentity::create(&vault).unwrap();
            assert!(matches!(
                CliIdentity::create(&vault),
                Err(VaultError::AlreadyExists)
            ));
            identity.public()
        };
        let vault = Vault::open(dir.path(), "pw").unwrap();
        assert_eq!(CliIdentity::load(&vault).unwrap().public(), public);
    }

    #[test]
    fn checkpoint_store_enforces_generations_and_integrity() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(Vault::create(dir.path(), "pw", TEST_COST).unwrap());
        let mut store = SealedCheckpointStore::new(vault);
        assert!(store.load().unwrap().is_none());
        let bytes = b"state".to_vec();
        let checkpoint = SealedCheckpoint {
            generation: 1,
            sha256: Sha256::digest(&bytes).into(),
            bytes,
        };
        assert_eq!(
            store.replace(5, checkpoint.clone()),
            Err(StorageError::Conflict)
        );
        store.replace(0, checkpoint.clone()).unwrap();
        assert_eq!(store.load().unwrap().unwrap().generation, 1);
        assert_eq!(store.replace(0, checkpoint), Err(StorageError::Conflict));
    }
}
