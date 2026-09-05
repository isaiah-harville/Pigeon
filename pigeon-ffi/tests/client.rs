use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer, SigningKey};
use pigeon_core::{wire_proto, ClientCommand};
use pigeon_ffi::{
    Checkpoint, CheckpointStore, FfiClient, IdentityPurposeKind, IdentityPurposeRequest,
    PlatformError, PlatformIdentity,
};
use prost::Message;

#[derive(Debug)]
struct TestIdentity {
    root: SigningKey,
    mls: SigningKey,
    capability: SigningKey,
    recovery: SigningKey,
}

impl TestIdentity {
    fn new() -> Self {
        Self {
            root: SigningKey::from_bytes(&[1; 32]),
            mls: SigningKey::from_bytes(&[2; 32]),
            capability: SigningKey::from_bytes(&[3; 32]),
            recovery: SigningKey::from_bytes(&[4; 32]),
        }
    }

    fn key(&self, purpose: &IdentityPurposeRequest) -> &SigningKey {
        match purpose.kind {
            IdentityPurposeKind::Root => &self.root,
            IdentityPurposeKind::Mls => &self.mls,
            IdentityPurposeKind::Relay => &self.root,
            IdentityPurposeKind::GroupCapability => &self.capability,
            IdentityPurposeKind::GroupRecovery => &self.recovery,
        }
    }
}

impl PlatformIdentity for TestIdentity {
    fn ensure_public_key(&self, purpose: IdentityPurposeRequest) -> Result<Vec<u8>, PlatformError> {
        Ok(self.key(&purpose).verifying_key().to_bytes().to_vec())
    }

    fn sign(
        &self,
        purpose: IdentityPurposeRequest,
        message: Vec<u8>,
    ) -> Result<Vec<u8>, PlatformError> {
        Ok(self.key(&purpose).sign(&message).to_bytes().to_vec())
    }
}

#[derive(Debug, Default)]
struct TestStore {
    checkpoint: Mutex<Option<Checkpoint>>,
    fail_replace: bool,
}

impl CheckpointStore for TestStore {
    fn load(&self) -> Result<Option<Checkpoint>, PlatformError> {
        Ok(self.checkpoint.lock().unwrap().clone())
    }

    fn replace(&self, expected_generation: u64, next: Checkpoint) -> Result<(), PlatformError> {
        if self.fail_replace {
            return Err(PlatformError::Unavailable);
        }
        let mut current = self.checkpoint.lock().unwrap();
        if current
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.generation)
            != expected_generation
        {
            return Err(PlatformError::Conflict);
        }
        *current = Some(next);
        Ok(())
    }
}

fn create_group() -> ClientCommand {
    ClientCommand::create_group(
        "ffi-create",
        "Birds",
        vec![[8; 32], [9; 32]],
        "https://relay.example",
        SigningKey::from_bytes(&[10; 32]).verifying_key().to_bytes(),
        false,
    )
    .unwrap()
}

#[test]
fn client_returns_output_only_after_the_host_checkpoint_is_durable() {
    let store = Arc::new(TestStore::default());
    let client = FfiClient::new(Arc::new(TestIdentity::new()), store.clone()).unwrap();

    let output = client.execute(create_group().encode()).unwrap();

    assert!(!output.is_empty());
    assert_eq!(client.checkpoint_generation().unwrap(), 1);
    assert_eq!(store.load().unwrap().unwrap().generation, 1);
}

#[test]
fn client_releases_no_output_when_the_host_checkpoint_fails() {
    let store = Arc::new(TestStore {
        checkpoint: Mutex::new(None),
        fail_replace: true,
    });
    let client = FfiClient::new(Arc::new(TestIdentity::new()), store).unwrap();

    assert!(client.execute(create_group().encode()).is_err());
    assert_eq!(client.checkpoint_generation().unwrap(), 0);
}

#[test]
fn client_exposes_read_only_snapshot_bytes() {
    let client = FfiClient::new(
        Arc::new(TestIdentity::new()),
        Arc::new(TestStore::default()),
    )
    .unwrap();

    let snapshot =
        wire_proto::ClientSnapshot::decode(client.snapshot().unwrap().as_slice()).unwrap();

    assert_eq!(snapshot.checkpoint_generation, 0);
    assert!(snapshot.groups.is_empty());
    assert_eq!(client.checkpoint_generation().unwrap(), 0);
}

#[test]
fn relay_challenge_signing_rejects_malformed_identifiers_at_the_ffi_boundary() {
    let client = FfiClient::new(
        Arc::new(TestIdentity::new()),
        Arc::new(TestStore::default()),
    )
    .unwrap();

    assert!(client
        .sign_group_relay_challenge(vec![1; 31], vec![2; 32])
        .is_err());
    assert!(client
        .sign_group_relay_challenge(vec![1; 32], vec![2; 31])
        .is_err());
}
