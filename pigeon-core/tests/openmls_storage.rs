use ed25519_dalek::{Signer, SigningKey};
use pigeon_core::{
    IdentityError, IdentityPurpose, ReservedKeyPackage, SecureIdentity, TransactionalOpenMlsStorage,
};

struct TestIdentity {
    root: SigningKey,
    mls: SigningKey,
}

impl TestIdentity {
    fn new(byte: u8) -> Self {
        Self {
            root: SigningKey::from_bytes(&[byte; 32]),
            mls: SigningKey::from_bytes(&[byte.wrapping_add(64); 32]),
        }
    }
}

impl SecureIdentity for TestIdentity {
    fn ensure_public_key(&self, purpose: IdentityPurpose) -> Result<[u8; 32], IdentityError> {
        Ok(match purpose {
            IdentityPurpose::Root => self.root.verifying_key().to_bytes(),
            IdentityPurpose::Mls => self.mls.verifying_key().to_bytes(),
            _ => return Err(IdentityError::Unavailable),
        })
    }

    fn sign(&self, purpose: IdentityPurpose, message: &[u8]) -> Result<[u8; 64], IdentityError> {
        let key = match purpose {
            IdentityPurpose::Root => &self.root,
            IdentityPurpose::Mls => &self.mls,
            _ => return Err(IdentityError::Unavailable),
        };
        Ok(key.sign(message).to_bytes())
    }
}

#[test]
fn openmls_state_round_trips_as_an_opaque_checkpoint() {
    let identity = TestIdentity::new(8);
    let mut transaction = TransactionalOpenMlsStorage::new();
    ReservedKeyPackage::issue(&identity, [7; 32], &mut transaction).unwrap();
    let before = transaction.entry_count();
    assert!(before > 0);

    let checkpoint = transaction.export_checkpoint().unwrap();
    let restored = TransactionalOpenMlsStorage::from_checkpoint(&checkpoint).unwrap();
    assert_eq!(restored.entry_count(), before);
    assert_eq!(restored.export_checkpoint().unwrap(), checkpoint);
}

#[test]
fn discarded_transaction_does_not_mutate_its_base_checkpoint() {
    let identity = TestIdentity::new(9);
    let base = TransactionalOpenMlsStorage::new();
    let base_checkpoint = base.export_checkpoint().unwrap();

    let mut candidate = TransactionalOpenMlsStorage::from_checkpoint(&base_checkpoint).unwrap();
    ReservedKeyPackage::issue(&identity, [6; 32], &mut candidate).unwrap();
    assert!(candidate.entry_count() > base.entry_count());
    drop(candidate);

    assert_eq!(base.export_checkpoint().unwrap(), base_checkpoint);
}
