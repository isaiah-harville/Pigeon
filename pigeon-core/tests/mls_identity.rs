use ed25519_dalek::{Signer, SigningKey};
use pigeon_core::{
    IdentityError, IdentityPurpose, KeyPackagePool, MlsIdentityBinding, ReservedKeyPackage,
    SecureIdentity, TransactionalOpenMlsStorage,
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

    fn root_public(&self) -> [u8; 32] {
        self.root.verifying_key().to_bytes()
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
fn mls_key_is_distinct_and_bound_to_the_root_identity() {
    let alice = TestIdentity::new(1);
    let binding = MlsIdentityBinding::create(&alice).unwrap();

    assert_ne!(binding.root_public_key(), binding.mls_public_key());
    binding.verify().unwrap();
}

#[test]
fn key_package_is_single_use_and_reserved_to_its_consumer() {
    let alice = TestIdentity::new(1);
    let bob = TestIdentity::new(2);
    let carol = TestIdentity::new(3);
    let mut storage = TransactionalOpenMlsStorage::new();
    let package = ReservedKeyPackage::issue(&alice, bob.root_public(), &mut storage).unwrap();

    package.verify_for(bob.root_public()).unwrap();
    assert!(package.verify_for(carol.root_public()).is_err());
    let package = ReservedKeyPackage::decode(&package.encode()).unwrap();
    package.verify_for(bob.root_public()).unwrap();
    let mut tampered = package.encode();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(
        ReservedKeyPackage::decode(&tampered)
            .and_then(|package| package.verify_for(bob.root_public()))
            .is_err()
    );

    let mut pool = KeyPackagePool::default();
    pool.insert_for(bob.root_public(), package).unwrap();
    let consumed = pool
        .consume(alice.root_public(), bob.root_public())
        .unwrap();
    assert!(!consumed.tls_bytes().is_empty());
    assert!(
        pool.consume(alice.root_public(), bob.root_public())
            .is_err()
    );
}
