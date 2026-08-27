use ed25519_dalek::{Signer, SigningKey};
use pigeon_core::{
    GroupId, GroupJoinMaterial, IdentityError, IdentityPurpose, SecureIdentity,
    TransactionalOpenMlsStorage,
};

struct TestIdentity {
    root: SigningKey,
    mls: SigningKey,
    capability: SigningKey,
    recovery: SigningKey,
}

impl TestIdentity {
    fn new(seed: u8) -> Self {
        Self {
            root: SigningKey::from_bytes(&[seed; 32]),
            mls: SigningKey::from_bytes(&[seed.wrapping_add(1); 32]),
            capability: SigningKey::from_bytes(&[seed.wrapping_add(2); 32]),
            recovery: SigningKey::from_bytes(&[seed.wrapping_add(3); 32]),
        }
    }

    fn root_public_key(&self) -> [u8; 32] {
        self.root.verifying_key().to_bytes()
    }

    fn key(&self, purpose: IdentityPurpose) -> Result<&SigningKey, IdentityError> {
        match purpose {
            IdentityPurpose::Root => Ok(&self.root),
            IdentityPurpose::Mls => Ok(&self.mls),
            IdentityPurpose::GroupCapability(_) => Ok(&self.capability),
            IdentityPurpose::GroupRecovery(_) => Ok(&self.recovery),
            IdentityPurpose::Relay => Err(IdentityError::Unavailable),
        }
    }
}

impl SecureIdentity for TestIdentity {
    fn ensure_public_key(&self, purpose: IdentityPurpose) -> Result<[u8; 32], IdentityError> {
        Ok(self.key(purpose)?.verifying_key().to_bytes())
    }

    fn sign(&self, purpose: IdentityPurpose, message: &[u8]) -> Result<[u8; 64], IdentityError> {
        Ok(self.key(purpose)?.sign(message).to_bytes())
    }
}

#[test]
fn join_material_binds_device_owned_keys_to_group_and_creator() {
    let creator = TestIdentity::new(1);
    let member = TestIdentity::new(20);
    let group_id = GroupId::from_bytes([7; 32]);
    let coordination_id = [9; 32];
    let mut storage = TransactionalOpenMlsStorage::new();

    let material = GroupJoinMaterial::issue(
        &member,
        creator.root_public_key(),
        group_id,
        coordination_id,
        &mut storage,
    )
    .unwrap();
    let decoded = GroupJoinMaterial::decode(&material.encode()).unwrap();

    decoded
        .verify_for(creator.root_public_key(), group_id, coordination_id)
        .unwrap();
    assert_eq!(decoded.member_identity(), member.root_public_key());
    assert_eq!(
        decoded.capability_public_key(),
        member.capability.verifying_key().to_bytes()
    );
    assert_eq!(
        decoded.recovery_public_key(),
        member.recovery.verifying_key().to_bytes()
    );
}

#[test]
fn join_material_is_not_reusable_across_groups_or_creators() {
    let creator = TestIdentity::new(1);
    let other_creator = TestIdentity::new(2);
    let member = TestIdentity::new(20);
    let group_id = GroupId::from_bytes([7; 32]);
    let coordination_id = [9; 32];
    let mut storage = TransactionalOpenMlsStorage::new();
    let material = GroupJoinMaterial::issue(
        &member,
        creator.root_public_key(),
        group_id,
        coordination_id,
        &mut storage,
    )
    .unwrap();

    assert!(
        material
            .verify_for(other_creator.root_public_key(), group_id, coordination_id)
            .is_err()
    );
    assert!(
        material
            .verify_for(
                creator.root_public_key(),
                GroupId::from_bytes([8; 32]),
                coordination_id,
            )
            .is_err()
    );
    assert!(
        material
            .verify_for(creator.root_public_key(), group_id, [10; 32])
            .is_err()
    );
}
