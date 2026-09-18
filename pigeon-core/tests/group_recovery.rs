use ed25519_dalek::{Signer, SigningKey};
use pigeon_core::{
    CoordinatorBinding, GroupAction, GroupId, GroupMemberKeys, IdentityError, IdentityPurpose,
    PigeonGroupPolicy, RecoveryCertificate, RecoveryEndorsement, RecoveryError, RecoveryProposal,
    SecureIdentity,
};

const GROUP_ID: GroupId = GroupId::from_bytes([9; 32]);
const COORDINATION_ID: [u8; 32] = [8; 32];
const EPOCH: u64 = 4;
const RECEIPT_HEAD: [u8; 32] = [7; 32];

struct TestIdentity {
    root: SigningKey,
    capability: SigningKey,
    recovery: SigningKey,
}

impl TestIdentity {
    fn new(byte: u8) -> Self {
        Self {
            root: SigningKey::from_bytes(&[byte; 32]),
            capability: SigningKey::from_bytes(&[byte.wrapping_add(96); 32]),
            recovery: SigningKey::from_bytes(&[byte.wrapping_add(128); 32]),
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
            IdentityPurpose::GroupCapability(_) => self.capability.verifying_key().to_bytes(),
            IdentityPurpose::GroupRecovery(_) => self.recovery.verifying_key().to_bytes(),
            _ => return Err(IdentityError::Unavailable),
        })
    }

    fn sign(&self, purpose: IdentityPurpose, message: &[u8]) -> Result<[u8; 64], IdentityError> {
        let key = match purpose {
            IdentityPurpose::Root => &self.root,
            IdentityPurpose::GroupCapability(_) => &self.capability,
            IdentityPurpose::GroupRecovery(_) => &self.recovery,
            _ => return Err(IdentityError::Unavailable),
        };
        Ok(key.sign(message).to_bytes())
    }
}

fn identity(byte: u8) -> TestIdentity {
    TestIdentity::new(byte)
}

fn member_keys(byte: u8) -> GroupMemberKeys {
    GroupMemberKeys::issue(
        &identity(byte),
        identity(1).root_public(),
        GROUP_ID,
        COORDINATION_ID,
    )
    .unwrap()
}

fn policy_with_non_owner_admins() -> PigeonGroupPolicy {
    let mut policy = PigeonGroupPolicy::new(
        GROUP_ID,
        identity(1).root_public(),
        (1..=4).map(member_keys).collect(),
        "Friends",
        "https://relay.example",
        CoordinatorBinding::new(
            COORDINATION_ID,
            SigningKey::from_bytes(&[60; 32]).verifying_key().to_bytes(),
        ),
    )
    .unwrap();
    for admin in [2, 3] {
        policy = policy
            .apply(&GroupAction::Promote {
                actor: identity(1).root_public(),
                subject: identity(admin).root_public(),
            })
            .unwrap()
            .0;
    }
    policy
}

fn replacement() -> CoordinatorBinding {
    CoordinatorBinding::new(
        [44; 32],
        SigningKey::from_bytes(&[61; 32]).verifying_key().to_bytes(),
    )
}

#[test]
fn strict_majority_of_non_owner_admins_recovers_without_owner() {
    let policy = policy_with_non_owner_admins();
    let proposal = RecoveryProposal::new(
        &policy,
        EPOCH,
        RECEIPT_HEAD,
        "https://replacement.example",
        replacement(),
    )
    .unwrap();
    let certificate = RecoveryCertificate::new(
        proposal.clone(),
        vec![
            RecoveryEndorsement::sign(&proposal, &identity(2)).unwrap(),
            RecoveryEndorsement::sign(&proposal, &identity(3)).unwrap(),
        ],
    )
    .unwrap();

    certificate.verify(&policy, EPOCH, RECEIPT_HEAD).unwrap();
    assert_eq!(
        RecoveryCertificate::decode(&certificate.encode()).unwrap(),
        certificate
    );
}

#[test]
fn recovery_rejects_minorities_removed_members_and_stale_contexts() {
    let policy = policy_with_non_owner_admins();
    let proposal = RecoveryProposal::new(
        &policy,
        EPOCH,
        RECEIPT_HEAD,
        "wss://replacement.example/ws",
        replacement(),
    )
    .unwrap();
    let minority = RecoveryCertificate::new(
        proposal.clone(),
        vec![RecoveryEndorsement::sign(&proposal, &identity(2)).unwrap()],
    )
    .unwrap();
    assert_eq!(
        minority.verify(&policy, EPOCH, RECEIPT_HEAD),
        Err(RecoveryError::InsufficientQuorum)
    );

    let removed = RecoveryCertificate::new(
        proposal.clone(),
        vec![RecoveryEndorsement::sign(&proposal, &identity(4)).unwrap()],
    )
    .unwrap();
    assert_eq!(
        removed.verify(&policy, EPOCH, RECEIPT_HEAD),
        Err(RecoveryError::UnauthorizedSigner)
    );
    assert_eq!(
        minority.verify(&policy, EPOCH + 1, RECEIPT_HEAD),
        Err(RecoveryError::InvalidContext)
    );
    assert_eq!(
        minority.verify(&policy, EPOCH, [6; 32]),
        Err(RecoveryError::InvalidContext)
    );
}

#[test]
fn owner_is_required_only_when_there_are_no_non_owner_admins() {
    let policy = PigeonGroupPolicy::new(
        GROUP_ID,
        identity(1).root_public(),
        (1..=3).map(member_keys).collect(),
        "Friends",
        "https://relay.example",
        CoordinatorBinding::new(
            COORDINATION_ID,
            SigningKey::from_bytes(&[60; 32]).verifying_key().to_bytes(),
        ),
    )
    .unwrap();
    let proposal = RecoveryProposal::new(
        &policy,
        EPOCH,
        RECEIPT_HEAD,
        "https://replacement.example",
        replacement(),
    )
    .unwrap();
    let certificate = RecoveryCertificate::new(
        proposal.clone(),
        vec![RecoveryEndorsement::sign(&proposal, &identity(1)).unwrap()],
    )
    .unwrap();

    certificate.verify(&policy, EPOCH, RECEIPT_HEAD).unwrap();
}
