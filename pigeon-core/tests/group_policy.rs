use ed25519_dalek::{Signer, SigningKey};
use pigeon_core::{
    CoordinatorBinding, GroupAction, GroupId, GroupMemberKeys, GroupRelayControl,
    GroupRelayControlKind, IdentityError, IdentityPurpose, PigeonGroupPolicy, PolicyError,
    SecureIdentity, validate_transition,
};
use sha2::{Digest, Sha256};

const GROUP_ID: GroupId = GroupId::from_bytes([9; 32]);
const COORDINATION_ID: [u8; 32] = [8; 32];

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

fn root(byte: u8) -> [u8; 32] {
    TestIdentity::new(byte).root_public()
}

fn member_keys(byte: u8) -> GroupMemberKeys {
    GroupMemberKeys::issue(&TestIdentity::new(byte), root(1), GROUP_ID, COORDINATION_ID).unwrap()
}

fn coordinator_key() -> [u8; 32] {
    SigningKey::from_bytes(&[60; 32]).verifying_key().to_bytes()
}

fn new_policy(member_keys: Vec<GroupMemberKeys>) -> Result<PigeonGroupPolicy, PolicyError> {
    PigeonGroupPolicy::new(
        GROUP_ID,
        root(1),
        member_keys,
        "Friends",
        "https://relay.example",
        CoordinatorBinding::new(COORDINATION_ID, coordinator_key()),
    )
}

fn policy() -> PigeonGroupPolicy {
    let mut policy = new_policy(vec![member_keys(1), member_keys(2), member_keys(3)]).unwrap();
    policy = policy
        .apply(&GroupAction::Promote {
            actor: root(1),
            subject: root(2),
        })
        .unwrap()
        .0;
    policy
}

#[test]
fn policy_role_matrix_is_fail_closed() {
    let policy = policy();
    let four_members = policy
        .apply(&GroupAction::Add {
            actor: root(2),
            member_keys: Box::new(member_keys(4)),
        })
        .unwrap()
        .0;
    assert!(
        four_members
            .apply(&GroupAction::Leave {
                actor: root(3),
                committer: root(2),
            })
            .is_ok()
    );
    assert!(
        policy
            .apply(&GroupAction::Add {
                actor: root(3),
                member_keys: Box::new(member_keys(4)),
            })
            .is_err()
    );
    assert!(
        policy
            .apply(&GroupAction::Leave {
                actor: root(3),
                committer: root(2),
            })
            .is_err(),
        "a three-person group cannot shrink below three"
    );
    assert!(
        policy
            .apply(&GroupAction::Leave {
                actor: root(1),
                committer: root(2),
            })
            .is_err()
    );
    assert!(
        policy
            .apply(&GroupAction::Demote {
                actor: root(2),
                subject: root(2),
            })
            .is_err()
    );
    assert!(
        policy
            .apply(&GroupAction::Rename {
                actor: root(2),
                name: "no".into(),
            })
            .is_err()
    );
    assert!(
        policy
            .apply(&GroupAction::SetMesh {
                actor: root(1),
                enabled: true,
            })
            .is_ok()
    );
}

#[test]
fn owner_and_terminal_invariants_cannot_be_bypassed() {
    let policy = policy();
    assert!(
        policy
            .apply(&GroupAction::Remove {
                actor: root(2),
                subject: root(1),
            })
            .is_err()
    );
    assert!(
        policy
            .apply(&GroupAction::Demote {
                actor: root(2),
                subject: root(1),
            })
            .is_err()
    );
    let dissolved = policy
        .apply(&GroupAction::Dissolve { actor: root(1) })
        .unwrap()
        .0;
    assert!(
        dissolved
            .apply(&GroupAction::SetMesh {
                actor: root(1),
                enabled: true,
            })
            .is_err()
    );
}

#[test]
fn roster_bounds_and_duplicates_are_rejected() {
    assert!(
        new_policy(vec![member_keys(1), member_keys(1), member_keys(3)]).is_err(),
        "duplicate member identities and key bindings must fail"
    );

    let members = (1u8..=128).map(member_keys).collect();
    let at_cap = new_policy(members).unwrap();
    assert_eq!(at_cap.members().len(), 128);
    assert!(
        at_cap
            .apply(&GroupAction::Add {
                actor: root(1),
                member_keys: Box::new(member_keys(129)),
            })
            .is_err()
    );
}

#[test]
fn membership_transitions_derive_exact_relay_capability_changes() {
    let initial = new_policy(vec![member_keys(1), member_keys(2), member_keys(3)]).unwrap();
    let (promoted, promoted_event) = initial
        .apply(&GroupAction::Promote {
            actor: root(1),
            subject: root(2),
        })
        .unwrap();
    let promote = GroupRelayControl::for_transition(&initial, &promoted, &promoted_event)
        .unwrap()
        .unwrap();
    assert_eq!(promote.kind(), GroupRelayControlKind::PromoteAdmin);
    assert_eq!(promote.public_key(), member_keys(2).capability_public_key());
    let (demoted, demoted_event) = promoted
        .apply(&GroupAction::Demote {
            actor: root(1),
            subject: root(2),
        })
        .unwrap();
    let demote = GroupRelayControl::for_transition(&promoted, &demoted, &demoted_event)
        .unwrap()
        .unwrap();
    assert_eq!(demote.kind(), GroupRelayControlKind::DemoteAdmin);

    let prior = policy();
    let dave_keys = member_keys(4);
    let dave_capability = dave_keys.capability_public_key();
    let (with_dave, added) = prior
        .apply(&GroupAction::Add {
            actor: root(2),
            member_keys: Box::new(dave_keys),
        })
        .unwrap();
    let grant = GroupRelayControl::for_transition(&prior, &with_dave, &added)
        .unwrap()
        .unwrap();
    assert_eq!(grant.kind(), GroupRelayControlKind::Grant);
    assert_eq!(grant.public_key(), dave_capability);
    assert_eq!(grant.coordination_id(), COORDINATION_ID);
    assert_eq!(GroupRelayControl::decode(&grant.encode()).unwrap(), grant);

    let (without_dave, removed) = with_dave
        .apply(&GroupAction::Remove {
            actor: root(2),
            subject: root(4),
        })
        .unwrap();
    let revoke = GroupRelayControl::for_transition(&with_dave, &without_dave, &removed)
        .unwrap()
        .unwrap();
    assert_eq!(revoke.kind(), GroupRelayControlKind::Revoke);
    assert_eq!(revoke.public_key(), dave_capability);

    let (renamed, renamed_event) = without_dave
        .apply(&GroupAction::Rename {
            actor: root(1),
            name: "Best Friends".into(),
        })
        .unwrap();
    assert!(
        GroupRelayControl::for_transition(&without_dave, &renamed, &renamed_event)
            .unwrap()
            .is_none()
    );
    assert!(GroupRelayControl::for_transition(&prior, &renamed, &added).is_err());
}

#[test]
fn coordinator_signing_key_is_required_and_authenticated() {
    assert_eq!(
        PigeonGroupPolicy::new(
            GROUP_ID,
            root(1),
            vec![member_keys(1), member_keys(2), member_keys(3)],
            "Friends",
            "https://relay.example",
            CoordinatorBinding::new(COORDINATION_ID, [0; 32]),
        ),
        Err(PolicyError::InvalidRelay)
    );
    assert_eq!(policy().coordinator_public_key(), coordinator_key());
}

#[test]
fn deterministic_policy_vectors_are_stable() {
    let initial = new_policy(vec![member_keys(1), member_keys(2), member_keys(3)]).unwrap();
    let renamed = initial
        .apply(&GroupAction::Rename {
            actor: root(1),
            name: "Best Friends".into(),
        })
        .unwrap()
        .0;
    let mesh = renamed
        .apply(&GroupAction::SetMesh {
            actor: root(1),
            enabled: true,
        })
        .unwrap()
        .0;

    let hashes: Vec<String> = [initial, renamed, mesh]
        .iter()
        .map(|policy| {
            Sha256::digest(policy.encode())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect()
        })
        .collect();
    assert_eq!(
        hashes,
        [
            "3045f22d34580be2d3d84628dda7dba4f8f0274500998066dcfeda03bd7975c9",
            "0252110b6fcf515ab61d13fd710fecfd9795149375de4617aae6a758b2afbf90",
            "3ac92d33a70427c8d266238494b7d6a0bb286598e35b736bde34975a8b11ac75",
        ]
    );
}

#[test]
fn transition_requires_exactly_the_authenticated_action() {
    let prior = policy();
    let action = GroupAction::Rename {
        actor: root(1),
        name: "Best Friends".into(),
    };
    let (next, _) = prior.apply(&action).unwrap();
    validate_transition(&prior, &next, &action).unwrap();

    let mut bytes = next.encode();
    let mut decoded = PigeonGroupPolicy::decode(&bytes).unwrap();
    assert_eq!(decoded.encode(), bytes);
    bytes.reverse();
    assert!(PigeonGroupPolicy::decode(&bytes).is_err());

    decoded = decoded
        .apply(&GroupAction::SetMesh {
            actor: root(1),
            enabled: true,
        })
        .unwrap()
        .0;
    assert!(matches!(
        validate_transition(&prior, &decoded, &action),
        Err(PolicyError::InvalidRevision)
    ));
}

#[test]
fn names_must_already_be_canonical_nfc() {
    let policy = policy();
    assert!(
        policy
            .apply(&GroupAction::Rename {
                actor: root(1),
                name: "Cafe\u{301}".into(),
            })
            .is_err()
    );
    assert!(
        policy
            .apply(&GroupAction::Rename {
                actor: root(1),
                name: "Café".into(),
            })
            .is_ok()
    );
    assert!(
        policy
            .apply(&GroupAction::Rename {
                actor: root(1),
                name: "Alice\u{202e}Bob".into(),
            })
            .is_err()
    );
    assert!(
        policy
            .apply(&GroupAction::Rename {
                actor: root(1),
                name: "x".repeat(65),
            })
            .is_err()
    );
}
