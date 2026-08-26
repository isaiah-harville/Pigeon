use ed25519_dalek::SigningKey;
use pigeon_core::{
    CoordinatorBinding, GroupAction, GroupId, PigeonGroupPolicy, PolicyError, validate_transition,
};
use sha2::{Digest, Sha256};

const OWNER: [u8; 32] = [1; 32];
const ADMIN: [u8; 32] = [2; 32];
const MEMBER: [u8; 32] = [3; 32];
const DAVE: [u8; 32] = [4; 32];

fn coordinator_key() -> [u8; 32] {
    SigningKey::from_bytes(&[60; 32]).verifying_key().to_bytes()
}

fn policy() -> PigeonGroupPolicy {
    let mut policy = PigeonGroupPolicy::new(
        GroupId::from_bytes([9; 32]),
        OWNER,
        vec![ADMIN, MEMBER],
        "Friends",
        "https://relay.example",
        CoordinatorBinding::new([8; 32], coordinator_key()),
    )
    .unwrap();
    policy = policy
        .apply(&GroupAction::Promote {
            actor: OWNER,
            subject: ADMIN,
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
            actor: ADMIN,
            subject: DAVE,
        })
        .unwrap()
        .0;
    assert!(
        four_members
            .apply(&GroupAction::Leave {
                actor: MEMBER,
                committer: DAVE,
            })
            .is_ok()
    );
    assert!(
        policy
            .apply(&GroupAction::Add {
                actor: MEMBER,
                subject: DAVE
            })
            .is_err()
    );
    assert!(
        policy
            .apply(&GroupAction::Leave {
                actor: MEMBER,
                committer: ADMIN,
            })
            .is_err(),
        "a three-person group cannot shrink below three"
    );
    assert!(
        policy
            .apply(&GroupAction::Leave {
                actor: OWNER,
                committer: ADMIN,
            })
            .is_err()
    );
    assert!(
        policy
            .apply(&GroupAction::Demote {
                actor: ADMIN,
                subject: ADMIN,
            })
            .is_err()
    );
    assert!(
        policy
            .apply(&GroupAction::Rename {
                actor: ADMIN,
                name: "no".into(),
            })
            .is_err()
    );
    assert!(
        policy
            .apply(&GroupAction::SetMesh {
                actor: OWNER,
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
                actor: ADMIN,
                subject: OWNER,
            })
            .is_err()
    );
    assert!(
        policy
            .apply(&GroupAction::Demote {
                actor: ADMIN,
                subject: OWNER,
            })
            .is_err()
    );
    let dissolved = policy
        .apply(&GroupAction::Dissolve { actor: OWNER })
        .unwrap()
        .0;
    assert!(
        dissolved
            .apply(&GroupAction::SetMesh {
                actor: OWNER,
                enabled: true,
            })
            .is_err()
    );
}

#[test]
fn roster_bounds_and_duplicates_are_rejected() {
    assert!(
        PigeonGroupPolicy::new(
            GroupId::from_bytes([9; 32]),
            OWNER,
            vec![OWNER, MEMBER],
            "Friends",
            "https://relay.example",
            CoordinatorBinding::new([8; 32], coordinator_key()),
        )
        .is_err()
    );

    let members: Vec<[u8; 32]> = (2u8..=128).map(|byte| [byte; 32]).collect();
    let at_cap = PigeonGroupPolicy::new(
        GroupId::from_bytes([9; 32]),
        OWNER,
        members,
        "Friends",
        "https://relay.example",
        CoordinatorBinding::new([8; 32], coordinator_key()),
    )
    .unwrap();
    assert_eq!(at_cap.members().len(), 128);
    assert!(
        at_cap
            .apply(&GroupAction::Add {
                actor: OWNER,
                subject: [129; 32],
            })
            .is_err()
    );
}

#[test]
fn coordinator_signing_key_is_required_and_authenticated() {
    assert_eq!(
        PigeonGroupPolicy::new(
            GroupId::from_bytes([9; 32]),
            OWNER,
            vec![ADMIN, MEMBER],
            "Friends",
            "https://relay.example",
            CoordinatorBinding::new([8; 32], [0; 32]),
        ),
        Err(PolicyError::InvalidRelay)
    );
    assert_eq!(policy().coordinator_public_key(), coordinator_key());
}

#[test]
fn deterministic_policy_vectors_are_stable() {
    let initial = PigeonGroupPolicy::new(
        GroupId::from_bytes([9; 32]),
        OWNER,
        vec![ADMIN, MEMBER],
        "Friends",
        "https://relay.example",
        CoordinatorBinding::new([8; 32], coordinator_key()),
    )
    .unwrap();
    let renamed = initial
        .apply(&GroupAction::Rename {
            actor: OWNER,
            name: "Best Friends".into(),
        })
        .unwrap()
        .0;
    let mesh = renamed
        .apply(&GroupAction::SetMesh {
            actor: OWNER,
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
            "1deedfcb74a9b858ae31523b1cc1c65b234c7bf91562a5fd688fdbc77be9b412",
            "eaa63b560701be7aced4efc04048f49767aef5e8365839a2a73d3b2d05e46957",
            "ba1e5be5f7c3d0e0299a25b89629c65dcedafd14ee08e2f16d3fb8a254c89b20",
        ]
    );
}

#[test]
fn transition_requires_exactly_the_authenticated_action() {
    let prior = policy();
    let action = GroupAction::Rename {
        actor: OWNER,
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
            actor: OWNER,
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
                actor: OWNER,
                name: "Cafe\u{301}".into(),
            })
            .is_err()
    );
    assert!(
        policy
            .apply(&GroupAction::Rename {
                actor: OWNER,
                name: "Café".into(),
            })
            .is_ok()
    );
    assert!(
        policy
            .apply(&GroupAction::Rename {
                actor: OWNER,
                name: "Alice\u{202e}Bob".into(),
            })
            .is_err()
    );
    assert!(
        policy
            .apply(&GroupAction::Rename {
                actor: OWNER,
                name: "x".repeat(65),
            })
            .is_err()
    );
}
