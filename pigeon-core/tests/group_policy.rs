use pigeon_core::{GroupAction, GroupId, PigeonGroupPolicy, PolicyError, validate_transition};
use sha2::{Digest, Sha256};

const OWNER: [u8; 32] = [1; 32];
const ADMIN: [u8; 32] = [2; 32];
const MEMBER: [u8; 32] = [3; 32];
const DAVE: [u8; 32] = [4; 32];

fn policy() -> PigeonGroupPolicy {
    let mut policy = PigeonGroupPolicy::new(
        GroupId::from_bytes([9; 32]),
        OWNER,
        vec![ADMIN, MEMBER],
        "Friends",
        "https://relay.example",
        [8; 32],
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
            [8; 32],
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
        [8; 32],
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
fn deterministic_policy_vectors_are_stable() {
    let initial = PigeonGroupPolicy::new(
        GroupId::from_bytes([9; 32]),
        OWNER,
        vec![ADMIN, MEMBER],
        "Friends",
        "https://relay.example",
        [8; 32],
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
            "7c385d09154df78c3492594b2c41af6dc919a6c36b2a51948e7b2e04ea6891f5",
            "da8a8ef8ee973fe758c0b27bd83db7e3b777aa44a785e695fd95fe2fac5fd5e1",
            "a435b3f3a66d4789e4e74eda44cb9eb85498c6883b6193869c410f681a6928c3",
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
