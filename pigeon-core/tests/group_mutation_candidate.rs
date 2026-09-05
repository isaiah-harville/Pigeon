use pigeon_core::{Error, GroupMutationCandidate, MAX_PROPOSAL_CANDIDATES, wire_proto};
use prost::Message;

#[test]
fn mutation_candidate_round_trips_commit_and_referenced_proposals() {
    let candidate = GroupMutationCandidate::new(
        vec![b"self-remove".to_vec(), b"other-proposal".to_vec()],
        b"commit".to_vec(),
    )
    .unwrap();

    let decoded = GroupMutationCandidate::decode(&candidate.encode()).unwrap();

    assert_eq!(
        decoded.proposals(),
        &[b"self-remove".to_vec(), b"other-proposal".to_vec()]
    );
    assert_eq!(decoded.commit(), b"commit");
}

#[test]
fn mutation_candidate_rejects_empty_or_excessive_content_before_crypto() {
    assert!(matches!(
        GroupMutationCandidate::new(Vec::new(), Vec::new()),
        Err(Error::MalformedBundle)
    ));

    let too_many = wire_proto::GroupMutationCandidate {
        version: 1,
        proposals: vec![vec![1]; MAX_PROPOSAL_CANDIDATES + 1],
        commit: vec![2],
    }
    .encode_to_vec();
    assert!(matches!(
        GroupMutationCandidate::decode(&too_many),
        Err(Error::ResourceLimit("MLS proposal candidates"))
    ));
}

#[test]
fn mutation_candidate_rejects_unsupported_versions_and_empty_proposals() {
    let unsupported = wire_proto::GroupMutationCandidate {
        version: 2,
        proposals: Vec::new(),
        commit: vec![1],
    }
    .encode_to_vec();
    assert!(matches!(
        GroupMutationCandidate::decode(&unsupported),
        Err(Error::UnsupportedVersion {
            kind: "group mutation candidate",
            version: 2
        })
    ));

    let empty_proposal = wire_proto::GroupMutationCandidate {
        version: 1,
        proposals: vec![Vec::new()],
        commit: vec![1],
    }
    .encode_to_vec();
    assert!(matches!(
        GroupMutationCandidate::decode(&empty_proposal),
        Err(Error::MalformedBundle)
    ));
}
