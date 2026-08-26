use prost::Message;

use pigeon_core::{
    Error, MAX_CLIENT_COMMAND_BYTES, MAX_GROUP_MEMBERS, decode_client_command, wire_proto,
};

#[test]
fn oversized_command_is_rejected_before_protobuf_decode() {
    let bytes = vec![0u8; MAX_CLIENT_COMMAND_BYTES + 1];
    assert!(matches!(
        decode_client_command(&bytes),
        Err(Error::ResourceLimit("client command bytes"))
    ));
}

#[test]
fn excessive_repeated_members_are_rejected_after_bounded_decode() {
    let command = wire_proto::ClientCommand {
        version: 1,
        command_id: "command-1".into(),
        body: Some(wire_proto::client_command::Body::CreateGroup(
            wire_proto::CreateGroup {
                name: "Friends".into(),
                member_identities: vec![vec![7u8; 32]; MAX_GROUP_MEMBERS + 1],
                relay_url: "https://relay.example".into(),
                mesh_enabled: false,
                coordinator_public_key: ed25519_dalek::SigningKey::from_bytes(&[60; 32])
                    .verifying_key()
                    .to_bytes()
                    .to_vec(),
            },
        )),
    };

    assert!(matches!(
        decode_client_command(&command.encode_to_vec()),
        Err(Error::ResourceLimit("group members"))
    ));
}

#[test]
fn unsupported_command_version_fails_explicitly() {
    let command = wire_proto::ClientCommand {
        version: 2,
        command_id: "command-2".into(),
        body: None,
    };
    assert!(matches!(
        decode_client_command(&command.encode_to_vec()),
        Err(Error::UnsupportedVersion {
            kind: "command",
            version: 2
        })
    ));
}
