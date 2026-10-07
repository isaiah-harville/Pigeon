#[derive(Clone, Debug)]
pub struct ClientCommand {
    pub(crate) inner: proto::ClientCommand,
}

impl ClientCommand {
    pub fn send_direct_text(
        command_id: impl Into<String>,
        recipient_identity: [u8; 32],
        text: impl Into<String>,
        reply_snippet: impl Into<String>,
        sender_timestamp_ms: i64,
    ) -> Result<Self, Error> {
        let command_id = command_id.into();
        Self::send_direct_application(
            command_id.clone(),
            recipient_identity,
            proto::DirectApplication {
                application_id: command_id,
                body: Some(proto::direct_application::Body::Message(
                    proto::DirectMessage {
                        text: text.into(),
                        reply_snippet: reply_snippet.into(),
                        sender_timestamp_ms,
                    },
                )),
            },
            Vec::new(),
        )
    }

    pub fn send_direct_acknowledgement(
        command_id: impl Into<String>,
        recipient_identity: [u8; 32],
        message_id: impl Into<String>,
    ) -> Result<Self, Error> {
        let command_id = command_id.into();
        Self::send_direct_application(
            command_id.clone(),
            recipient_identity,
            proto::DirectApplication {
                application_id: command_id,
                body: Some(proto::direct_application::Body::Acknowledgement(
                    proto::DirectAcknowledgement {
                        message_id: message_id.into(),
                    },
                )),
            },
            Vec::new(),
        )
    }

    pub fn send_direct_contact_acceptance(
        command_id: impl Into<String>,
        recipient_identity: [u8; 32],
    ) -> Result<Self, Error> {
        let command_id = command_id.into();
        Self::send_direct_application(
            command_id.clone(),
            recipient_identity,
            proto::DirectApplication {
                application_id: command_id,
                body: Some(proto::direct_application::Body::ContactAcceptance(
                    proto::DirectContactAcceptance {},
                )),
            },
            Vec::new(),
        )
    }

    pub fn send_direct_message_request(
        command_id: impl Into<String>,
        recipient_identity: [u8; 32],
        text: impl Into<String>,
        sender_timestamp_ms: i64,
        sender_contact_card: Vec<u8>,
    ) -> Result<Self, Error> {
        let command_id = command_id.into();
        Self::send_direct_application(
            command_id.clone(),
            recipient_identity,
            proto::DirectApplication {
                application_id: command_id,
                body: Some(proto::direct_application::Body::Message(
                    proto::DirectMessage {
                        text: text.into(),
                        reply_snippet: String::new(),
                        sender_timestamp_ms,
                    },
                )),
            },
            sender_contact_card,
        )
    }

    fn send_direct_application(
        command_id: String,
        recipient_identity: [u8; 32],
        application: proto::DirectApplication,
        sender_contact_card: Vec<u8>,
    ) -> Result<Self, Error> {
        let inner = proto::ClientCommand {
            version: PROTOCOL_VERSION,
            command_id,
            body: Some(proto::client_command::Body::SendDirectApplication(
                proto::SendDirectApplication {
                    recipient_identity: recipient_identity.to_vec(),
                    application: Some(application),
                    local_only: false,
                    sender_contact_card,
                },
            )),
        };
        wire::validate_client_command(&inner)?;
        Ok(Self { inner })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            inner: wire::decode_client_command(bytes)?,
        })
    }

    pub fn create_group(
        command_id: impl Into<String>,
        name: impl Into<String>,
        member_identities: Vec<[u8; 32]>,
        relay_url: impl Into<String>,
        coordinator_public_key: [u8; 32],
        mesh_enabled: bool,
    ) -> Result<Self, Error> {
        let inner = proto::ClientCommand {
            version: PROTOCOL_VERSION,
            command_id: command_id.into(),
            body: Some(proto::client_command::Body::CreateGroup(
                proto::CreateGroup {
                    name: name.into(),
                    member_identities: member_identities
                        .into_iter()
                        .map(|identity| identity.to_vec())
                        .collect(),
                    relay_url: relay_url.into(),
                    mesh_enabled,
                    coordinator_public_key: coordinator_public_key.to_vec(),
                },
            )),
        };
        wire::validate_client_command(&inner)?;
        Ok(Self { inner })
    }

    pub fn encode(&self) -> Vec<u8> {
        self.inner.encode_to_vec()
    }

    /// Durably creates the core-owned Olm account when absent. Its public
    /// signed prekey becomes available in [`crate::ClientSnapshot`] only after
    /// this command commits successfully.
    pub fn ensure_pairwise_account(command_id: impl Into<String>) -> Result<Self, Error> {
        let inner = proto::ClientCommand {
            version: PROTOCOL_VERSION,
            command_id: command_id.into(),
            body: Some(proto::client_command::Body::EnsurePairwiseAccount(
                proto::EnsurePairwiseAccount {},
            )),
        };
        wire::validate_client_command(&inner)?;
        Ok(Self { inner })
    }

    pub fn migrate_legacy_pairwise_state(
        command_id: impl Into<String>,
        account_state: Vec<u8>,
        fallback_key: [u8; 32],
        sessions: Vec<([u8; 32], Vec<u8>)>,
    ) -> Result<Self, Error> {
        let inner = proto::ClientCommand {
            version: PROTOCOL_VERSION,
            command_id: command_id.into(),
            body: Some(proto::client_command::Body::MigrateLegacyPairwiseState(
                proto::MigrateLegacyPairwiseState {
                    format_version: crate::wire::LEGACY_PAIRWISE_MIGRATION_VERSION,
                    account_state,
                    fallback_key: fallback_key.to_vec(),
                    sessions: sessions
                        .into_iter()
                        .map(|(remote_identity, state)| proto::LegacyPairwiseSession {
                            remote_identity: remote_identity.to_vec(),
                            state,
                        })
                        .collect(),
                },
            )),
        };
        wire::validate_client_command(&inner)?;
        Ok(Self { inner })
    }

    pub fn register_pairwise_contact(
        command_id: impl Into<String>,
        prekey_bundle: Vec<u8>,
        relay_url: impl Into<String>,
    ) -> Result<Self, Error> {
        Self::register_pairwise_contact_with_relationship(
            command_id,
            prekey_bundle,
            relay_url,
            proto::PairwiseRelationship::Contact,
        )
    }

    pub fn register_pairwise_contact_with_relationship(
        command_id: impl Into<String>,
        prekey_bundle: Vec<u8>,
        relay_url: impl Into<String>,
        relationship: proto::PairwiseRelationship,
    ) -> Result<Self, Error> {
        let inner = proto::ClientCommand {
            version: PROTOCOL_VERSION,
            command_id: command_id.into(),
            body: Some(proto::client_command::Body::RegisterPairwiseContact(
                proto::RegisterPairwiseContact {
                    prekey_bundle,
                    relay_url: relay_url.into(),
                    relationship: relationship as i32,
                },
            )),
        };
        wire::validate_client_command(&inner)?;
        Ok(Self { inner })
    }

    pub fn set_pairwise_relationship(
        command_id: impl Into<String>,
        identity: [u8; 32],
        relationship: proto::PairwiseRelationship,
    ) -> Result<Self, Error> {
        let inner = proto::ClientCommand {
            version: PROTOCOL_VERSION,
            command_id: command_id.into(),
            body: Some(proto::client_command::Body::SetPairwiseRelationship(
                proto::SetPairwiseRelationship {
                    identity: identity.to_vec(),
                    relationship: relationship as i32,
                },
            )),
        };
        wire::validate_client_command(&inner)?;
        Ok(Self { inner })
    }

    pub fn remove_pairwise_contact(
        command_id: impl Into<String>,
        identity: [u8; 32],
    ) -> Result<Self, Error> {
        let inner = proto::ClientCommand {
            version: PROTOCOL_VERSION,
            command_id: command_id.into(),
            body: Some(proto::client_command::Body::RemovePairwiseContact(
                proto::RemovePairwiseContact {
                    identity: identity.to_vec(),
                },
            )),
        };
        wire::validate_client_command(&inner)?;
        Ok(Self { inner })
    }

    pub fn send_pairwise_control(
        command_id: impl Into<String>,
        recipient_identity: [u8; 32],
        content_kind: proto::OutboundKind,
        payload: Vec<u8>,
    ) -> Result<Self, Error> {
        let inner = proto::ClientCommand {
            version: PROTOCOL_VERSION,
            command_id: command_id.into(),
            body: Some(proto::client_command::Body::SendPairwiseControl(
                proto::SendPairwiseControl {
                    recipient_identity: recipient_identity.to_vec(),
                    content_kind: content_kind as i32,
                    payload,
                },
            )),
        };
        wire::validate_client_command(&inner)?;
        Ok(Self { inner })
    }

    pub fn acknowledge_effects(
        command_id: impl Into<String>,
        outbound_item_ids: Vec<String>,
        event_ids: Vec<String>,
    ) -> Result<Self, Error> {
        let inner = proto::ClientCommand {
            version: PROTOCOL_VERSION,
            command_id: command_id.into(),
            body: Some(proto::client_command::Body::AcknowledgeEffects(
                proto::AcknowledgeEffects {
                    outbound_item_ids,
                    event_ids,
                },
            )),
        };
        wire::validate_client_command(&inner)?;
        Ok(Self { inner })
    }

    /// Sends queued delivery receipts for `group_id`, or for every group.
    pub fn flush_group_acknowledgements(
        command_id: impl Into<String>,
        group_id: Option<GroupId>,
    ) -> Result<Self, Error> {
        let inner = proto::ClientCommand {
            version: PROTOCOL_VERSION,
            command_id: command_id.into(),
            body: Some(proto::client_command::Body::FlushGroupAcknowledgements(
                proto::FlushGroupAcknowledgements {
                    group_id: group_id.map_or_else(Vec::new, |id| id.as_bytes().to_vec()),
                },
            )),
        };
        wire::validate_client_command(&inner)?;
        Ok(Self { inner })
    }

    pub fn confirm_group_relay_authorization(
        command_id: impl Into<String>,
        group_id: GroupId,
        capability_id: [u8; 32],
    ) -> Result<Self, Error> {
        let inner = proto::ClientCommand {
            version: PROTOCOL_VERSION,
            command_id: command_id.into(),
            body: Some(proto::client_command::Body::ConfirmGroupRelayAuthorization(
                proto::ConfirmGroupRelayAuthorization {
                    group_id: group_id.as_bytes().to_vec(),
                    capability_id: capability_id.to_vec(),
                },
            )),
        };
        wire::validate_client_command(&inner)?;
        Ok(Self { inner })
    }

}
