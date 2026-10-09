impl ClientCommand {
    pub fn recover_group(
        command_id: impl Into<String>,
        recovery_certificate: Vec<u8>,
    ) -> Result<Self, Error> {
        let inner = proto::ClientCommand {
            version: PROTOCOL_VERSION,
            command_id: command_id.into(),
            body: Some(proto::client_command::Body::RecoverGroup(
                proto::RecoverGroup {
                    recovery_certificate,
                },
            )),
        };
        wire::validate_client_command(&inner)?;
        Ok(Self { inner })
    }

    pub fn begin_group_recovery(
        command_id: impl Into<String>,
        group_id: GroupId,
        replacement_relay_url: impl Into<String>,
        replacement_coordination_id: [u8; 32],
        replacement_coordinator_public_key: [u8; 32],
    ) -> Result<Self, Error> {
        let inner = proto::ClientCommand {
            version: PROTOCOL_VERSION,
            command_id: command_id.into(),
            body: Some(proto::client_command::Body::BeginGroupRecovery(
                proto::BeginGroupRecovery {
                    group_id: group_id.as_bytes().to_vec(),
                    replacement_relay_url: replacement_relay_url.into(),
                    replacement_coordination_id: replacement_coordination_id.to_vec(),
                    replacement_coordinator_public_key: replacement_coordinator_public_key.to_vec(),
                },
            )),
        };
        wire::validate_client_command(&inner)?;
        Ok(Self { inner })
    }

    pub fn apply_group_join_request(
        command_id: impl Into<String>,
        request_id: impl Into<String>,
        request: Vec<u8>,
    ) -> Result<Self, Error> {
        Self::apply_inbound(
            command_id,
            request_id,
            proto::OutboundKind::GroupJoinRequest,
            request,
        )
    }

    pub fn apply_group_join_material(
        command_id: impl Into<String>,
        request_id: impl Into<String>,
        material: Vec<u8>,
    ) -> Result<Self, Error> {
        Self::apply_inbound(
            command_id,
            request_id,
            proto::OutboundKind::GroupJoinMaterial,
            material,
        )
    }

    pub fn apply_pairwise_control(
        command_id: impl Into<String>,
        envelope: Vec<u8>,
    ) -> Result<Self, Error> {
        let command_id = command_id.into();
        Self::apply_inbound(
            command_id.clone(),
            command_id,
            proto::OutboundKind::Pairwise,
            envelope,
        )
    }

    fn apply_inbound(
        command_id: impl Into<String>,
        request_id: impl Into<String>,
        kind: proto::OutboundKind,
        payload: Vec<u8>,
    ) -> Result<Self, Error> {
        let inner = proto::ClientCommand {
            version: PROTOCOL_VERSION,
            command_id: command_id.into(),
            body: Some(proto::client_command::Body::ApplyInbound(
                proto::ApplyInbound {
                    kind: kind as i32,
                    payload,
                    request_id: request_id.into(),
                    now_ms: 0,
                },
            )),
        };
        wire::validate_client_command(&inner)?;
        Ok(Self { inner })
    }

    pub fn send_group_text(
        command_id: impl Into<String>,
        group_id: GroupId,
        body: Vec<u8>,
        reply_to_message_id: impl Into<String>,
    ) -> Result<Self, Error> {
        Self::send_group_text_at(command_id, group_id, body, reply_to_message_id, 0)
    }

    pub fn rename_group(
        command_id: impl Into<String>,
        group_id: GroupId,
        name: impl Into<String>,
    ) -> Result<Self, Error> {
        Self::change_group_policy(
            command_id,
            group_id,
            proto::GroupPolicyChangeKind::NameChanged,
            Vec::new(),
            name.into(),
            false,
        )
    }

    pub fn set_group_mesh(
        command_id: impl Into<String>,
        group_id: GroupId,
        enabled: bool,
    ) -> Result<Self, Error> {
        Self::change_group_policy(
            command_id,
            group_id,
            proto::GroupPolicyChangeKind::MeshChanged,
            Vec::new(),
            String::new(),
            enabled,
        )
    }

    pub fn promote_group_admin(
        command_id: impl Into<String>,
        group_id: GroupId,
        subject: [u8; 32],
    ) -> Result<Self, Error> {
        Self::member_policy_change(
            command_id,
            group_id,
            proto::GroupPolicyChangeKind::AdminPromoted,
            subject,
        )
    }

    pub fn demote_group_admin(
        command_id: impl Into<String>,
        group_id: GroupId,
        subject: [u8; 32],
    ) -> Result<Self, Error> {
        Self::member_policy_change(
            command_id,
            group_id,
            proto::GroupPolicyChangeKind::AdminDemoted,
            subject,
        )
    }

    pub fn remove_group_member(
        command_id: impl Into<String>,
        group_id: GroupId,
        subject: [u8; 32],
    ) -> Result<Self, Error> {
        Self::member_policy_change(
            command_id,
            group_id,
            proto::GroupPolicyChangeKind::MemberRemoved,
            subject,
        )
    }

    pub fn add_group_member(
        command_id: impl Into<String>,
        group_id: GroupId,
        subject: [u8; 32],
    ) -> Result<Self, Error> {
        Self::member_policy_change(
            command_id,
            group_id,
            proto::GroupPolicyChangeKind::MemberAdded,
            subject,
        )
    }

    pub fn dissolve_group(command_id: impl Into<String>, group_id: GroupId) -> Result<Self, Error> {
        Self::change_group_policy(
            command_id,
            group_id,
            proto::GroupPolicyChangeKind::Dissolved,
            Vec::new(),
            String::new(),
            false,
        )
    }

    pub fn leave_group(command_id: impl Into<String>, group_id: GroupId) -> Result<Self, Error> {
        Self::change_group_policy(
            command_id,
            group_id,
            proto::GroupPolicyChangeKind::MemberLeft,
            Vec::new(),
            String::new(),
            false,
        )
    }

    fn member_policy_change(
        command_id: impl Into<String>,
        group_id: GroupId,
        kind: proto::GroupPolicyChangeKind,
        subject: [u8; 32],
    ) -> Result<Self, Error> {
        Self::change_group_policy(
            command_id,
            group_id,
            kind,
            subject.to_vec(),
            String::new(),
            false,
        )
    }

    fn change_group_policy(
        command_id: impl Into<String>,
        group_id: GroupId,
        kind: proto::GroupPolicyChangeKind,
        subject_identity: Vec<u8>,
        string_value: String,
        bool_value: bool,
    ) -> Result<Self, Error> {
        let inner = proto::ClientCommand {
            version: PROTOCOL_VERSION,
            command_id: command_id.into(),
            body: Some(proto::client_command::Body::ChangeGroupPolicy(
                proto::ChangeGroupPolicy {
                    group_id: group_id.as_bytes().to_vec(),
                    kind: kind as i32,
                    subject_identity,
                    string_value,
                    bool_value,
                },
            )),
        };
        wire::validate_client_command(&inner)?;
        Ok(Self { inner })
    }

    pub fn send_group_text_at(
        command_id: impl Into<String>,
        group_id: GroupId,
        body: Vec<u8>,
        reply_to_message_id: impl Into<String>,
        sender_timestamp_ms: i64,
    ) -> Result<Self, Error> {
        let command_id = command_id.into();
        let inner = proto::ClientCommand {
            version: PROTOCOL_VERSION,
            command_id: command_id.clone(),
            body: Some(proto::client_command::Body::SendGroupMessage(
                proto::SendGroupMessage {
                    group_id: group_id.as_bytes().to_vec(),
                    message_id: command_id,
                    body,
                    reply_to_message_id: reply_to_message_id.into(),
                    sender_timestamp_ms,
                },
            )),
        };
        wire::validate_client_command(&inner)?;
        Ok(Self { inner })
    }

    pub fn apply_group_welcome(
        command_id: impl Into<String>,
        welcome: Vec<u8>,
    ) -> Result<Self, Error> {
        Self::apply_group_input(command_id, proto::OutboundKind::GroupWelcome, welcome)
    }

    pub fn apply_group_message(
        command_id: impl Into<String>,
        ciphertext: Vec<u8>,
    ) -> Result<Self, Error> {
        Self::apply_group_input(command_id, proto::OutboundKind::GroupMessage, ciphertext)
    }

    pub fn apply_group_coordinator_candidate(
        command_id: impl Into<String>,
        candidate: Vec<u8>,
    ) -> Result<Self, Error> {
        Self::apply_group_input(command_id, proto::OutboundKind::GroupCoordinator, candidate)
    }

    pub fn apply_group_leave_proposal(
        command_id: impl Into<String>,
        proposal: Vec<u8>,
    ) -> Result<Self, Error> {
        Self::apply_group_input(
            command_id,
            proto::OutboundKind::GroupLeaveProposal,
            proposal,
        )
    }

    fn apply_group_input(
        command_id: impl Into<String>,
        kind: proto::OutboundKind,
        payload: Vec<u8>,
    ) -> Result<Self, Error> {
        let command_id = command_id.into();
        let inner = proto::ClientCommand {
            version: PROTOCOL_VERSION,
            command_id: command_id.clone(),
            body: Some(proto::client_command::Body::ApplyInbound(
                proto::ApplyInbound {
                    kind: kind as i32,
                    payload,
                    request_id: command_id,
                    now_ms: 0,
                },
            )),
        };
        wire::validate_client_command(&inner)?;
        Ok(Self { inner })
    }

}

impl ClientCommand {
    pub fn command_id(&self) -> &str {
        &self.inner.command_id
    }
}
