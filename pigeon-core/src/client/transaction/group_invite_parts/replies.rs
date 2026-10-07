impl<S: StateStore, I: SecureIdentity> PigeonClient<S, I> {
    pub(super) fn stage_flush_public_group_invites(
        &self,
        command_id: &str,
        now_ms: i64,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        for index in 0..candidate.group_invites.len() {
            let ticket = GroupInviteTicket::decode(&candidate.group_invites[index].ticket)?;
            if ticket.mode() != GroupInviteMode::Public
                || ticket.validate(now_ms).is_err()
                || group_has_pending_mutation(candidate, ticket.group_id())
            {
                continue;
            }
            let policy = group_policy(candidate, ticket.group_id())?;
            let actor = self.identity.ensure_public_key(IdentityPurpose::Root)?;
            if !policy.is_admin(actor) || policy.dissolved() {
                continue;
            }
            let pending = candidate.group_invites[index]
                .requests
                .iter()
                .filter(|request| request.progress == proto::GroupInviteProgress::Pending as i32)
                .map(|request| {
                    GroupInviteIntent::decode(&request.intent).map(|intent| intent.request_id())
                })
                .collect::<Result<Vec<_>, _>>()?;
            for request_id in pending {
                if candidate.pending_outbound.len() + output.outbound.len()
                    >= crate::MAX_PENDING_OUTBOUND_ENTRIES
                {
                    return Ok(());
                }
                self.decide_invite_request(
                    command_id, index, request_id, true, now_ms, candidate, output,
                )?;
            }
        }
        Ok(())
    }

    pub(super) fn stage_apply_group_invite_reply(
        &self,
        command_id: &str,
        value: &proto::ApplyGroupInviteReply,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        let index = candidate
            .group_invite_joins
            .iter()
            .position(|join| {
                let Ok(ticket) = GroupInviteTicket::decode(&join.ticket) else {
                    return false;
                };
                let Ok(inbox) =
                    GroupInviteReplyInbox::import_state(&join.reply_inbox_state, &ticket)
                else {
                    return false;
                };
                inbox.address().as_slice() == value.reply_address
            })
            .ok_or(Error::InvalidKey)?;
        if candidate.group_invite_joins[index].progress
            != proto::GroupInviteProgress::Pending as i32
        {
            return Err(Error::InvalidSignature);
        }
        let ticket = GroupInviteTicket::decode(&candidate.group_invite_joins[index].ticket)?;
        let mut inbox = GroupInviteReplyInbox::import_state(
            &candidate.group_invite_joins[index].reply_inbox_state,
            &ticket,
        )?;
        let reply = inbox.open_reply(&ticket, &value.ciphertext, value.now_ms)?;
        let progress = if value.now_ms >= ticket.expires_at_ms() {
            proto::GroupInviteProgress::Expired
        } else {
            match reply.status() {
                GroupInviteReplyStatus::Approved => proto::GroupInviteProgress::Approved,
                GroupInviteReplyStatus::Rejected => proto::GroupInviteProgress::Rejected,
                GroupInviteReplyStatus::Expired => proto::GroupInviteProgress::Expired,
                GroupInviteReplyStatus::Full => proto::GroupInviteProgress::Full,
            }
        };
        if progress == proto::GroupInviteProgress::Approved {
            let request = reply.join_request().ok_or(Error::MalformedBundle)?;
            let mut mls_storage = if candidate.openmls_checkpoint.is_empty() {
                TransactionalOpenMlsStorage::new()
            } else {
                TransactionalOpenMlsStorage::from_checkpoint(&candidate.openmls_checkpoint)?
            };
            let material = GroupJoinMaterial::issue_for(
                &self.identity,
                request.requester_identity(),
                request.owner_identity(),
                ticket.group_id(),
                ticket.coordination_id(),
                &mut mls_storage,
            )?;
            candidate.openmls_checkpoint = mls_storage.export_checkpoint()?;
            let payload = GroupInviteInbox::seal_material(
                &ticket,
                reply.request_id(),
                &material,
                value.now_ms,
            )?;
            output.outbound.push(invite_outbound(
                command_id,
                "material",
                proto::OutboundKind::GroupInviteMaterial,
                &ticket,
                ticket.inbox_address(),
                payload,
            ));
        }
        candidate.group_invite_joins[index].reply_inbox_state = if matches!(
            progress,
            proto::GroupInviteProgress::Rejected
                | proto::GroupInviteProgress::Expired
                | proto::GroupInviteProgress::Full
        ) {
            Vec::new()
        } else {
            inbox.export_state()?
        };
        candidate.group_invite_joins[index].progress = progress as i32;
        Ok(())
    }

    pub(super) fn group_invite_snapshot(&self) -> Result<Vec<proto::GroupInviteState>, Error> {
        self.state
            .group_invites
            .iter()
            .map(|stored| {
                let ticket = GroupInviteTicket::decode(&stored.ticket)?;
                let requests = stored
                    .requests
                    .iter()
                    .map(|stored_request| {
                        let intent = GroupInviteIntent::decode(&stored_request.intent)?;
                        intent.verify(&ticket)?;
                        Ok(proto::GroupInviteRequestState {
                            request_id: intent.request_id().to_vec(),
                            requester_identity: intent.requester_identity().to_vec(),
                            progress: stored_request.progress,
                        })
                    })
                    .collect::<Result<Vec<_>, Error>>()?;
                Ok(proto::GroupInviteState {
                    ticket: stored.ticket.clone(),
                    requests,
                })
            })
            .collect()
    }

    pub(super) fn group_invite_join_snapshot(
        &self,
    ) -> Result<Vec<proto::GroupInviteJoinState>, Error> {
        self.state
            .group_invite_joins
            .iter()
            .map(|stored| {
                let ticket = GroupInviteTicket::decode(&stored.ticket)?;
                let address = if stored.reply_address.len() == 32 {
                    stored.reply_address.clone()
                } else {
                    GroupInviteReplyInbox::import_state(&stored.reply_inbox_state, &ticket)?
                        .address()
                        .to_vec()
                };
                Ok(proto::GroupInviteJoinState {
                    ticket: stored.ticket.clone(),
                    request_id: stored.request_id.clone(),
                    reply_address: address,
                    progress: stored.progress,
                })
            })
            .collect()
    }

    pub fn sign_group_invite_mailbox_challenge(
        &self,
        address: &[u8],
        nonce: &[u8],
    ) -> Result<[u8; 64], Error> {
        for stored in &self.state.group_invites {
            let ticket = GroupInviteTicket::decode(&stored.ticket)?;
            if ticket.inbox_address().as_slice() == address {
                return GroupInviteInbox::import_state(&stored.inbox_state, &ticket)?
                    .sign_mailbox_challenge(nonce);
            }
        }
        for stored in &self.state.group_invite_joins {
            if stored.reply_inbox_state.is_empty() {
                continue;
            }
            let ticket = GroupInviteTicket::decode(&stored.ticket)?;
            let inbox = GroupInviteReplyInbox::import_state(&stored.reply_inbox_state, &ticket)?;
            if inbox.address().as_slice() == address {
                return inbox.sign_mailbox_challenge(nonce);
            }
        }
        Err(Error::InvalidKey)
    }
}


fn array(bytes: &[u8]) -> Result<[u8; 32], Error> {
    bytes.try_into().map_err(|_| Error::MalformedBundle)
}

fn invite_index(candidate: &proto::ClientCheckpoint, address: &[u8]) -> Result<usize, Error> {
    candidate
        .group_invites
        .iter()
        .position(|stored| {
            GroupInviteTicket::decode(&stored.ticket)
                .is_ok_and(|ticket| ticket.inbox_address().as_slice() == address)
        })
        .ok_or(Error::InvalidKey)
}

fn request_index(stored: &proto::StoredGroupInvite, request_id: [u8; 32]) -> Result<usize, Error> {
    stored
        .requests
        .iter()
        .position(|request| {
            GroupInviteIntent::decode(&request.intent)
                .is_ok_and(|intent| intent.request_id() == request_id)
        })
        .ok_or(Error::InvalidKey)
}

fn group_policy(
    candidate: &proto::ClientCheckpoint,
    group_id: GroupId,
) -> Result<PigeonGroupPolicy, Error> {
    let stored = candidate
        .groups
        .iter()
        .find(|group| group.group_id.as_slice() == group_id.as_bytes())
        .ok_or(Error::InvalidKey)?;
    Ok(PigeonGroupPolicy::decode(&stored.policy)?)
}

fn group_has_pending_mutation(candidate: &proto::ClientCheckpoint, group_id: GroupId) -> bool {
    candidate
        .pending_group_mutations
        .iter()
        .any(|pending| pending.group_id.as_slice() == group_id.as_bytes())
        || candidate
            .pending_group_additions
            .iter()
            .any(|addition| addition.group_id.as_slice() == group_id.as_bytes())
}

fn invite_outbound(
    command_id: &str,
    suffix: &str,
    kind: proto::OutboundKind,
    ticket: &GroupInviteTicket,
    destination: [u8; 32],
    payload: Vec<u8>,
) -> OutboundItem {
    let mut hasher = Sha256::new();
    hasher.update(b"pigeon.group-invite.outbound-id.v1\0");
    hasher.update(command_id.as_bytes());
    hasher.update(suffix.as_bytes());
    hasher.update(&payload);
    let digest = hasher.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    id[6] = (id[6] & 0x0f) | 0x80;
    id[8] = (id[8] & 0x3f) | 0x80;
    let item_id = format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_be_bytes(id[..4].try_into().unwrap()),
        u16::from_be_bytes(id[4..6].try_into().unwrap()),
        u16::from_be_bytes(id[6..8].try_into().unwrap()),
        u16::from_be_bytes(id[8..10].try_into().unwrap()),
        u64::from_be_bytes([0, 0, id[10], id[11], id[12], id[13], id[14], id[15]]),
    );
    OutboundItem {
        inner: proto::OutboundItem {
            item_id,
            kind: kind as i32,
            relay_url: ticket.relay_url().to_owned(),
            destination: destination.to_vec(),
            payload,
            local_only: false,
        },
    }
}
