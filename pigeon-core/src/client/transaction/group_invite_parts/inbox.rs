impl<S: StateStore, I: SecureIdentity> PigeonClient<S, I> {
    pub(super) fn stage_refresh_group_invites(
        &self,
        now_ms: i64,
        candidate: &mut proto::ClientCheckpoint,
    ) -> Result<bool, Error> {
        if now_ms <= 0 {
            return Err(Error::MalformedBundle);
        }
        let mut changed = false;
        let mut index = 0;
        while index < candidate.group_invites.len() {
            let ticket = GroupInviteTicket::decode(&candidate.group_invites[index].ticket)?;
            if ticket.expires_at_ms() <= now_ms {
                candidate.group_invites.remove(index);
                changed = true;
            } else {
                index += 1;
            }
        }
        let prior_join_count = candidate.group_invite_joins.len();
        candidate.group_invite_joins.retain(|join| {
            matches!(
                proto::GroupInviteProgress::try_from(join.progress),
                Ok(proto::GroupInviteProgress::Pending | proto::GroupInviteProgress::Approved)
            )
        });
        changed |= candidate.group_invite_joins.len() != prior_join_count;
        let mut expired_destinations = Vec::new();
        for join in &mut candidate.group_invite_joins {
            let ticket = GroupInviteTicket::decode(&join.ticket)?;
            if now_ms >= ticket.expires_at_ms()
                && matches!(
                    proto::GroupInviteProgress::try_from(join.progress),
                    Ok(proto::GroupInviteProgress::Pending | proto::GroupInviteProgress::Approved)
                )
            {
                join.progress = proto::GroupInviteProgress::Expired as i32;
                if join.reply_address.is_empty() {
                    let inbox =
                        GroupInviteReplyInbox::import_state(&join.reply_inbox_state, &ticket)?;
                    join.reply_address = inbox.address().to_vec();
                }
                join.reply_inbox_state.clear();
                expired_destinations.push(ticket.inbox_address().to_vec());
                changed = true;
            }
        }
        if !expired_destinations.is_empty() {
            candidate.pending_outbound.retain(|item| {
                let invite_delivery = item.kind == proto::OutboundKind::GroupInviteRequest as i32
                    || item.kind == proto::OutboundKind::GroupInviteMaterial as i32;
                !invite_delivery || !expired_destinations.contains(&item.destination)
            });
        }
        Ok(changed)
    }

    pub(super) fn stage_create_group_invite(
        &self,
        value: &proto::CreateGroupInvite,
        candidate: &mut proto::ClientCheckpoint,
    ) -> Result<(), Error> {
        if value.now_ms <= 0 {
            return Err(Error::MalformedBundle);
        }
        if value
            .expires_at_ms
            .checked_sub(value.now_ms)
            .is_none_or(|lifetime| lifetime <= 0 || lifetime > MAX_INVITE_LIFETIME_MS)
        {
            return Err(Error::MalformedBundle);
        }
        let mut invite_index = 0;
        while invite_index < candidate.group_invites.len() {
            let ticket = GroupInviteTicket::decode(&candidate.group_invites[invite_index].ticket)?;
            if ticket.expires_at_ms() <= value.now_ms {
                candidate.group_invites.remove(invite_index);
            } else {
                invite_index += 1;
            }
        }
        if candidate.group_invites.len() >= MAX_ACTIVE_INVITES {
            return Err(Error::ResourceLimit("active group invites"));
        }
        let stored = candidate
            .groups
            .iter()
            .find(|group| group.group_id == value.group_id)
            .ok_or(Error::InvalidKey)?;
        let policy = PigeonGroupPolicy::decode(&stored.policy)?;
        let actor = self.identity.ensure_public_key(IdentityPurpose::Root)?;
        if !policy.is_admin(actor) || policy.dissolved() {
            return Err(Error::InvalidSignature);
        }
        let mode = match proto::GroupInviteMode::try_from(value.mode) {
            Ok(proto::GroupInviteMode::Public) => GroupInviteMode::Public,
            Ok(proto::GroupInviteMode::Private) => GroupInviteMode::Private,
            _ => return Err(Error::MalformedBundle),
        };
        let (ticket, inbox) = GroupInviteInbox::create(
            policy.group_id(),
            policy.coordination_id(),
            policy.coordinator_public_key(),
            policy.relay_url().to_owned(),
            mode,
            value.expires_at_ms,
        )?;
        ticket.validate(value.now_ms)?;
        candidate.group_invites.push(proto::StoredGroupInvite {
            ticket: ticket.encode(),
            inbox_state: inbox.export_state()?,
            requests: Vec::new(),
        });
        Ok(())
    }

    pub(super) fn stage_revoke_group_invite(
        &self,
        value: &proto::RevokeGroupInvite,
        candidate: &mut proto::ClientCheckpoint,
    ) -> Result<(), Error> {
        let index = invite_index(candidate, &value.inbox_address)?;
        // The inbox key is local state: its holder can always stop serving it,
        // including after leaving or losing the group's admin role.
        candidate.group_invites.remove(index);
        Ok(())
    }

    pub(super) fn stage_start_group_invite_join(
        &self,
        command_id: &str,
        value: &proto::StartGroupInviteJoin,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        let ticket = GroupInviteTicket::decode(&value.ticket)?;
        ticket.validate(value.now_ms)?;
        self.stage_refresh_group_invites(value.now_ms, candidate)?;
        // Completed joins no longer need their private reply inbox. Remove them
        // before enforcing the cap so historical attempts cannot block joining.
        candidate.group_invite_joins.retain(|join| {
            matches!(
                proto::GroupInviteProgress::try_from(join.progress),
                Ok(proto::GroupInviteProgress::Pending | proto::GroupInviteProgress::Approved)
            )
        });
        if candidate.group_invite_joins.len() >= MAX_INVITE_JOINS {
            return Err(Error::ResourceLimit("pending group invite joins"));
        }
        if candidate
            .groups
            .iter()
            .any(|group| group.group_id.as_slice() == ticket.group_id().as_bytes())
            || candidate
                .group_invite_joins
                .iter()
                .any(|join| join.ticket == value.ticket)
        {
            return Err(Error::InvalidSignature);
        }
        let mut request_id = [0; 32];
        getrandom::getrandom(&mut request_id).map_err(|_| Error::Entropy)?;
        let reply = GroupInviteReplyInbox::create(&ticket, request_id)?;
        let intent = GroupInviteIntent::create(
            &self.identity,
            &ticket,
            request_id,
            reply.address(),
            reply.curve_identity_key(),
            reply.fallback_prekey(),
        )?;
        let payload = GroupInviteInbox::seal_request(&ticket, &intent, value.now_ms)?;
        candidate
            .group_invite_joins
            .push(proto::StoredGroupInviteJoin {
                ticket: value.ticket.clone(),
                request_id: request_id.to_vec(),
                reply_inbox_state: reply.export_state()?,
                progress: proto::GroupInviteProgress::Pending as i32,
                reply_address: reply.address().to_vec(),
            });
        output.outbound.push(invite_outbound(
            command_id,
            "request",
            proto::OutboundKind::GroupInviteRequest,
            &ticket,
            ticket.inbox_address(),
            payload,
        ));
        Ok(())
    }

    pub(super) fn stage_apply_group_invite_inbox_envelope(
        &self,
        command_id: &str,
        value: &proto::ApplyGroupInviteInboxEnvelope,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        let index = invite_index(candidate, &value.inbox_address)?;
        let ticket = GroupInviteTicket::decode(&candidate.group_invites[index].ticket)?;
        let mut inbox =
            GroupInviteInbox::import_state(&candidate.group_invites[index].inbox_state, &ticket)?;
        // A material envelope and a request envelope use the same encrypted
        // mailbox. Opening on a clone avoids consuming Olm state for a payload
        // that belongs to the other message type.
        let mut probe =
            GroupInviteInbox::import_state(&candidate.group_invites[index].inbox_state, &ticket)?;
        match probe.open_request(&ticket, &value.ciphertext, value.now_ms) {
            Ok(intent) => {
                candidate.group_invites[index].requests.retain(|request| {
                    !matches!(
                        proto::GroupInviteProgress::try_from(request.progress),
                        Ok(proto::GroupInviteProgress::Rejected
                            | proto::GroupInviteProgress::Expired
                            | proto::GroupInviteProgress::Full
                            | proto::GroupInviteProgress::Joined)
                    )
                });
                if candidate.group_invites[index].requests.len() >= MAX_REQUESTS_PER_INVITE {
                    return Err(Error::ResourceLimit("group invite requests"));
                }
                inbox = probe;
                let progress = proto::GroupInviteProgress::Pending;
                candidate.group_invites[index]
                    .requests
                    .push(proto::StoredGroupInviteRequest {
                        intent: intent.encode(),
                        progress: progress as i32,
                    });
                candidate.group_invites[index].inbox_state = inbox.export_state()?;
                if ticket.mode() == GroupInviteMode::Public
                    && !group_has_pending_mutation(candidate, ticket.group_id())
                {
                    self.decide_invite_request(
                        command_id,
                        index,
                        intent.request_id(),
                        true,
                        value.now_ms,
                        candidate,
                        output,
                    )?;
                }
                Ok(())
            }
            Err(_) => {
                let material = inbox.open_material(&ticket, &value.ciphertext, value.now_ms)?;
                let request_index =
                    request_index(&candidate.group_invites[index], material.request_id())?;
                if candidate.group_invites[index].requests[request_index].progress
                    != proto::GroupInviteProgress::Approved as i32
                {
                    return Err(Error::InvalidSignature);
                }
                let intent = GroupInviteIntent::decode(
                    &candidate.group_invites[index].requests[request_index].intent,
                )?;
                if material.material().member_identity() != intent.requester_identity() {
                    return Err(Error::InvalidSignature);
                }
                let actor = self.identity.ensure_public_key(IdentityPurpose::Root)?;
                let policy = group_policy(candidate, ticket.group_id())?;
                material.material().verify_for_requester(
                    actor,
                    policy.owner(),
                    ticket.group_id(),
                    ticket.coordination_id(),
                )?;
                if candidate
                    .pending_group_mutations
                    .iter()
                    .any(|pending| pending.group_id.as_slice() == ticket.group_id().as_bytes())
                    || candidate.pending_group_additions.iter().any(|addition| {
                        addition.group_id.as_slice() == ticket.group_id().as_bytes()
                    })
                {
                    return Err(Error::Mls("group mutation already pending"));
                }
                candidate
                    .pending_group_additions
                    .push(proto::PendingGroupAddition {
                        request_id: format!("{command_id}:addition"),
                        group_id: ticket.group_id().as_bytes().to_vec(),
                        member_identity: intent.requester_identity().to_vec(),
                    });
                let inbound = proto::ApplyInbound::default();
                if !self.stage_apply_group_addition_material(
                    command_id,
                    &inbound,
                    material.material(),
                    candidate,
                    output,
                )? {
                    return Err(Error::InvalidSignature);
                }
                candidate.group_invites[index].requests[request_index].progress =
                    proto::GroupInviteProgress::Joined as i32;
                candidate.group_invites[index].inbox_state = inbox.export_state()?;
                Ok(())
            }
        }
    }

    pub(super) fn stage_decide_group_invite_request(
        &self,
        command_id: &str,
        value: &proto::DecideGroupInviteRequest,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        let index = invite_index(candidate, &value.inbox_address)?;
        let request_id = array(&value.request_id)?;
        self.decide_invite_request(
            command_id,
            index,
            request_id,
            value.approve,
            value.now_ms,
            candidate,
            output,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn decide_invite_request(
        &self,
        command_id: &str,
        index: usize,
        request_id: [u8; 32],
        approve: bool,
        now_ms: i64,
        candidate: &mut proto::ClientCheckpoint,
        output: &mut ClientOutput,
    ) -> Result<(), Error> {
        let ticket = GroupInviteTicket::decode(&candidate.group_invites[index].ticket)?;
        let policy = group_policy(candidate, ticket.group_id())?;
        let actor = self.identity.ensure_public_key(IdentityPurpose::Root)?;
        if !policy.is_admin(actor) || policy.dissolved() {
            return Err(Error::InvalidSignature);
        }
        let request_index = request_index(&candidate.group_invites[index], request_id)?;
        if candidate.group_invites[index].requests[request_index].progress
            != proto::GroupInviteProgress::Pending as i32
        {
            return Err(Error::InvalidSignature);
        }
        let intent = GroupInviteIntent::decode(
            &candidate.group_invites[index].requests[request_index].intent,
        )?;
        intent.verify(&ticket)?;
        let inbox =
            GroupInviteInbox::import_state(&candidate.group_invites[index].inbox_state, &ticket)?;
        if approve && group_has_pending_mutation(candidate, ticket.group_id()) {
            return Err(Error::Mls("group mutation already pending"));
        }
        let stale_ticket = policy.coordination_id() != ticket.coordination_id()
            || policy.coordinator_public_key() != ticket.coordinator_public_key()
            || policy.relay_url() != ticket.relay_url();
        let (status, request) = if stale_ticket {
            (GroupInviteReplyStatus::Expired, None)
        } else if !approve {
            (GroupInviteReplyStatus::Rejected, None)
        } else if policy.members().len() >= MAX_GROUP_MEMBERS
            || policy.members().contains(&intent.requester_identity())
        {
            (GroupInviteReplyStatus::Full, None)
        } else {
            policy.can_invite(actor, intent.requester_identity())?;
            (
                GroupInviteReplyStatus::Approved,
                Some(GroupJoinRequest::create_for_owner(
                    &self.identity,
                    policy.owner(),
                    policy.group_id(),
                    policy.coordination_id(),
                    policy.relay_url(),
                )?),
            )
        };
        let payload = inbox.seal_reply(&ticket, &intent, status, request.as_ref(), now_ms)?;
        let progress = match status {
            GroupInviteReplyStatus::Approved => proto::GroupInviteProgress::Approved,
            GroupInviteReplyStatus::Rejected => proto::GroupInviteProgress::Rejected,
            GroupInviteReplyStatus::Expired => proto::GroupInviteProgress::Expired,
            GroupInviteReplyStatus::Full => proto::GroupInviteProgress::Full,
        };
        candidate.group_invites[index].requests[request_index].progress = progress as i32;
        candidate.group_invites[index].inbox_state = inbox.export_state()?;
        output.outbound.push(invite_outbound(
            command_id,
            "reply",
            proto::OutboundKind::GroupInviteReply,
            &ticket,
            intent.reply_address(),
            payload,
        ));
        Ok(())
    }

}
