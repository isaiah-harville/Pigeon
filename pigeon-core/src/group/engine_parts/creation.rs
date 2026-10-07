#[derive(Clone, Debug)]
pub struct GroupEngine {
    group_id: GroupId,
    policy: PigeonGroupPolicy,
    epoch: u64,
    pending: Option<PendingMutation>,
}

pub struct GroupCreationConfig {
    pub group_id: GroupId,
    pub name: String,
    pub relay_url: String,
    pub coordinator: CoordinatorBinding,
    pub mesh_enabled: bool,
}

impl GroupEngine {
    pub(crate) fn restore(
        storage: &TransactionalOpenMlsStorage,
        policy: PigeonGroupPolicy,
        expected_epoch: u64,
    ) -> Result<Self, Error> {
        let group = load_group(storage.provider(), policy.group_id())?;
        verify_group_policy(&group, &policy)?;
        if group.epoch().as_u64() != expected_epoch {
            return Err(Error::InvalidSignature);
        }
        Ok(Self {
            group_id: policy.group_id(),
            policy,
            epoch: expected_epoch,
            pending: None,
        })
    }

    pub(crate) fn restore_pending(
        storage: &TransactionalOpenMlsStorage,
        policy: PigeonGroupPolicy,
        expected_epoch: u64,
        commit: Vec<u8>,
        next_policy: PigeonGroupPolicy,
        event: PolicyEvent,
    ) -> Result<Self, Error> {
        policy.relay_capability_delta(&next_policy, &event)?;
        let mut engine = Self::restore(storage, policy, expected_epoch)?;
        engine.pending = Some(PendingMutation {
            commit,
            policy: next_policy,
            event,
            welcome: None,
        });
        Ok(engine)
    }

    pub(crate) fn restore_recovery_pending(
        storage: &TransactionalOpenMlsStorage,
        policy: PigeonGroupPolicy,
        expected_epoch: u64,
        commit: Vec<u8>,
        next_policy: PigeonGroupPolicy,
        event: PolicyEvent,
        certificate: &RecoveryCertificate,
    ) -> Result<Self, Error> {
        let expected = policy.recover(&next_policy, event.actor, certificate)?;
        if expected != event {
            return Err(Error::InvalidSignature);
        }
        let mut engine = Self::restore(storage, policy, expected_epoch)?;
        engine.pending = Some(PendingMutation {
            commit,
            policy: next_policy,
            event,
            welcome: None,
        });
        Ok(engine)
    }

    pub fn encrypt_application<I: SecureIdentity>(
        &mut self,
        identity: &I,
        storage: &mut TransactionalOpenMlsStorage,
        application: GroupApplication,
    ) -> Result<GroupCiphertext, Error> {
        let sender = identity.ensure_public_key(crate::IdentityPurpose::Root)?;
        if !self.policy.members().contains(&sender) || self.policy.dissolved() {
            return Err(Error::InvalidSignature);
        }
        let mut message_id = [0_u8; 16];
        getrandom::getrandom(&mut message_id).map_err(|_| Error::Entropy)?;
        let message_id = GroupMessageId::from_bytes(message_id);
        let plaintext = super::message::encode_content(
            self.group_id,
            self.epoch,
            sender,
            message_id,
            application,
        )?;
        let provider = storage.provider();
        let signer = PlatformMlsSigner(identity);
        let mut group = load_group(provider, self.group_id)?;
        let credential = group.credential().map_err(|_| Error::InvalidKey)?;
        if binding_from_credential(credential)?.root_public_key() != sender {
            return Err(Error::InvalidSignature);
        }
        let ciphertext = group
            .create_message(provider, &signer, &plaintext)
            .map_err(|_| Error::Mls("encrypt group application"))?
            .tls_serialize_detached()
            .map_err(|_| Error::Serialization)?;
        Ok(GroupCiphertext::new(
            self.group_id,
            self.epoch,
            message_id,
            ciphertext,
        ))
    }

    pub fn decrypt_application(
        &mut self,
        storage: &mut TransactionalOpenMlsStorage,
        ciphertext: &GroupCiphertext,
    ) -> Result<AuthenticatedGroupMessage, Error> {
        if ciphertext.group_id() != self.group_id
            || ciphertext.epoch() > self.epoch
            || self.epoch.saturating_sub(ciphertext.epoch()) > MAX_FUTURE_EPOCHS as u64
        {
            return Err(Error::InvalidSignature);
        }
        if ciphertext.ciphertext().len() > MAX_MLS_OBJECT_BYTES {
            return Err(Error::ResourceLimit("MLS application bytes"));
        }
        let provider = storage.provider();
        let mut group = load_group(provider, self.group_id)?;
        let message = MlsMessageIn::tls_deserialize_exact(ciphertext.ciphertext())
            .map_err(|_| Error::Serialization)?;
        let protocol_message = message
            .try_into_protocol_message()
            .map_err(|_| Error::Serialization)?;
        let processed = group
            .process_message(provider, protocol_message)
            .map_err(|_| Error::Mls("decrypt group application"))?;
        let sender = binding_from_credential(processed.credential())?.root_public_key();
        let ProcessedMessageContent::ApplicationMessage(application) = processed.into_content()
        else {
            return Err(Error::Mls("group input was not an application message"));
        };
        super::message::decode_content(&application.into_bytes(), ciphertext, sender)
    }

    pub fn create<I: SecureIdentity>(
        identity: &I,
        storage: &mut TransactionalOpenMlsStorage,
        config: GroupCreationConfig,
        materials: Vec<GroupJoinMaterial>,
    ) -> Result<(Self, Vec<u8>), Error> {
        let (engine, _, welcome) = Self::create_configured(identity, storage, config, materials)?;
        Ok((engine, welcome))
    }

    pub(crate) fn create_configured<I: SecureIdentity>(
        identity: &I,
        storage: &mut TransactionalOpenMlsStorage,
        config: GroupCreationConfig,
        materials: Vec<GroupJoinMaterial>,
    ) -> Result<(Self, Vec<u8>, Vec<u8>), Error> {
        let owner = identity.ensure_public_key(crate::IdentityPurpose::Root)?;
        let mut member_keys = Vec::with_capacity(materials.len() + 1);
        member_keys.push(GroupMemberKeys::issue(identity, owner, config.group_id)?);
        let mut key_packages = Vec::with_capacity(materials.len());
        for material in materials {
            material.verify_for_requester(
                owner,
                owner,
                config.group_id,
                config.coordinator.coordination_id,
            )?;
            member_keys.push(material.member_keys());
            key_packages.push(material.key_package().validated_key_package()?);
        }

        let policy = PigeonGroupPolicy::new_with_mesh(
            config.group_id,
            owner,
            member_keys,
            config.name,
            config.relay_url,
            config.coordinator,
            config.mesh_enabled,
        )?;
        let binding = MlsIdentityBinding::create(identity)?;
        let signer = PlatformMlsSigner(identity);
        let provider = storage.provider();
        let mut group = MlsGroup::builder()
            .with_group_id(openmls::prelude::GroupId::from_slice(
                config.group_id.as_bytes(),
            ))
            .ciphersuite(CIPHERSUITE)
            .with_wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .with_capabilities(policy_capabilities())
            .with_group_context_extensions(policy_extensions(&policy)?)
            .max_past_epochs(MAX_PAST_EPOCHS)
            .build(provider, &signer, binding.credential_with_key())
            .map_err(|_| Error::Mls("create group"))?;

        if key_packages.is_empty() {
            verify_group_policy(&group, &policy)?;
            return Ok((
                Self {
                    group_id: config.group_id,
                    policy,
                    epoch: group.epoch().as_u64(),
                    pending: None,
                },
                Vec::new(),
                Vec::new(),
            ));
        }

        let bundle = group
            .commit_builder()
            .propose_adds(key_packages)
            .load_psks(provider.storage())
            .map_err(|_| Error::Mls("load pre-shared keys"))?
            .build(provider.rand(), provider.crypto(), &signer, |_| true)
            .map_err(|_| Error::Mls("build initial member commit"))?
            .stage_commit(provider)
            .map_err(|_| Error::Mls("stage initial member commit"))?;
        let welcome = bundle
            .to_welcome_msg()
            .ok_or(Error::Mls("create initial Welcome"))?
            .tls_serialize_detached()
            .map_err(|_| Error::Serialization)?;
        let initial_commit = bundle
            .commit()
            .tls_serialize_detached()
            .map_err(|_| Error::Serialization)?;
        group
            .merge_pending_commit(provider)
            .map_err(|_| Error::Mls("merge initial member commit"))?;
        verify_group_policy(&group, &policy)?;

        Ok((
            Self {
                group_id: config.group_id,
                policy,
                epoch: group.epoch().as_u64(),
                pending: None,
            },
            initial_commit,
            welcome,
        ))
    }

    pub fn join_welcome<I: SecureIdentity>(
        identity: &I,
        storage: &mut TransactionalOpenMlsStorage,
        welcome: &[u8],
    ) -> Result<Self, Error> {
        if welcome.len() > MAX_MLS_OBJECT_BYTES {
            return Err(Error::ResourceLimit("MLS Welcome bytes"));
        }
        let message =
            MlsMessageIn::tls_deserialize_exact(welcome).map_err(|_| Error::Serialization)?;
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            return Err(Error::Serialization);
        };
        let join_config = MlsGroupJoinConfig::builder()
            .max_past_epochs(MAX_PAST_EPOCHS)
            .build();
        let staged =
            StagedWelcome::new_from_welcome(storage.provider(), &join_config, welcome, None)
                .map_err(|_| Error::Mls("stage Welcome"))?;
        let policy = policy_from_extensions(staged.group_context().extensions())?;
        verify_staged_roster(&staged, &policy)?;
        let local_root = identity.ensure_public_key(crate::IdentityPurpose::Root)?;
        let own_binding = binding_from_credential(
            staged
                .own_leaf_node()
                .ok_or(Error::Mls("missing own MLS leaf"))?
                .credential(),
        )?;
        if own_binding.root_public_key() != local_root {
            return Err(Error::InvalidSignature);
        }
        let mls_group_id = staged.group_context().group_id().as_slice();
        if mls_group_id != policy.group_id().as_bytes() {
            return Err(Error::InvalidSignature);
        }
        let group = staged
            .into_group(storage.provider())
            .map_err(|_| Error::Mls("join Welcome"))?;
        Ok(Self {
            group_id: policy.group_id(),
            policy,
            epoch: group.epoch().as_u64(),
            pending: None,
        })
    }

    pub fn stage_candidate<I: SecureIdentity>(
        &mut self,
        identity: &I,
        storage: &mut TransactionalOpenMlsStorage,
        action: GroupAction,
        join_material: Option<GroupJoinMaterial>,
    ) -> Result<PendingMutation, Error> {
        if self.pending.is_some() {
            return Err(Error::Mls("candidate already pending"));
        }
        if matches!(action, GroupAction::Leave { .. }) {
            return Err(Error::Mls("leave requires a signed self-remove proposal"));
        }
        let local_root = identity.ensure_public_key(crate::IdentityPurpose::Root)?;
        if action_actor(&action) != local_root {
            return Err(Error::InvalidSignature);
        }
        let (candidate, event) = self.policy.apply(&action)?;
        let signer = PlatformMlsSigner(identity);
        let provider = storage.provider();
        let mut group = load_group(provider, self.group_id)?;
        let (add, remove) = match &action {
            GroupAction::Add { actor, member_keys } => {
                let material = join_material.ok_or(Error::InvalidKey)?;
                material.verify_for_requester(
                    *actor,
                    self.policy.owner(),
                    self.group_id,
                    self.policy.coordination_id(),
                )?;
                if material.member_keys() != **member_keys {
                    return Err(Error::InvalidSignature);
                }
                (Some(material.key_package().validated_key_package()?), None)
            }
            GroupAction::Remove { subject, .. } | GroupAction::Leave { actor: subject, .. } => {
                if join_material.is_some() {
                    return Err(Error::InvalidKey);
                }
                (None, Some(member_index(&group, *subject)?))
            }
            _ => {
                if join_material.is_some() {
                    return Err(Error::InvalidKey);
                }
                (None, None)
            }
        };
        let mut builder = group
            .commit_builder()
            .propose_group_context_extensions(policy_extensions(&candidate)?)
            .map_err(|_| Error::Mls("propose policy extension"))?;
        if let Some(package) = add {
            builder = builder.propose_adds([package]);
        }
        if let Some(index) = remove {
            builder = builder.propose_removals([index]);
        }
        let bundle = builder
            .load_psks(provider.storage())
            .map_err(|_| Error::Mls("load pre-shared keys"))?
            .build(provider.rand(), provider.crypto(), &signer, |_| true)
            .map_err(|_| Error::Mls("build policy commit"))?
            .stage_commit(provider)
            .map_err(|_| Error::Mls("stage policy commit"))?;
        let commit = bundle
            .commit()
            .tls_serialize_detached()
            .map_err(|_| Error::Serialization)?;
        let welcome = bundle
            .to_welcome_msg()
            .map(|message| message.tls_serialize_detached())
            .transpose()
            .map_err(|_| Error::Serialization)?;
        let pending = PendingMutation {
            commit,
            policy: candidate,
            event,
            welcome,
        };
        self.pending = Some(pending.clone());
        Ok(pending)
    }

}
