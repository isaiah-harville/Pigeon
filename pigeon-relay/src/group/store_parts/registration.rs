impl Store {
    pub fn bounded(config: Config) -> Self {
        Self {
            config,
            groups: HashMap::new(),
            total_bytes: 0,
            retired_controllers: HashMap::new(),
            journal: None,
        }
    }

    /// Restores every group from `journal` and writes through all later
    /// mutations. Expiry and cursor garbage collection are re-applied, since the
    /// journal applies them lazily.
    pub fn durable(
        config: Config,
        mut journal: GroupJournal,
        now: u64,
    ) -> Result<Self, DurableError> {
        let cutoff = now.saturating_sub(config.ttl_secs);
        let mut store = Self::bounded(config);
        journal.expire(cutoff)?;
        let records = journal.load(cutoff)?;
        if records.len() > store.config.max_groups {
            return Err(DurableError::Corrupt(
                "group count exceeds configured limit",
            ));
        }
        for record in records {
            validate_record(&record, &store.config, store.total_bytes)?;
            let entries: VecDeque<GroupEntry> = record
                .entries
                .into_iter()
                .map(|entry| GroupEntry {
                    sequence: entry.sequence,
                    ciphertext: entry.ciphertext,
                    timestamp: entry.timestamp,
                })
                .collect();
            store.total_bytes += entries
                .iter()
                .map(|entry| entry.ciphertext.len())
                .sum::<usize>();
            let capabilities = record
                .capabilities
                .into_iter()
                .map(|capability| {
                    (
                        capability.capability_id,
                        CapabilityState {
                            public_key: capability.public_key,
                            can_append: capability.can_append,
                            can_read: capability.can_read,
                            can_control: capability.can_control,
                            cursor: capability.cursor,
                        },
                    )
                })
                .collect();
            store.groups.insert(
                record.coordination_id,
                StoredGroup {
                    capabilities,
                    permanent_controller_public_key: record.permanent_controller_public_key,
                    authorization_generation: record.authorization_generation,
                    entries,
                    next_sequence: record.next_sequence,
                    revoked_at: record.revoked_at,
                    registered_at: record.registered_at,
                    last_activity_at: record.last_activity_at,
                    coordinator_active: record.coordinator_active,
                },
            );
        }
        let freed = store
            .groups
            .values_mut()
            .map(StoredGroup::collect_garbage)
            .sum::<usize>();
        store.total_bytes = store.total_bytes.saturating_sub(freed);
        store.total_bytes = store
            .total_bytes
            .saturating_add(journal.inactive_ciphertext_bytes()?);
        if store.total_bytes > store.config.max_total_bytes {
            return Err(DurableError::Corrupt(
                "group ciphertext bytes exceed configured limit",
            ));
        }
        store.journal = Some(journal);
        store.expire_at(now);
        Ok(store)
    }

    /// Writes a group's authorization state and cursors through to the journal
    /// before the caller releases the store lock.
    fn persist_authorization(&mut self, coordination_id: [u8; GROUP_ID_BYTES]) {
        let Some(journal) = self.journal.as_mut() else {
            return;
        };
        let Some(group) = self.groups.get(&coordination_id) else {
            return;
        };
        let capabilities = group
            .capabilities
            .iter()
            .map(|(capability_id, state)| CapabilityRecord {
                capability_id: *capability_id,
                public_key: state.public_key,
                can_append: state.can_append,
                can_read: state.can_read,
                can_control: state.can_control,
                cursor: state.cursor,
            })
            .collect::<Vec<_>>();
        let authorization = GroupAuthorization {
            permanent_controller_public_key: group.permanent_controller_public_key,
            authorization_generation: group.authorization_generation,
            next_sequence: group.next_sequence,
            revoked_at: group.revoked_at,
            registered_at: group.registered_at,
            last_activity_at: group.last_activity_at,
            coordinator_active: group.coordinator_active,
            capabilities: &capabilities,
            first_live_sequence: group
                .entries
                .front()
                .map_or(group.next_sequence, |entry| entry.sequence),
        };
        if let Err(error) = journal.sync_authorization(&coordination_id, &authorization) {
            fail_stop(error);
        }
    }

    #[cfg(test)]
    pub fn register(
        &mut self,
        registration: GroupRegistration,
    ) -> Result<RegisteredGroup, StoreError> {
        self.register_at(registration, 0)
    }

    pub fn register_at(
        &mut self,
        registration: GroupRegistration,
        now: u64,
    ) -> Result<RegisteredGroup, StoreError> {
        self.expire_at(now);
        if registration.capabilities.is_empty()
            || registration.capabilities.len() > self.config.max_capabilities_per_group
        {
            return Err(StoreError::CapabilityLimit);
        }
        let unique_ids: HashSet<_> = registration
            .capabilities
            .iter()
            .map(|capability| capability.capability_id)
            .collect();
        let unique_keys: HashSet<_> = registration
            .capabilities
            .iter()
            .map(|capability| capability.public_key)
            .collect();
        if unique_ids.len() != registration.capabilities.len()
            || unique_keys.len() != registration.capabilities.len()
            || !registration
                .capabilities
                .iter()
                .any(|capability| capability.can_append)
            || !registration
                .capabilities
                .iter()
                .any(|capability| capability.can_read)
            || !registration
                .capabilities
                .iter()
                .any(|capability| capability.can_control)
            || registration.capabilities.iter().any(|capability| {
                !capability.can_append && !capability.can_read && !capability.can_control
            })
        {
            return Err(StoreError::InvalidRegistration);
        }
        let has_permanent_controller = registration.capabilities.iter().any(|capability| {
            capability.can_control
                && capability.public_key == registration.permanent_controller_public_key
        });
        if !has_permanent_controller {
            return Err(StoreError::InvalidRegistration);
        }
        if let Some(existing) = self.groups.get(&registration.coordination_id) {
            if existing.matches_registration(
                &registration.capabilities,
                registration.permanent_controller_public_key,
                registration.authorization_generation,
            ) {
                return Ok(RegisteredGroup {
                    coordination_id: registration.coordination_id,
                    capabilities: registration.capabilities,
                });
            }
            return Err(StoreError::AlreadyRegistered);
        }
        if self.contains_group(&registration.coordination_id) {
            if let Some(journal) = self.journal.as_ref() {
                let inactive = journal
                    .inactive_group(&registration.coordination_id)
                    .unwrap_or_else(|error| fail_stop(error));
                if inactive.is_some_and(|record| {
                    record.revoked_at.is_none()
                        && record.permanent_controller_public_key
                            == registration.permanent_controller_public_key
                        && record.authorization_generation == registration.authorization_generation
                        && record.capabilities.len() == registration.capabilities.len()
                        && registration.capabilities.iter().all(|candidate| {
                            record.capabilities.iter().any(|saved| {
                                candidate.capability_id == saved.capability_id
                                    && candidate.public_key == saved.public_key
                                    && candidate.can_append == saved.can_append
                                    && candidate.can_read == saved.can_read
                                    && candidate.can_control == saved.can_control
                            })
                        })
                }) {
                    return Ok(RegisteredGroup {
                        coordination_id: registration.coordination_id,
                        capabilities: registration.capabilities,
                    });
                }
            }
            return Err(StoreError::AlreadyRegistered);
        }
        let retired_controller = if let Some(journal) = self.journal.as_ref() {
            journal
                .retired_controller(&registration.coordination_id)
                .unwrap_or_else(|error| fail_stop(error))
        } else {
            self.retired_controllers
                .get(&registration.coordination_id)
                .copied()
        };
        if retired_controller.is_some_and(|(key, terminal)| {
            terminal || key != registration.permanent_controller_public_key
        }) {
            return Err(StoreError::AlreadyRegistered);
        }
        if self.groups.len() >= self.config.max_groups {
            return Err(StoreError::AtCapacity);
        }
        let capabilities = registration
            .capabilities
            .iter()
            .map(|capability| {
                (
                    capability.capability_id,
                    CapabilityState {
                        public_key: capability.public_key,
                        can_append: capability.can_append,
                        can_read: capability.can_read,
                        can_control: capability.can_control,
                        cursor: 0,
                    },
                )
            })
            .collect();
        self.groups.insert(
            registration.coordination_id,
            StoredGroup {
                capabilities,
                permanent_controller_public_key: registration.permanent_controller_public_key,
                authorization_generation: registration.authorization_generation,
                entries: VecDeque::new(),
                next_sequence: 1,
                revoked_at: None,
                registered_at: now,
                last_activity_at: now,
                coordinator_active: false,
            },
        );
        self.persist_authorization(registration.coordination_id);
        Ok(RegisteredGroup {
            coordination_id: registration.coordination_id,
            capabilities: registration.capabilities,
        })
    }

    pub fn append(
        &mut self,
        capability: &GroupCapability,
        ciphertext: Vec<u8>,
        now: u64,
    ) -> Result<AppendReceipt, StoreError> {
        if ciphertext.is_empty() || ciphertext.len() > self.config.max_entry_bytes {
            return Err(StoreError::OversizedEntry);
        }
        self.expire(now.saturating_sub(self.config.ttl_secs));
        let group = self
            .groups
            .get_mut(&capability.coordination_id)
            .ok_or(StoreError::Unauthorized)?;
        let authorized = group
            .capabilities
            .get(&capability.capability_id)
            .is_some_and(|state| state.can_append && state.public_key == capability.public_key)
            && group.revoked_at.is_none();
        if !authorized {
            return Err(StoreError::Unauthorized);
        }
        if let Some(existing) = group
            .entries
            .iter()
            .find(|entry| entry.ciphertext == ciphertext)
        {
            return Ok(AppendReceipt {
                sequence: existing.sequence,
            });
        }
        if group.entries.len() >= self.config.max_entries_per_group
            || self.total_bytes.saturating_add(ciphertext.len()) > self.config.max_total_bytes
        {
            return Err(StoreError::AtCapacity);
        }
        let sequence = group.next_sequence;
        group.next_sequence = group
            .next_sequence
            .checked_add(1)
            .ok_or(StoreError::AtCapacity)?;
        if let Some(journal) = self.journal.as_mut() {
            if let Err(error) = journal.append_entry(
                &capability.coordination_id,
                group.next_sequence,
                sequence,
                &ciphertext,
                now,
            ) {
                fail_stop(error);
            }
        }
        self.total_bytes += ciphertext.len();
        group.last_activity_at = now;
        group.entries.push_back(GroupEntry {
            sequence,
            ciphertext,
            timestamp: now,
        });
        Ok(AppendReceipt { sequence })
    }

}
