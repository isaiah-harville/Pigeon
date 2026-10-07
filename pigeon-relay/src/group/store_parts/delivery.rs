impl Store {
    pub fn fetch(
        &self,
        capability: &GroupCapability,
        after_cursor: u64,
    ) -> Result<Vec<GroupEntry>, StoreError> {
        let group = self
            .groups
            .get(&capability.coordination_id)
            .ok_or(StoreError::Unauthorized)?;
        let reader = group
            .capabilities
            .get(&capability.capability_id)
            .filter(|state| state.can_read && state.public_key == capability.public_key)
            .ok_or(StoreError::Unauthorized)?;
        let effective_cursor = after_cursor.max(reader.cursor);
        let mut bytes: usize = 0;
        Ok(group
            .entries
            .iter()
            .filter(|entry| entry.sequence > effective_cursor)
            .take_while(|entry| {
                let next = bytes.saturating_add(entry.ciphertext.len());
                if next > self.config.max_fetch_batch_bytes && bytes != 0 {
                    false
                } else {
                    bytes = next;
                    true
                }
            })
            .cloned()
            .collect())
    }

    pub fn advance(
        &mut self,
        capability: &GroupCapability,
        sequence: u64,
    ) -> Result<(), StoreError> {
        let group = self
            .groups
            .get_mut(&capability.coordination_id)
            .ok_or(StoreError::Unauthorized)?;
        let last_sequence = group.next_sequence.saturating_sub(1);
        let reader = group
            .capabilities
            .get_mut(&capability.capability_id)
            .filter(|state| state.can_read && state.public_key == capability.public_key)
            .ok_or(StoreError::Unauthorized)?;
        if sequence > 0 && sequence <= reader.cursor {
            return Ok(());
        }
        if sequence == 0 || sequence > last_sequence {
            return Err(StoreError::StaleCursor);
        }
        reader.cursor = sequence;
        self.total_bytes = self.total_bytes.saturating_sub(group.collect_garbage());
        self.persist_authorization(capability.coordination_id);
        Ok(())
    }

    pub fn replace_capabilities(
        &mut self,
        controller: &GroupCapability,
        expected_generation: u64,
        new_generation: u64,
        permanent_controller_public_key: [u8; CAPABILITY_KEY_BYTES],
        replacements: Vec<CapabilityRegistration>,
    ) -> Result<(), StoreError> {
        let group = self
            .groups
            .get_mut(&controller.coordination_id)
            .ok_or(StoreError::Unauthorized)?;
        let authorized = group.revoked_at.is_none()
            && group
                .capabilities
                .get(&controller.capability_id)
                .is_some_and(|capability| {
                    capability.can_control && capability.public_key == controller.public_key
                });
        if !authorized {
            return Err(StoreError::Unauthorized);
        }
        if group.authorization_generation != expected_generation
            || new_generation != expected_generation.saturating_add(1)
        {
            return Err(StoreError::StaleGeneration);
        }
        if permanent_controller_public_key != group.permanent_controller_public_key
            || replacements.len() < 3
            || replacements.len() > self.config.max_capabilities_per_group
        {
            return Err(StoreError::InvalidRegistration);
        }
        let unique_ids: HashSet<_> = replacements
            .iter()
            .map(|capability| capability.capability_id)
            .collect();
        let unique_keys: HashSet<_> = replacements
            .iter()
            .map(|capability| capability.public_key)
            .collect();
        if unique_ids.len() != replacements.len()
            || unique_keys.len() != replacements.len()
            || replacements
                .iter()
                .any(|capability| !capability.can_append || !capability.can_read)
            || !replacements.iter().any(|capability| {
                capability.can_control && capability.public_key == permanent_controller_public_key
            })
        {
            return Err(StoreError::InvalidRegistration);
        }
        let current_sequence = group.next_sequence.saturating_sub(1);
        let next = replacements
            .into_iter()
            .map(|capability| {
                let cursor = group
                    .capabilities
                    .values()
                    .find(|state| state.public_key == capability.public_key)
                    .map_or(current_sequence, |state| state.cursor);
                (
                    capability.capability_id,
                    CapabilityState {
                        public_key: capability.public_key,
                        can_append: capability.can_append,
                        can_read: capability.can_read,
                        can_control: capability.can_control,
                        cursor,
                    },
                )
            })
            .collect();
        group.capabilities = next;
        group.authorization_generation = new_generation;
        self.total_bytes = self.total_bytes.saturating_sub(group.collect_garbage());
        self.persist_authorization(controller.coordination_id);
        Ok(())
    }

    pub fn revoke_group(
        &mut self,
        controller: &GroupCapability,
        expected_generation: u64,
        now: u64,
    ) -> Result<(), StoreError> {
        let group = self
            .groups
            .get_mut(&controller.coordination_id)
            .ok_or(StoreError::Unauthorized)?;
        let authorized = group.authorization_generation == expected_generation
            && controller.public_key == group.permanent_controller_public_key
            && group
                .capabilities
                .get(&controller.capability_id)
                .is_some_and(|capability| {
                    capability.can_control && capability.public_key == controller.public_key
                });
        if !authorized {
            return Err(StoreError::Unauthorized);
        }
        // Keep read capabilities alive for one TTL after dissolution. The
        // terminal MLS commit is coordinator-delivered, so an offline member
        // must still be able to authenticate and fetch it. All mutating paths
        // fail closed as soon as this tombstone is installed.
        group.revoked_at.get_or_insert(now);
        self.persist_authorization(controller.coordination_id);
        Ok(())
    }

    pub fn resolve_capability(
        &self,
        coordination_id: [u8; GROUP_ID_BYTES],
        capability_id: [u8; CAPABILITY_KEY_BYTES],
    ) -> Option<GroupCapability> {
        self.groups
            .get(&coordination_id)
            .and_then(|group| group.capabilities.get(&capability_id))
            .map(|state| GroupCapability {
                coordination_id,
                capability_id,
                public_key: state.public_key,
            })
            .or_else(|| {
                self.journal.as_ref().and_then(|journal| {
                    journal
                        .inactive_capability(&coordination_id, &capability_id)
                        .unwrap_or_else(|error| fail_stop(error))
                        .map(|public_key| GroupCapability {
                            coordination_id,
                            capability_id,
                            public_key,
                        })
                })
            })
    }

    pub fn contains_group(&self, coordination_id: &[u8; GROUP_ID_BYTES]) -> bool {
        self.groups.contains_key(coordination_id)
            || self.journal.as_ref().is_some_and(|journal| {
                journal
                    .contains_group(coordination_id)
                    .unwrap_or_else(|error| fail_stop(error))
            })
    }

    pub fn activate(&mut self, capability: &GroupCapability, now: u64) -> Result<(), StoreError> {
        self.expire_at(now);
        if let Some(group) = self.groups.get(&capability.coordination_id) {
            return if group
                .capabilities
                .get(&capability.capability_id)
                .is_some_and(|state| state.public_key == capability.public_key)
            {
                Ok(())
            } else {
                Err(StoreError::Unauthorized)
            };
        }
        if self.groups.len() >= self.config.max_groups {
            return Err(StoreError::AtCapacity);
        }
        let journal = self.journal.as_mut().ok_or(StoreError::Unauthorized)?;
        let key = journal
            .inactive_capability(&capability.coordination_id, &capability.capability_id)
            .unwrap_or_else(|error| fail_stop(error));
        if key != Some(capability.public_key) {
            return Err(StoreError::Unauthorized);
        }
        let record = journal
            .reactivate(
                &capability.coordination_id,
                now,
                now.saturating_sub(self.config.ttl_secs),
            )
            .unwrap_or_else(|error| fail_stop(error));
        let record_bytes = record
            .entries
            .iter()
            .map(|entry| entry.ciphertext.len())
            .sum::<usize>();
        validate_record(
            &record,
            &self.config,
            self.total_bytes.saturating_sub(record_bytes),
        )
        .unwrap_or_else(|error| fail_stop(error));
        self.groups.insert(
            record.coordination_id,
            StoredGroup {
                capabilities: record
                    .capabilities
                    .into_iter()
                    .map(|state| {
                        (
                            state.capability_id,
                            CapabilityState {
                                public_key: state.public_key,
                                can_append: state.can_append,
                                can_read: state.can_read,
                                can_control: state.can_control,
                                cursor: state.cursor,
                            },
                        )
                    })
                    .collect(),
                permanent_controller_public_key: record.permanent_controller_public_key,
                authorization_generation: record.authorization_generation,
                entries: record
                    .entries
                    .into_iter()
                    .map(|entry| GroupEntry {
                        sequence: entry.sequence,
                        ciphertext: entry.ciphertext,
                        timestamp: entry.timestamp,
                    })
                    .collect(),
                next_sequence: record.next_sequence,
                revoked_at: record.revoked_at,
                registered_at: record.registered_at,
                last_activity_at: record.last_activity_at,
                coordinator_active: record.coordinator_active,
            },
        );
        Ok(())
    }

    pub fn touch(&mut self, coordination_id: [u8; GROUP_ID_BYTES], now: u64) {
        if let Some(group) = self.groups.get_mut(&coordination_id) {
            group.last_activity_at = now;
            if let Some(journal) = self.journal.as_mut() {
                journal
                    .touch(&coordination_id, now)
                    .unwrap_or_else(|error| fail_stop(error));
            }
        }
    }

    #[cfg(test)]
    pub fn groups_active_for_test(&self, coordination_id: &[u8; GROUP_ID_BYTES]) -> bool {
        self.groups.contains_key(coordination_id)
    }

    /// Pins authorization before a coordinator receipt can be signed. A
    /// candidate rejected later may leave a harmless pinned registration.
    pub fn mark_coordinator_activity(&mut self, coordination_id: &[u8; GROUP_ID_BYTES]) {
        if let Some(group) = self.groups.get_mut(coordination_id) {
            if !group.coordinator_active {
                group.coordinator_active = true;
                self.persist_authorization(*coordination_id);
            }
        }
    }

    pub fn can_read(&self, capability: &GroupCapability) -> bool {
        self.groups
            .get(&capability.coordination_id)
            .and_then(|group| group.capabilities.get(&capability.capability_id))
            .is_some_and(|state| state.can_read && state.public_key == capability.public_key)
    }

    pub fn can_append(&self, capability: &GroupCapability) -> bool {
        self.groups
            .get(&capability.coordination_id)
            .is_some_and(|group| {
                group.revoked_at.is_none()
                    && group
                        .capabilities
                        .get(&capability.capability_id)
                        .is_some_and(|state| {
                            state.can_append && state.public_key == capability.public_key
                        })
            })
    }

}
