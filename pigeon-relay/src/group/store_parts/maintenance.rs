impl Store {
    pub fn reader_keys(
        &self,
        coordination_id: &[u8; GROUP_ID_BYTES],
    ) -> Vec<[u8; CAPABILITY_KEY_BYTES]> {
        self.groups
            .get(coordination_id)
            .map(|group| {
                group
                    .capabilities
                    .iter()
                    .filter_map(|(key, capability)| capability.can_read.then_some(*key))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn expire(&mut self, cutoff: u64) {
        let mut freed = 0;
        for group in self.groups.values_mut() {
            while group
                .entries
                .front()
                .is_some_and(|entry| entry.timestamp < cutoff)
            {
                if let Some(entry) = group.entries.pop_front() {
                    freed += entry.ciphertext.len();
                }
            }
        }
        self.total_bytes = self.total_bytes.saturating_sub(freed);
    }

    pub fn expire_at(&mut self, now: u64) {
        let cutoff = now.saturating_sub(self.config.ttl_secs);
        if let Some(journal) = self.journal.as_mut() {
            if let Err(error) = journal.expire(cutoff) {
                fail_stop(error);
            }
        }
        self.expire(cutoff);
        let expired = self
            .groups
            .iter()
            .filter_map(|(id, group)| {
                group
                    .revoked_at
                    .is_some_and(|at| at < cutoff)
                    .then_some(*id)
                    .or_else(|| {
                        (self.journal.is_none()
                            && group.revoked_at.is_none()
                            && group.next_sequence == 1
                            && group.authorization_generation == 0
                            && !group.coordinator_active
                            && group.registered_at < cutoff)
                            .then_some(*id)
                    })
            })
            .collect::<Vec<_>>();
        for id in expired {
            if let Some(group) = self.groups.remove(&id) {
                if self.journal.is_none() {
                    self.retired_controllers.insert(
                        id,
                        (
                            group.permanent_controller_public_key,
                            group.revoked_at.is_some(),
                        ),
                    );
                }
                let freed = group
                    .entries
                    .iter()
                    .map(|entry| entry.ciphertext.len())
                    .sum::<usize>();
                self.total_bytes = self.total_bytes.saturating_sub(freed);
            }
        }
        let inactive = self
            .groups
            .iter()
            .filter_map(|(id, group)| {
                (group.revoked_at.is_none()
                    && now.saturating_sub(group.last_activity_at) > self.config.lease_secs)
                    .then_some(*id)
            })
            .collect::<Vec<_>>();
        for id in inactive {
            if let Some(journal) = self.journal.as_mut() {
                journal
                    .mark_inactive(&id)
                    .unwrap_or_else(|error| fail_stop(error));
                self.groups.remove(&id);
            }
        }
        if let Some(journal) = self.journal.as_ref() {
            let active_bytes = self
                .groups
                .values()
                .flat_map(|group| &group.entries)
                .map(|entry| entry.ciphertext.len())
                .sum::<usize>();
            self.total_bytes = active_bytes.saturating_add(
                journal
                    .inactive_ciphertext_bytes()
                    .unwrap_or_else(|error| fail_stop(error)),
            );
        }
    }

    #[cfg(test)]
    pub fn entry_count(&self, coordination_id: &[u8; GROUP_ID_BYTES]) -> usize {
        self.groups
            .get(coordination_id)
            .map_or(0, |group| group.entries.len())
    }

    #[cfg(test)]
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }
}


fn validate_record(
    record: &GroupRecord,
    config: &Config,
    existing_bytes: usize,
) -> Result<(), DurableError> {
    if record.capabilities.is_empty()
        || record.capabilities.len() > config.max_capabilities_per_group
        || record.entries.len() > config.max_entries_per_group
        || record.next_sequence == 0
    {
        return Err(DurableError::Corrupt("invalid group bounds"));
    }
    let unique_ids = record
        .capabilities
        .iter()
        .map(|capability| capability.capability_id)
        .collect::<HashSet<_>>();
    let unique_keys = record
        .capabilities
        .iter()
        .map(|capability| capability.public_key)
        .collect::<HashSet<_>>();
    let last_sequence = record.next_sequence.saturating_sub(1);
    if unique_ids.len() != record.capabilities.len()
        || unique_keys.len() != record.capabilities.len()
        || !record.capabilities.iter().any(|capability| {
            capability.can_control
                && capability.public_key == record.permanent_controller_public_key
        })
        || record.capabilities.iter().any(|capability| {
            (!capability.can_append && !capability.can_read && !capability.can_control)
                || capability.cursor > last_sequence
        })
    {
        return Err(DurableError::Corrupt("invalid group capabilities"));
    }
    let mut prior = 0;
    let mut bytes = existing_bytes;
    for entry in &record.entries {
        if entry.sequence == 0
            || entry.sequence <= prior
            || entry.sequence >= record.next_sequence
            || entry.ciphertext.is_empty()
            || entry.ciphertext.len() > config.max_entry_bytes
        {
            return Err(DurableError::Corrupt("invalid group entry"));
        }
        prior = entry.sequence;
        bytes = bytes.saturating_add(entry.ciphertext.len());
        if bytes > config.max_total_bytes {
            return Err(DurableError::Corrupt("group bytes exceed configured limit"));
        }
    }
    Ok(())
}
