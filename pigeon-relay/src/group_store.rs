// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! Isolated, bounded storage for opaque group application ciphertexts.

use std::collections::{HashMap, HashSet, VecDeque};

pub const GROUP_ID_BYTES: usize = 32;
pub const CAPABILITY_KEY_BYTES: usize = 32;

#[derive(Clone, Debug)]
pub struct GroupStoreConfig {
    pub ttl_secs: u64,
    pub max_groups: usize,
    pub max_capabilities_per_group: usize,
    pub max_entry_bytes: usize,
    pub max_entries_per_group: usize,
    pub max_total_bytes: usize,
    pub max_fetch_batch_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityRegistration {
    pub public_key: [u8; CAPABILITY_KEY_BYTES],
    pub can_append: bool,
    pub can_read: bool,
    pub can_control: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupRegistration {
    pub coordination_id: [u8; GROUP_ID_BYTES],
    pub capabilities: Vec<CapabilityRegistration>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupCapability {
    pub coordination_id: [u8; GROUP_ID_BYTES],
    pub public_key: [u8; CAPABILITY_KEY_BYTES],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredGroup {
    coordination_id: [u8; GROUP_ID_BYTES],
    capabilities: Vec<CapabilityRegistration>,
}

impl RegisteredGroup {
    #[cfg(test)]
    pub fn id(&self) -> &[u8; GROUP_ID_BYTES] {
        &self.coordination_id
    }

    #[cfg(test)]
    pub fn writer(&self, index: usize) -> GroupCapability {
        self.capability(index)
    }

    #[cfg(test)]
    pub fn reader(&self, index: usize) -> GroupCapability {
        self.capability(index)
    }

    #[cfg(test)]
    fn capability(&self, index: usize) -> GroupCapability {
        GroupCapability {
            coordination_id: self.coordination_id,
            public_key: self.capabilities[index].public_key,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppendReceipt {
    pub sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupEntry {
    pub sequence: u64,
    pub ciphertext: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupStoreError {
    AlreadyRegistered,
    AtCapacity,
    CapabilityLimit,
    InvalidRegistration,
    OversizedEntry,
    StaleCursor,
    Unauthorized,
}

#[derive(Clone, Debug)]
struct CapabilityState {
    can_append: bool,
    can_read: bool,
    can_control: bool,
    cursor: u64,
}

#[derive(Debug)]
struct StoredGroup {
    capabilities: HashMap<[u8; CAPABILITY_KEY_BYTES], CapabilityState>,
    entries: VecDeque<GroupEntry>,
    next_sequence: u64,
}

impl StoredGroup {
    fn collect_garbage(&mut self) -> usize {
        let Some(minimum_cursor) = self
            .capabilities
            .values()
            .filter(|capability| capability.can_read)
            .map(|capability| capability.cursor)
            .min()
        else {
            return 0;
        };
        let mut freed = 0;
        while self
            .entries
            .front()
            .is_some_and(|entry| entry.sequence <= minimum_cursor)
        {
            if let Some(entry) = self.entries.pop_front() {
                freed += entry.ciphertext.len();
            }
        }
        freed
    }
}

#[derive(Debug)]
pub struct GroupStore {
    config: GroupStoreConfig,
    groups: HashMap<[u8; GROUP_ID_BYTES], StoredGroup>,
    total_bytes: usize,
}

impl GroupStore {
    pub fn bounded(config: GroupStoreConfig) -> Self {
        Self {
            config,
            groups: HashMap::new(),
            total_bytes: 0,
        }
    }

    pub fn register(
        &mut self,
        registration: GroupRegistration,
    ) -> Result<RegisteredGroup, GroupStoreError> {
        if self.groups.contains_key(&registration.coordination_id) {
            return Err(GroupStoreError::AlreadyRegistered);
        }
        if self.groups.len() >= self.config.max_groups {
            return Err(GroupStoreError::AtCapacity);
        }
        if registration.capabilities.is_empty()
            || registration.capabilities.len() > self.config.max_capabilities_per_group
        {
            return Err(GroupStoreError::CapabilityLimit);
        }
        let unique: HashSet<_> = registration
            .capabilities
            .iter()
            .map(|capability| capability.public_key)
            .collect();
        if unique.len() != registration.capabilities.len()
            || !registration
                .capabilities
                .iter()
                .any(|capability| capability.can_append)
            || !registration
                .capabilities
                .iter()
                .any(|capability| capability.can_read)
            || registration
                .capabilities
                .iter()
                .filter(|capability| capability.can_control)
                .count()
                != 1
            || registration.capabilities.iter().any(|capability| {
                !capability.can_append && !capability.can_read && !capability.can_control
            })
        {
            return Err(GroupStoreError::InvalidRegistration);
        }
        let capabilities = registration
            .capabilities
            .iter()
            .map(|capability| {
                (
                    capability.public_key,
                    CapabilityState {
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
                entries: VecDeque::new(),
                next_sequence: 1,
            },
        );
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
    ) -> Result<AppendReceipt, GroupStoreError> {
        if ciphertext.is_empty() || ciphertext.len() > self.config.max_entry_bytes {
            return Err(GroupStoreError::OversizedEntry);
        }
        self.expire(now.saturating_sub(self.config.ttl_secs));
        let group = self
            .groups
            .get_mut(&capability.coordination_id)
            .ok_or(GroupStoreError::Unauthorized)?;
        let authorized = group
            .capabilities
            .get(&capability.public_key)
            .is_some_and(|state| state.can_append);
        if !authorized {
            return Err(GroupStoreError::Unauthorized);
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
            return Err(GroupStoreError::AtCapacity);
        }
        let sequence = group.next_sequence;
        group.next_sequence = group
            .next_sequence
            .checked_add(1)
            .ok_or(GroupStoreError::AtCapacity)?;
        self.total_bytes += ciphertext.len();
        group.entries.push_back(GroupEntry {
            sequence,
            ciphertext,
            timestamp: now,
        });
        Ok(AppendReceipt { sequence })
    }

    pub fn fetch(
        &self,
        capability: &GroupCapability,
        after_cursor: u64,
    ) -> Result<Vec<GroupEntry>, GroupStoreError> {
        let group = self
            .groups
            .get(&capability.coordination_id)
            .ok_or(GroupStoreError::Unauthorized)?;
        let reader = group
            .capabilities
            .get(&capability.public_key)
            .filter(|state| state.can_read)
            .ok_or(GroupStoreError::Unauthorized)?;
        if after_cursor < reader.cursor {
            return Err(GroupStoreError::StaleCursor);
        }
        let mut bytes: usize = 0;
        Ok(group
            .entries
            .iter()
            .filter(|entry| entry.sequence > after_cursor)
            .take_while(|entry| {
                let next = bytes.saturating_add(entry.ciphertext.len());
                if next > self.config.max_fetch_batch_bytes {
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
    ) -> Result<(), GroupStoreError> {
        let group = self
            .groups
            .get_mut(&capability.coordination_id)
            .ok_or(GroupStoreError::Unauthorized)?;
        let last_sequence = group.next_sequence.saturating_sub(1);
        let reader = group
            .capabilities
            .get_mut(&capability.public_key)
            .filter(|state| state.can_read)
            .ok_or(GroupStoreError::Unauthorized)?;
        if sequence <= reader.cursor || sequence > last_sequence {
            return Err(GroupStoreError::StaleCursor);
        }
        reader.cursor = sequence;
        self.total_bytes = self.total_bytes.saturating_sub(group.collect_garbage());
        Ok(())
    }

    pub fn rotate_capability(
        &mut self,
        controller: &GroupCapability,
        old_public_key: [u8; CAPABILITY_KEY_BYTES],
        replacement: CapabilityRegistration,
    ) -> Result<(), GroupStoreError> {
        let group = self
            .groups
            .get_mut(&controller.coordination_id)
            .ok_or(GroupStoreError::Unauthorized)?;
        if !group
            .capabilities
            .get(&controller.public_key)
            .is_some_and(|capability| capability.can_control)
            || group.capabilities.contains_key(&replacement.public_key)
        {
            return Err(GroupStoreError::Unauthorized);
        }
        let old = group
            .capabilities
            .remove(&old_public_key)
            .ok_or(GroupStoreError::Unauthorized)?;
        if old.can_control != replacement.can_control {
            group.capabilities.insert(old_public_key, old);
            return Err(GroupStoreError::InvalidRegistration);
        }
        group.capabilities.insert(
            replacement.public_key,
            CapabilityState {
                can_append: replacement.can_append,
                can_read: replacement.can_read,
                can_control: replacement.can_control,
                cursor: old.cursor,
            },
        );
        self.total_bytes = self.total_bytes.saturating_sub(group.collect_garbage());
        Ok(())
    }

    pub fn revoke_capability(
        &mut self,
        controller: &GroupCapability,
        public_key: [u8; CAPABILITY_KEY_BYTES],
    ) -> Result<(), GroupStoreError> {
        let group = self
            .groups
            .get_mut(&controller.coordination_id)
            .ok_or(GroupStoreError::Unauthorized)?;
        if !group
            .capabilities
            .get(&controller.public_key)
            .is_some_and(|capability| capability.can_control)
        {
            return Err(GroupStoreError::Unauthorized);
        }
        let removed = group
            .capabilities
            .get(&public_key)
            .ok_or(GroupStoreError::Unauthorized)?;
        if removed.can_control
            || (removed.can_read
                && group
                    .capabilities
                    .values()
                    .filter(|capability| capability.can_read)
                    .count()
                    == 1)
        {
            return Err(GroupStoreError::InvalidRegistration);
        }
        group.capabilities.remove(&public_key);
        self.total_bytes = self.total_bytes.saturating_sub(group.collect_garbage());
        Ok(())
    }

    pub fn is_authorized(&self, capability: &GroupCapability) -> bool {
        self.groups
            .get(&capability.coordination_id)
            .and_then(|group| group.capabilities.get(&capability.public_key))
            .is_some()
    }

    pub fn can_read(&self, capability: &GroupCapability) -> bool {
        self.groups
            .get(&capability.coordination_id)
            .and_then(|group| group.capabilities.get(&capability.public_key))
            .is_some_and(|capability| capability.can_read)
    }

    pub fn can_append(&self, capability: &GroupCapability) -> bool {
        self.groups
            .get(&capability.coordination_id)
            .and_then(|group| group.capabilities.get(&capability.public_key))
            .is_some_and(|capability| capability.can_append)
    }

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
        self.expire(now.saturating_sub(self.config.ttl_secs));
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
