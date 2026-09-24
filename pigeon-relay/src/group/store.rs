// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! Isolated, bounded storage for opaque group application ciphertexts.

use std::collections::{HashMap, HashSet, VecDeque};

pub const GROUP_ID_BYTES: usize = 32;
pub const CAPABILITY_KEY_BYTES: usize = 32;

#[derive(Clone, Debug)]
pub struct Config {
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
    pub capability_id: [u8; CAPABILITY_KEY_BYTES],
    pub public_key: [u8; CAPABILITY_KEY_BYTES],
    pub can_append: bool,
    pub can_read: bool,
    pub can_control: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupRegistration {
    pub coordination_id: [u8; GROUP_ID_BYTES],
    pub authorization_generation: u64,
    pub permanent_controller_public_key: [u8; CAPABILITY_KEY_BYTES],
    pub capabilities: Vec<CapabilityRegistration>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupCapability {
    pub coordination_id: [u8; GROUP_ID_BYTES],
    pub capability_id: [u8; CAPABILITY_KEY_BYTES],
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
            capability_id: self.capabilities[index].capability_id,
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
pub enum StoreError {
    AlreadyRegistered,
    AtCapacity,
    CapabilityLimit,
    InvalidRegistration,
    OversizedEntry,
    StaleCursor,
    Unauthorized,
    StaleGeneration,
}

#[derive(Clone, Debug)]
struct CapabilityState {
    public_key: [u8; CAPABILITY_KEY_BYTES],
    can_append: bool,
    can_read: bool,
    can_control: bool,
    cursor: u64,
}

#[derive(Debug)]
struct StoredGroup {
    capabilities: HashMap<[u8; CAPABILITY_KEY_BYTES], CapabilityState>,
    permanent_controller_public_key: [u8; CAPABILITY_KEY_BYTES],
    authorization_generation: u64,
    entries: VecDeque<GroupEntry>,
    next_sequence: u64,
}

impl StoredGroup {
    fn matches_registration(
        &self,
        capabilities: &[CapabilityRegistration],
        permanent_controller_public_key: [u8; CAPABILITY_KEY_BYTES],
        authorization_generation: u64,
    ) -> bool {
        self.permanent_controller_public_key == permanent_controller_public_key
            && self.authorization_generation == authorization_generation
            && self.capabilities.len() == capabilities.len()
            && capabilities.iter().all(|capability| {
                self.capabilities
                    .get(&capability.capability_id)
                    .is_some_and(|stored| {
                        stored.public_key == capability.public_key
                            && stored.can_append == capability.can_append
                            && stored.can_read == capability.can_read
                            && stored.can_control == capability.can_control
                    })
            })
    }

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
pub struct Store {
    config: Config,
    groups: HashMap<[u8; GROUP_ID_BYTES], StoredGroup>,
    total_bytes: usize,
}

impl Store {
    pub fn bounded(config: Config) -> Self {
        Self {
            config,
            groups: HashMap::new(),
            total_bytes: 0,
        }
    }

    pub fn register(
        &mut self,
        registration: GroupRegistration,
    ) -> Result<RegisteredGroup, StoreError> {
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
            .is_some_and(|state| state.can_append && state.public_key == capability.public_key);
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
        let authorized = group
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
            .and_then(|group| group.capabilities.get(&capability.capability_id))
            .is_some_and(|state| state.can_append && state.public_key == capability.public_key)
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
