#[derive(Clone, Debug)]
pub struct Config {
    pub ttl_secs: u64,
    pub lease_secs: u64,
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
    revoked_at: Option<u64>,
    registered_at: u64,
    last_activity_at: u64,
    coordinator_active: bool,
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

pub struct Store {
    config: Config,
    groups: HashMap<[u8; GROUP_ID_BYTES], StoredGroup>,
    total_bytes: usize,
    retired_controllers: HashMap<[u8; GROUP_ID_BYTES], ([u8; CAPABILITY_KEY_BYTES], bool)>,
    /// Write-through durable copy; `None` keeps the store memory-only.
    journal: Option<GroupJournal>,
}
