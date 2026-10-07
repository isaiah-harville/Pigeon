fn prune_subscribers(state: &ConnectionState, coordination_id: [u8; 32]) {
    let store = state.service.store.lock().unwrap();
    if let Some(subscribers) = state
        .service
        .subscribers
        .lock()
        .unwrap()
        .get_mut(&coordination_id)
    {
        subscribers.retain(|subscriber| {
            store.can_read(&subscriber.capability) && !subscriber.tx.is_closed()
        });
    }
}

fn wake_authorized_subscribers(store: &super::store::Store, subscribers: &mut Vec<Subscriber>) {
    subscribers.retain(|subscriber| {
        store.can_read(&subscriber.capability)
            && (subscriber.tx.try_send(GroupServerMsg::Wake).is_ok() || !subscriber.tx.is_closed())
    });
}

const MAX_FETCH_ENTRIES: usize = 512;

fn batch_entries(entries: Vec<GroupEntryWire>) -> Result<GroupServerMsg, ()> {
    let overhead = serde_json::to_vec(&GroupServerMsg::Entries { entries: vec![] })
        .map_err(|_| ())?
        .len();
    let entries = bounded_items(entries, overhead)?;
    Ok(GroupServerMsg::Entries { entries })
}

fn batch_candidates(candidates: Vec<CandidateWire>) -> Result<GroupServerMsg, ()> {
    let overhead =
        serde_json::to_vec(&GroupServerMsg::CoordinatorCandidates { candidates: vec![] })
            .map_err(|_| ())?
            .len();
    let candidates = bounded_items(candidates, overhead)?;
    Ok(GroupServerMsg::CoordinatorCandidates { candidates })
}

fn bounded_items<T: Serialize>(items: Vec<T>, overhead: usize) -> Result<Vec<T>, ()> {
    let mut bytes = overhead;
    let mut page = Vec::new();
    for item in items {
        if page.len() == MAX_FETCH_ENTRIES {
            break;
        }
        let item_bytes = serde_json::to_vec(&item).map_err(|_| ())?.len();
        let next = bytes
            .saturating_add(item_bytes)
            .saturating_add(usize::from(!page.is_empty()));
        if next > MAX_GROUP_FRAME_BYTES {
            if page.is_empty() {
                return Err(());
            }
            break;
        }
        bytes = next;
        page.push(item);
    }
    Ok(page)
}

fn wake_and_push_readers(state: &ConnectionState, coordination_id: [u8; 32]) {
    wake_readers(state, coordination_id);
    for reader_key in state
        .service
        .store
        .lock()
        .unwrap()
        .reader_keys(&coordination_id)
    {
        push::notify_deposit(state.push.clone(), push_scope(coordination_id, reader_key));
    }
}

fn remove_subscriber(
    state: &ConnectionState,
    capability: Option<&GroupCapability>,
    connection_id: u64,
) {
    let Some(capability) = capability else {
        return;
    };
    let mut groups = state.service.subscribers.lock().unwrap();
    if let Some(subscribers) = groups.get_mut(&capability.coordination_id) {
        subscribers.retain(|subscriber| subscriber.connection_id != connection_id);
        if subscribers.is_empty() {
            groups.remove(&capability.coordination_id);
        }
    }
}

fn ok_or_error(result: Result<(), ()>) -> GroupServerMsg {
    if result.is_ok() {
        GroupServerMsg::Ok
    } else {
        generic_error()
    }
}

fn malformed_error() -> GroupServerMsg {
    GroupServerMsg::Error {
        message: "malformed message".into(),
    }
}

fn generic_error() -> GroupServerMsg {
    GroupServerMsg::Error {
        message: "group operation rejected".into(),
    }
}

fn capacity_error() -> GroupServerMsg {
    GroupServerMsg::Error {
        message: "capacity".into(),
    }
}

fn push_scope(coordination_id: [u8; 32], capability_key: [u8; 32]) -> String {
    let mut scope = String::with_capacity(6 + 128);
    scope.push_str("group:");
    scope.push_str(&hex::encode(coordination_id));
    scope.push_str(&hex::encode(capability_key));
    scope
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::store::{CapabilityRegistration, Config, GroupRegistration, Store};

    #[test]
    fn group_pages_at_512_entries_and_within_encoded_frame_limit() {
        let entries = (1..=513)
            .map(|sequence| GroupEntryWire {
                sequence,
                ciphertext: B64.encode([0_u8; 1]),
                timestamp: 1,
            })
            .collect();
        let page = batch_entries(entries).unwrap();
        let GroupServerMsg::Entries { entries } = &page else {
            panic!("wrong response")
        };
        assert_eq!(entries.len(), 512);
        assert!(serde_json::to_vec(&page).unwrap().len() <= MAX_GROUP_FRAME_BYTES);

        let entries = (1..=3)
            .map(|sequence| GroupEntryWire {
                sequence,
                ciphertext: B64.encode(vec![0_u8; 600_000]),
                timestamp: 1,
            })
            .collect();
        let page = batch_entries(entries).unwrap();
        let GroupServerMsg::Entries { entries } = &page else {
            panic!("wrong response")
        };
        assert_eq!(entries.len(), 2);
        assert!(serde_json::to_vec(&page).unwrap().len() <= MAX_GROUP_FRAME_BYTES);
    }

    #[test]
    fn group_page_includes_one_maximum_sized_entry() {
        let page = batch_entries(vec![GroupEntryWire {
            sequence: u64::MAX,
            ciphertext: B64.encode(vec![0_u8; 1024 * 1024]),
            timestamp: u64::MAX,
        }])
        .unwrap();
        let GroupServerMsg::Entries { entries } = &page else {
            panic!("wrong response")
        };
        assert_eq!(entries.len(), 1);
        assert!(serde_json::to_vec(&page).unwrap().len() <= MAX_GROUP_FRAME_BYTES);
    }

    #[test]
    fn coordinator_pages_by_count_and_encoded_bytes() {
        use crate::coordinator::protocol::ReceiptWire;
        let receipt = ReceiptWire {
            coordination_id: "a".repeat(64),
            sequence: 1,
            prior_receipt_hash: "b".repeat(64),
            claimed_base_epoch: 1,
            entry_hash: "c".repeat(64),
            signature: "d".repeat(88),
        };
        let candidates = (0..513)
            .map(|_| CandidateWire {
                receipt: receipt.clone(),
                candidate: B64.encode([1_u8]),
                timestamp: 1,
            })
            .collect();
        let page = batch_candidates(candidates).unwrap();
        let GroupServerMsg::CoordinatorCandidates { candidates } = &page else {
            panic!("wrong response")
        };
        assert_eq!(candidates.len(), 512);
        assert!(serde_json::to_vec(&page).unwrap().len() <= MAX_GROUP_FRAME_BYTES);

        let candidates = (0..3)
            .map(|_| CandidateWire {
                receipt: receipt.clone(),
                candidate: B64.encode(vec![1_u8; 600_000]),
                timestamp: 1,
            })
            .collect();
        let page = batch_candidates(candidates).unwrap();
        let GroupServerMsg::CoordinatorCandidates { candidates } = &page else {
            panic!("wrong response")
        };
        assert_eq!(candidates.len(), 2);
        assert!(serde_json::to_vec(&page).unwrap().len() <= MAX_GROUP_FRAME_BYTES);

        let page = batch_candidates(vec![CandidateWire {
            receipt,
            candidate: B64.encode(vec![1_u8; 1024 * 1024]),
            timestamp: u64::MAX,
        }])
        .unwrap();
        let GroupServerMsg::CoordinatorCandidates { candidates } = &page else {
            panic!("wrong response")
        };
        assert_eq!(candidates.len(), 1);
        assert!(serde_json::to_vec(&page).unwrap().len() <= MAX_GROUP_FRAME_BYTES);
    }

    #[test]
    fn revoked_socket_receives_no_wake_and_retained_reader_does() {
        let mut store = Store::bounded(Config {
            ttl_secs: 60,
            lease_secs: 60,
            max_groups: 4,
            max_capabilities_per_group: 4,
            max_entry_bytes: 1024,
            max_entries_per_group: 4,
            max_total_bytes: 4096,
            max_fetch_batch_bytes: 2048,
        });
        let registration = GroupRegistration {
            coordination_id: [9; 32],
            authorization_generation: 0,
            permanent_controller_public_key: [1; 32],
            capabilities: (1..=3)
                .map(|id| CapabilityRegistration {
                    capability_id: [id; 32],
                    public_key: [id; 32],
                    can_append: true,
                    can_read: true,
                    can_control: id == 1,
                })
                .collect(),
        };
        let group = store.register(registration).unwrap();
        let removed = group.reader(2);
        let retained = group.reader(1);
        let (removed_tx, mut removed_rx) = mpsc::channel(2);
        let (retained_tx, mut retained_rx) = mpsc::channel(2);
        let mut subscribers = vec![
            Subscriber {
                connection_id: 1,
                capability: removed,
                tx: removed_tx,
            },
            Subscriber {
                connection_id: 2,
                capability: retained.clone(),
                tx: retained_tx,
            },
        ];
        let replacements = vec![
            CapabilityRegistration {
                capability_id: [11; 32],
                public_key: [1; 32],
                can_append: true,
                can_read: true,
                can_control: true,
            },
            CapabilityRegistration {
                capability_id: retained.capability_id,
                public_key: retained.public_key,
                can_append: true,
                can_read: true,
                can_control: false,
            },
            CapabilityRegistration {
                capability_id: [14; 32],
                public_key: [4; 32],
                can_append: true,
                can_read: true,
                can_control: false,
            },
        ];
        store
            .replace_capabilities(&group.writer(0), 0, 1, [1; 32], replacements)
            .unwrap();
        wake_authorized_subscribers(&store, &mut subscribers);
        assert!(removed_rx.try_recv().is_err());
        assert!(matches!(retained_rx.try_recv(), Ok(GroupServerMsg::Wake)));
        assert_eq!(subscribers.len(), 1);
        // Message appends and coordinator submissions both use this wake path.
        wake_authorized_subscribers(&store, &mut subscribers);
        assert!(removed_rx.try_recv().is_err());
        assert!(matches!(retained_rx.try_recv(), Ok(GroupServerMsg::Wake)));
    }

    #[test]
    fn group_fetch_returns_first_entry_when_raw_budget_is_smaller() {
        let mut store = Store::bounded(Config {
            ttl_secs: 60,
            lease_secs: 60,
            max_groups: 4,
            max_capabilities_per_group: 4,
            max_entry_bytes: 1024,
            max_entries_per_group: 4,
            max_total_bytes: 4096,
            max_fetch_batch_bytes: 1,
        });
        let group = store
            .register(GroupRegistration {
                coordination_id: [7; 32],
                authorization_generation: 0,
                permanent_controller_public_key: [1; 32],
                capabilities: (1..=3)
                    .map(|id| CapabilityRegistration {
                        capability_id: [id; 32],
                        public_key: [id; 32],
                        can_append: true,
                        can_read: true,
                        can_control: id == 1,
                    })
                    .collect(),
            })
            .unwrap();
        store.append(&group.writer(0), vec![1; 10], 1).unwrap();
        assert_eq!(store.fetch(&group.reader(1), 0).unwrap().len(), 1);
    }

    #[test]
    fn durable_backlog_pages_after_restart() {
        use crate::durable::GroupJournal;
        let directory = tempfile::tempdir().unwrap();
        let config = Config {
            ttl_secs: 60,
            lease_secs: 60,
            max_groups: 4,
            max_capabilities_per_group: 4,
            max_entry_bytes: 1024,
            max_entries_per_group: 600,
            max_total_bytes: 4096,
            max_fetch_batch_bytes: 4096,
        };
        let mut store = Store::durable(
            config.clone(),
            GroupJournal::open(directory.path()).unwrap(),
            1,
        )
        .unwrap();
        let group = store
            .register_at(
                GroupRegistration {
                    coordination_id: [7; 32],
                    authorization_generation: 0,
                    permanent_controller_public_key: [1; 32],
                    capabilities: (1..=3)
                        .map(|id| CapabilityRegistration {
                            capability_id: [id; 32],
                            public_key: [id; 32],
                            can_append: true,
                            can_read: true,
                            can_control: id == 1,
                        })
                        .collect(),
                },
                1,
            )
            .unwrap();
        for value in 0..513_u16 {
            store
                .append(&group.writer(0), value.to_be_bytes().to_vec(), 1)
                .unwrap();
        }
        drop(store);

        let restored =
            Store::durable(config, GroupJournal::open(directory.path()).unwrap(), 2).unwrap();
        let reader = restored
            .resolve_capability(*group.id(), group.reader(1).capability_id)
            .unwrap();
        let first = batch_entries(
            restored
                .fetch(&reader, 0)
                .unwrap()
                .into_iter()
                .map(|entry| GroupEntryWire {
                    sequence: entry.sequence,
                    ciphertext: B64.encode(entry.ciphertext),
                    timestamp: entry.timestamp,
                })
                .collect(),
        )
        .unwrap();
        let GroupServerMsg::Entries { entries } = first else {
            panic!("wrong response")
        };
        assert_eq!(entries.len(), 512);
        let second = batch_entries(
            restored
                .fetch(&reader, entries.last().unwrap().sequence)
                .unwrap()
                .into_iter()
                .map(|entry| GroupEntryWire {
                    sequence: entry.sequence,
                    ciphertext: B64.encode(entry.ciphertext),
                    timestamp: entry.timestamp,
                })
                .collect(),
        )
        .unwrap();
        let GroupServerMsg::Entries { entries } = second else {
            panic!("wrong response")
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].sequence, 513);
    }
}
