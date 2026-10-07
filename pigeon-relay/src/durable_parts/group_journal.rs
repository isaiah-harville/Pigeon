impl GroupJournal {
    pub fn open(dir: &Path) -> Result<Self, DurableError> {
        Self::with_connection(open(Some(&dir.join(GROUP_DATABASE)))?)
    }

    fn with_connection(mut connection: Connection) -> Result<Self, DurableError> {
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version == 1 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(
                "ALTER TABLE groups ADD COLUMN registered_at INTEGER NOT NULL DEFAULT 0;
                 UPDATE groups SET registered_at = unixepoch();",
            )?;
            transaction.pragma_update(None, "user_version", 2)?;
            transaction.commit()?;
        }
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version == 2 {
            let transaction = connection.transaction()?;
            // Legacy registrations may already have signed coordinator
            // receipts. Preserve them until an operator deliberately reclaims.
            transaction.execute_batch(
                "ALTER TABLE groups ADD COLUMN coordinator_active INTEGER NOT NULL DEFAULT 1;",
            )?;
            transaction.pragma_update(None, "user_version", 3)?;
            transaction.commit()?;
        }
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version == 3 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE retired_groups (
                    coordination_id BLOB PRIMARY KEY NOT NULL,
                    permanent_controller_public_key BLOB NOT NULL,
                    terminal INTEGER NOT NULL
                ) WITHOUT ROWID;",
            )?;
            transaction.pragma_update(None, "user_version", 4)?;
            transaction.commit()?;
        }
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version == 4 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(
                "ALTER TABLE groups ADD COLUMN last_activity_at INTEGER NOT NULL DEFAULT 0;
                 ALTER TABLE groups ADD COLUMN inactive INTEGER NOT NULL DEFAULT 0;
                 UPDATE groups SET last_activity_at = unixepoch();",
            )?;
            transaction.pragma_update(None, "user_version", 5)?;
            transaction.commit()?;
        }
        migrate(&mut connection, GROUP_SCHEMA, GROUP_SCHEMA_VERSION)?;
        Ok(Self { connection })
    }

    pub fn load(&self, cutoff: u64) -> Result<Vec<GroupRecord>, DurableError> {
        let mut groups = Vec::new();
        let mut statement = self.connection.prepare(
            "SELECT coordination_id, permanent_controller_public_key, authorization_generation,
                    next_sequence, revoked_at, registered_at, coordinator_active, last_activity_at
             FROM groups
             WHERE inactive = 0
               AND (revoked_at IS NULL OR revoked_at >= ?1)
             ORDER BY coordination_id",
        )?;
        let mut rows = statement.query(params![to_sql(cutoff)])?;
        while let Some(row) = rows.next()? {
            groups.push(GroupRecord {
                coordination_id: fixed(row.get(0)?, "group id")?,
                permanent_controller_public_key: fixed(row.get(1)?, "controller key")?,
                authorization_generation: from_sql(row.get(2)?),
                next_sequence: from_sql(row.get(3)?),
                revoked_at: row.get::<_, Option<i64>>(4)?.map(from_sql),
                registered_at: from_sql(row.get(5)?),
                coordinator_active: row.get(6)?,
                last_activity_at: from_sql(row.get(7)?),
                capabilities: Vec::new(),
                entries: Vec::new(),
            });
        }
        for group in &mut groups {
            self.load_group_contents(group, cutoff)?;
        }
        Ok(groups)
    }

    fn load_group_contents(
        &self,
        group: &mut GroupRecord,
        cutoff: u64,
    ) -> Result<(), DurableError> {
        let mut capabilities = self.connection.prepare_cached(
            "SELECT capability_id, public_key, can_append, can_read, can_control, cursor
                 FROM capabilities WHERE coordination_id = ?1",
        )?;
        let mut rows = capabilities.query(params![group.coordination_id.as_slice()])?;
        while let Some(row) = rows.next()? {
            group.capabilities.push(CapabilityRecord {
                capability_id: fixed(row.get(0)?, "capability id")?,
                public_key: fixed(row.get(1)?, "capability key")?,
                can_append: row.get(2)?,
                can_read: row.get(3)?,
                can_control: row.get(4)?,
                cursor: from_sql(row.get(5)?),
            });
        }
        let mut entries = self.connection.prepare_cached(
            "SELECT sequence, ciphertext, timestamp FROM entries
                 WHERE coordination_id = ?1 AND timestamp >= ?2 ORDER BY sequence",
        )?;
        let mut rows = entries.query(params![group.coordination_id.as_slice(), to_sql(cutoff)])?;
        while let Some(row) = rows.next()? {
            group.entries.push(EntryRecord {
                sequence: from_sql(row.get(0)?),
                ciphertext: row.get(1)?,
                timestamp: from_sql(row.get(2)?),
            });
        }
        Ok(())
    }

    pub fn contains_group(&self, coordination_id: &[u8; 32]) -> Result<bool, DurableError> {
        Ok(self
            .connection
            .query_row(
                "SELECT 1 FROM groups WHERE coordination_id = ?1",
                params![coordination_id.as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    pub fn inactive_ciphertext_bytes(&self) -> Result<usize, DurableError> {
        let bytes: i64 = self.connection.query_row(
            "SELECT COALESCE(SUM(LENGTH(e.ciphertext)), 0) FROM entries e
             JOIN groups g USING (coordination_id) WHERE g.inactive = 1",
            [],
            |row| row.get(0),
        )?;
        usize::try_from(bytes)
            .map_err(|_| DurableError::Corrupt("invalid inactive ciphertext bytes"))
    }

    pub fn inactive_capability(
        &self,
        coordination_id: &[u8; 32],
        capability_id: &[u8; 32],
    ) -> Result<Option<[u8; 32]>, DurableError> {
        let key: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT c.public_key FROM capabilities c JOIN groups g USING (coordination_id)
             WHERE c.coordination_id = ?1 AND c.capability_id = ?2
               AND g.inactive = 1 AND g.revoked_at IS NULL",
                params![coordination_id.as_slice(), capability_id.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        key.map(|bytes| fixed(bytes, "inactive capability key"))
            .transpose()
    }

    pub fn inactive_group(
        &self,
        coordination_id: &[u8; 32],
    ) -> Result<Option<GroupRecord>, DurableError> {
        let mut group = self
            .connection
            .query_row(
                "SELECT coordination_id, permanent_controller_public_key, authorization_generation,
                    next_sequence, revoked_at, registered_at, coordinator_active, last_activity_at
             FROM groups WHERE coordination_id = ?1 AND inactive = 1",
                params![coordination_id.as_slice()],
                |row| {
                    Ok(GroupRecord {
                        coordination_id: row
                            .get::<_, Vec<u8>>(0)?
                            .try_into()
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        permanent_controller_public_key: row
                            .get::<_, Vec<u8>>(1)?
                            .try_into()
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        authorization_generation: from_sql(row.get(2)?),
                        next_sequence: from_sql(row.get(3)?),
                        revoked_at: row.get::<_, Option<i64>>(4)?.map(from_sql),
                        registered_at: from_sql(row.get(5)?),
                        coordinator_active: row.get(6)?,
                        last_activity_at: from_sql(row.get(7)?),
                        capabilities: Vec::new(),
                        entries: Vec::new(),
                    })
                },
            )
            .optional()?;
        if let Some(group) = group.as_mut() {
            self.load_group_contents(group, u64::MAX)?;
        }
        Ok(group)
    }

    pub fn reactivate(
        &mut self,
        coordination_id: &[u8; 32],
        now: u64,
        cutoff: u64,
    ) -> Result<GroupRecord, DurableError> {
        let transaction = self.connection.transaction()?;
        let changed = transaction.execute(
            "UPDATE groups SET inactive = 0, last_activity_at = ?2
             WHERE coordination_id = ?1 AND inactive = 1 AND revoked_at IS NULL",
            params![coordination_id.as_slice(), to_sql(now)],
        )?;
        if changed != 1 {
            return Err(DurableError::Corrupt("inactive group disappeared"));
        }
        transaction.commit()?;
        let mut group = self.connection.query_row(
            "SELECT coordination_id, permanent_controller_public_key, authorization_generation,
                    next_sequence, revoked_at, registered_at, coordinator_active, last_activity_at
             FROM groups WHERE coordination_id = ?1",
            params![coordination_id.as_slice()],
            |row| {
                Ok(GroupRecord {
                    coordination_id: row
                        .get::<_, Vec<u8>>(0)?
                        .try_into()
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    permanent_controller_public_key: row
                        .get::<_, Vec<u8>>(1)?
                        .try_into()
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    authorization_generation: from_sql(row.get(2)?),
                    next_sequence: from_sql(row.get(3)?),
                    revoked_at: row.get::<_, Option<i64>>(4)?.map(from_sql),
                    registered_at: from_sql(row.get(5)?),
                    coordinator_active: row.get(6)?,
                    last_activity_at: from_sql(row.get(7)?),
                    capabilities: Vec::new(),
                    entries: Vec::new(),
                })
            },
        )?;
        self.load_group_contents(&mut group, cutoff)?;
        Ok(group)
    }

    pub fn mark_inactive(&mut self, coordination_id: &[u8; 32]) -> Result<(), DurableError> {
        let changed = self.connection.execute(
            "UPDATE groups SET inactive = 1 WHERE coordination_id = ?1 AND inactive = 0",
            params![coordination_id.as_slice()],
        )?;
        if changed != 1 {
            return Err(DurableError::Corrupt("active group disappeared"));
        }
        Ok(())
    }

    pub fn touch(&mut self, coordination_id: &[u8; 32], now: u64) -> Result<(), DurableError> {
        self.connection.execute(
            "UPDATE groups SET last_activity_at = ?2 WHERE coordination_id = ?1",
            params![coordination_id.as_slice(), to_sql(now)],
        )?;
        Ok(())
    }

    pub fn retired_controller(
        &self,
        coordination_id: &[u8; 32],
    ) -> Result<Option<([u8; 32], bool)>, DurableError> {
        let stored: Option<(Vec<u8>, bool)> = self
            .connection
            .query_row(
                "SELECT permanent_controller_public_key, terminal FROM retired_groups
                 WHERE coordination_id = ?1",
                params![coordination_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        stored
            .map(|(bytes, terminal)| Ok((fixed(bytes, "retired controller key")?, terminal)))
            .transpose()
    }

    /// Writes a group's complete authorization state and drops entries memory
    /// no longer holds. Used for registration, capability replacement,
    /// revocation, and cursor advances.
    pub fn sync_authorization(
        &mut self,
        coordination_id: &[u8; 32],
        group: &GroupAuthorization<'_>,
    ) -> Result<(), DurableError> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO groups (coordination_id, permanent_controller_public_key,
                                 authorization_generation, next_sequence, revoked_at,
                                 registered_at, coordinator_active, last_activity_at, inactive)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0)
             ON CONFLICT (coordination_id) DO UPDATE SET
                 permanent_controller_public_key = excluded.permanent_controller_public_key,
                 authorization_generation = excluded.authorization_generation,
                 next_sequence = excluded.next_sequence,
                 revoked_at = excluded.revoked_at,
                 registered_at = excluded.registered_at,
                 coordinator_active = excluded.coordinator_active,
                 last_activity_at = excluded.last_activity_at,
                 inactive = 0",
            params![
                coordination_id.as_slice(),
                group.permanent_controller_public_key.as_slice(),
                to_sql(group.authorization_generation),
                to_sql(group.next_sequence),
                group.revoked_at.map(to_sql),
                to_sql(group.registered_at),
                group.coordinator_active,
                to_sql(group.last_activity_at),
            ],
        )?;
        transaction.execute(
            "DELETE FROM capabilities WHERE coordination_id = ?1",
            params![coordination_id.as_slice()],
        )?;
        {
            let mut insert = transaction.prepare_cached(
                "INSERT INTO capabilities (coordination_id, capability_id, public_key,
                                           can_append, can_read, can_control, cursor)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            for capability in group.capabilities {
                insert.execute(params![
                    coordination_id.as_slice(),
                    capability.capability_id.as_slice(),
                    capability.public_key.as_slice(),
                    capability.can_append,
                    capability.can_read,
                    capability.can_control,
                    to_sql(capability.cursor),
                ])?;
            }
        }
        transaction.execute(
            "DELETE FROM entries WHERE coordination_id = ?1 AND sequence < ?2",
            params![
                coordination_id.as_slice(),
                to_sql(group.first_live_sequence)
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn append_entry(
        &mut self,
        coordination_id: &[u8; 32],
        next_sequence: u64,
        sequence: u64,
        ciphertext: &[u8],
        timestamp: u64,
    ) -> Result<(), DurableError> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "UPDATE groups SET next_sequence = ?2, last_activity_at = ?3 WHERE coordination_id = ?1",
            params![coordination_id.as_slice(), to_sql(next_sequence), to_sql(timestamp)],
        )?;
        transaction.execute(
            "INSERT INTO entries (coordination_id, sequence, ciphertext, timestamp)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                coordination_id.as_slice(),
                to_sql(sequence),
                ciphertext,
                to_sql(timestamp),
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Mirrors [`crate::group::store::Store::expire_at`]: drops expired
    /// entries and dissolved groups whose draining period has ended.
    pub fn expire(&mut self, cutoff: u64) -> Result<(), DurableError> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "DELETE FROM entries WHERE timestamp < ?1",
            params![to_sql(cutoff)],
        )?;
        transaction.execute(
            "INSERT OR IGNORE INTO retired_groups
             (coordination_id, permanent_controller_public_key, terminal)
             SELECT coordination_id, permanent_controller_public_key,
                    revoked_at IS NOT NULL FROM groups
             WHERE revoked_at IS NOT NULL AND revoked_at < ?1",
            params![to_sql(cutoff)],
        )?;
        transaction.execute(
            "DELETE FROM groups WHERE revoked_at IS NOT NULL AND revoked_at < ?1",
            params![to_sql(cutoff)],
        )?;
        transaction.commit()?;
        Ok(())
    }
}

/// Offline operator action for a registration with no queued ciphertext or
/// coordinator candidates. A retained coordinator log head is never deleted:
/// a future registration of the same ID must continue its signed chain.
pub fn reclaim_empty_group(dir: &Path, coordination_id: &[u8; 32]) -> Result<bool, DurableError> {
    let group_path = dir.join(GROUP_DATABASE);
    let coordinator_path = dir.join(COORDINATOR_DATABASE);
    if !group_path.exists() || !coordinator_path.exists() {
        return Err(DurableError::Corrupt("relay databases are missing"));
    }
    let mut coordinator = open(Some(&coordinator_path))?;
    let group = GroupJournal::open(dir)?.connection;
    let transaction = coordinator.transaction()?;
    let candidate_count: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM candidates WHERE coordination_id = ?1",
        params![coordination_id.as_slice()],
        |row| row.get(0),
    )?;
    if candidate_count != 0 {
        return Ok(false);
    }
    let entry_count: i64 = group.query_row(
        "SELECT COUNT(*) FROM entries WHERE coordination_id = ?1",
        params![coordination_id.as_slice()],
        |row| row.get(0),
    )?;
    if entry_count != 0 {
        return Ok(false);
    }
    group.execute(
        "INSERT OR IGNORE INTO retired_groups
         (coordination_id, permanent_controller_public_key, terminal)
         SELECT coordination_id, permanent_controller_public_key,
                revoked_at IS NOT NULL FROM groups
         WHERE coordination_id = ?1",
        params![coordination_id.as_slice()],
    )?;
    let removed = group.execute(
        "DELETE FROM groups WHERE coordination_id = ?1",
        params![coordination_id.as_slice()],
    )?;
    transaction.commit()?;
    Ok(removed != 0)
}

// MARK: - Coordinator

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateRecord {
    pub sequence: u64,
    pub prior_receipt_hash: [u8; 32],
    pub claimed_base_epoch: u64,
    pub entry_hash: [u8; 32],
    pub signature: [u8; 64],
    pub candidate: Vec<u8>,
    pub timestamp: u64,
    pub submitter_capability_id: [u8; 32],
}

/// A newly signed receipt and its candidate, borrowed for one durable write.
pub struct CandidateWrite<'a> {
    pub sequence: u64,
    pub prior_receipt_hash: [u8; 32],
    pub claimed_base_epoch: u64,
    pub entry_hash: [u8; 32],
    pub signature: [u8; 64],
    pub candidate: &'a [u8],
    pub timestamp: u64,
    pub submitter_capability_id: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogRecord {
    pub coordination_id: [u8; 32],
    pub next_sequence: u64,
    pub receipt_head: [u8; 32],
    pub candidates: Vec<CandidateRecord>,
}

pub struct CoordinatorJournal {
    connection: Connection,
}
