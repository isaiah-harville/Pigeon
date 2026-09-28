// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! Durable state for group mailboxes and the MLS commit coordinator.
//!
//! The in-memory stores remain the query path. Every successful mutation is
//! written through to SQLite while the owning store's lock is still held, so no
//! client can observe state that is not on disk. A failed write stops the
//! process instead of continuing: otherwise a restart could forget an append the
//! relay already acknowledged or, worse, re-sign a different candidate at a
//! coordinator sequence that clients already hold.
//!
//! The database holds exactly what the relay already holds in memory: opaque
//! ciphertext and MLS candidates, public capability keys, cursors, generations,
//! and timestamps. Expiry and cursor garbage collection are applied lazily on
//! disk, so the database may briefly hold rows memory has dropped; loading
//! re-applies both rules. Pairwise mailboxes stay memory-only because senders
//! retransmit until the recipient acknowledges.
//!
//! SQLite stores signed 64-bit integers. Several persisted values are chosen by
//! clients (for example authorization generations), so `u64` values are stored
//! as bit-preserving `i64` casts rather than range-checked conversions: a large
//! client value must round-trip, never fail a write and stop the relay.

use std::fmt;
use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};

pub const GROUP_DATABASE: &str = "groups.sqlite3";
pub const COORDINATOR_DATABASE: &str = "coordinator.sqlite3";

const GROUP_SCHEMA_VERSION: i64 = 4;
const COORDINATOR_SCHEMA_VERSION: i64 = 1;
const COORDINATOR_KEY: &str = "coordinator_public_key";

const GROUP_SCHEMA: &str = "
    CREATE TABLE groups (
        coordination_id BLOB PRIMARY KEY NOT NULL,
        permanent_controller_public_key BLOB NOT NULL,
        authorization_generation INTEGER NOT NULL,
        next_sequence INTEGER NOT NULL,
        revoked_at INTEGER,
        registered_at INTEGER NOT NULL,
        coordinator_active INTEGER NOT NULL
    ) WITHOUT ROWID;
    CREATE TABLE capabilities (
        coordination_id BLOB NOT NULL
            REFERENCES groups(coordination_id) ON DELETE CASCADE,
        capability_id BLOB NOT NULL,
        public_key BLOB NOT NULL,
        can_append INTEGER NOT NULL,
        can_read INTEGER NOT NULL,
        can_control INTEGER NOT NULL,
        cursor INTEGER NOT NULL,
        PRIMARY KEY (coordination_id, capability_id)
    ) WITHOUT ROWID;
    CREATE TABLE entries (
        coordination_id BLOB NOT NULL
            REFERENCES groups(coordination_id) ON DELETE CASCADE,
        sequence INTEGER NOT NULL,
        ciphertext BLOB NOT NULL,
        timestamp INTEGER NOT NULL,
        PRIMARY KEY (coordination_id, sequence)
    );
    CREATE INDEX entries_by_timestamp ON entries(timestamp);
    CREATE TABLE retired_groups (
        coordination_id BLOB PRIMARY KEY NOT NULL,
        permanent_controller_public_key BLOB NOT NULL,
        terminal INTEGER NOT NULL
    ) WITHOUT ROWID;
";

const COORDINATOR_SCHEMA: &str = "
    CREATE TABLE metadata (
        key TEXT PRIMARY KEY NOT NULL,
        value BLOB NOT NULL
    ) WITHOUT ROWID;
    CREATE TABLE logs (
        coordination_id BLOB PRIMARY KEY NOT NULL,
        next_sequence INTEGER NOT NULL,
        receipt_head BLOB NOT NULL
    ) WITHOUT ROWID;
    CREATE TABLE candidates (
        coordination_id BLOB NOT NULL
            REFERENCES logs(coordination_id) ON DELETE CASCADE,
        sequence INTEGER NOT NULL,
        prior_receipt_hash BLOB NOT NULL,
        claimed_base_epoch INTEGER NOT NULL,
        entry_hash BLOB NOT NULL,
        signature BLOB NOT NULL,
        candidate BLOB NOT NULL,
        timestamp INTEGER NOT NULL,
        submitter_capability_id BLOB NOT NULL,
        PRIMARY KEY (coordination_id, sequence)
    );
    CREATE INDEX candidates_by_timestamp ON candidates(timestamp);
";

#[derive(Debug)]
pub enum DurableError {
    Sqlite(rusqlite::Error),
    Io(std::io::Error),
    UnsupportedSchema(i64),
    CoordinatorKeyMismatch,
    Corrupt(&'static str),
}

impl fmt::Display for DurableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(error) => write!(formatter, "sqlite: {error}"),
            Self::Io(error) => write!(formatter, "io: {error}"),
            Self::UnsupportedSchema(version) => {
                write!(formatter, "unsupported durable schema version {version}")
            }
            Self::CoordinatorKeyMismatch => write!(
                formatter,
                "coordinator signing seed does not match the key that signed the stored \
                 receipt logs; restore the original PIGEON_COORDINATOR_SIGNING_SEED_HEX"
            ),
            Self::Corrupt(what) => write!(formatter, "corrupt durable state: {what}"),
        }
    }
}

impl std::error::Error for DurableError {}

impl From<rusqlite::Error> for DurableError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl From<std::io::Error> for DurableError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Stops the relay after a failed durable write. Called while the store lock is
/// held, so the unpersisted in-memory change is never served to any client.
pub fn fail_stop(error: DurableError) -> ! {
    // Durable errors carry no addresses, keys, or content.
    eprintln!(
        "pigeon-relay: durable state write failed ({error}); stopping so no unpersisted \
         state is served"
    );
    std::process::abort()
}

/// Creates the data directory, readable only by the relay's user.
pub fn prepare_data_dir(dir: &Path) -> Result<(), DurableError> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn open(path: Option<&Path>) -> Result<Connection, DurableError> {
    let connection = match path {
        Some(path) => Connection::open(path)?,
        None => Connection::open_in_memory()?,
    };
    // WAL with FULL synchronization: a commit is on stable storage before the
    // relay replies, so an acknowledged append or signed receipt survives power
    // loss as well as a process restart.
    connection.query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()))?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    Ok(connection)
}

fn migrate(connection: &mut Connection, schema: &str, version: i64) -> Result<(), DurableError> {
    let current: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if current == version {
        return Ok(());
    }
    if current != 0 {
        return Err(DurableError::UnsupportedSchema(current));
    }
    let transaction = connection.transaction()?;
    transaction.execute_batch(schema)?;
    transaction.pragma_update(None, "user_version", version)?;
    transaction.commit()?;
    Ok(())
}

fn to_sql(value: u64) -> i64 {
    value as i64
}

fn from_sql(value: i64) -> u64 {
    value as u64
}

fn fixed<const N: usize>(bytes: Vec<u8>, what: &'static str) -> Result<[u8; N], DurableError> {
    bytes.try_into().map_err(|_| DurableError::Corrupt(what))
}

// MARK: - Group mailboxes

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityRecord {
    pub capability_id: [u8; 32],
    pub public_key: [u8; 32],
    pub can_append: bool,
    pub can_read: bool,
    pub can_control: bool,
    pub cursor: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryRecord {
    pub sequence: u64,
    pub ciphertext: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupRecord {
    pub coordination_id: [u8; 32],
    pub permanent_controller_public_key: [u8; 32],
    pub authorization_generation: u64,
    pub next_sequence: u64,
    pub revoked_at: Option<u64>,
    pub registered_at: u64,
    pub coordinator_active: bool,
    pub capabilities: Vec<CapabilityRecord>,
    pub entries: Vec<EntryRecord>,
}

/// A group's authorization state after a mutation. Entries are written
/// separately by [`GroupJournal::append_entry`].
pub struct GroupAuthorization<'a> {
    pub permanent_controller_public_key: [u8; 32],
    pub authorization_generation: u64,
    pub next_sequence: u64,
    pub revoked_at: Option<u64>,
    pub registered_at: u64,
    pub coordinator_active: bool,
    pub capabilities: &'a [CapabilityRecord],
    /// Entries below this sequence were dropped from memory.
    pub first_live_sequence: u64,
}

pub struct GroupJournal {
    connection: Connection,
}

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
            transaction.pragma_update(None, "user_version", GROUP_SCHEMA_VERSION)?;
            transaction.commit()?;
        }
        migrate(&mut connection, GROUP_SCHEMA, GROUP_SCHEMA_VERSION)?;
        Ok(Self { connection })
    }

    pub fn load(&self, cutoff: u64) -> Result<Vec<GroupRecord>, DurableError> {
        let mut groups = Vec::new();
        let mut statement = self.connection.prepare(
            "SELECT coordination_id, permanent_controller_public_key, authorization_generation,
                    next_sequence, revoked_at, registered_at, coordinator_active
             FROM groups
             WHERE (revoked_at IS NULL OR revoked_at >= ?1)
               AND NOT (revoked_at IS NULL AND next_sequence = 1
                        AND authorization_generation = 0 AND coordinator_active = 0
                        AND registered_at < ?1)
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
                capabilities: Vec::new(),
                entries: Vec::new(),
            });
        }
        for group in &mut groups {
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
            let mut rows =
                entries.query(params![group.coordination_id.as_slice(), to_sql(cutoff)])?;
            while let Some(row) = rows.next()? {
                group.entries.push(EntryRecord {
                    sequence: from_sql(row.get(0)?),
                    ciphertext: row.get(1)?,
                    timestamp: from_sql(row.get(2)?),
                });
            }
        }
        Ok(groups)
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
                                 registered_at, coordinator_active)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT (coordination_id) DO UPDATE SET
                 permanent_controller_public_key = excluded.permanent_controller_public_key,
                 authorization_generation = excluded.authorization_generation,
                 next_sequence = excluded.next_sequence,
                 revoked_at = excluded.revoked_at,
                 registered_at = excluded.registered_at,
                 coordinator_active = excluded.coordinator_active",
            params![
                coordination_id.as_slice(),
                group.permanent_controller_public_key.as_slice(),
                to_sql(group.authorization_generation),
                to_sql(group.next_sequence),
                group.revoked_at.map(to_sql),
                to_sql(group.registered_at),
                group.coordinator_active,
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
            "UPDATE groups SET next_sequence = ?2 WHERE coordination_id = ?1",
            params![coordination_id.as_slice(), to_sql(next_sequence)],
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
             WHERE (revoked_at IS NOT NULL AND revoked_at < ?1)
                OR (revoked_at IS NULL AND next_sequence = 1
                    AND authorization_generation = 0 AND coordinator_active = 0
                    AND registered_at < ?1)",
            params![to_sql(cutoff)],
        )?;
        transaction.execute(
            "DELETE FROM groups WHERE revoked_at IS NOT NULL AND revoked_at < ?1",
            params![to_sql(cutoff)],
        )?;
        transaction.execute(
            "DELETE FROM groups WHERE revoked_at IS NULL AND next_sequence = 1
             AND authorization_generation = 0 AND coordinator_active = 0
             AND registered_at < ?1",
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

impl CoordinatorJournal {
    /// Opens the coordinator database and binds it to `public_key`. Stored
    /// receipt chains were signed by one key; continuing them with another
    /// would break every group's chain, so a mismatch refuses to start.
    pub fn open(dir: &Path, public_key: [u8; 32]) -> Result<Self, DurableError> {
        Self::with_connection(open(Some(&dir.join(COORDINATOR_DATABASE)))?, public_key)
    }

    fn with_connection(
        mut connection: Connection,
        public_key: [u8; 32],
    ) -> Result<Self, DurableError> {
        migrate(
            &mut connection,
            COORDINATOR_SCHEMA,
            COORDINATOR_SCHEMA_VERSION,
        )?;
        let stored: Option<Vec<u8>> = connection
            .query_row(
                "SELECT value FROM metadata WHERE key = ?1",
                params![COORDINATOR_KEY],
                |row| row.get(0),
            )
            .optional()?;
        match stored {
            Some(stored) if stored != public_key => {
                return Err(DurableError::CoordinatorKeyMismatch)
            }
            Some(_) => {}
            None => {
                connection.execute(
                    "INSERT INTO metadata (key, value) VALUES (?1, ?2)",
                    params![COORDINATOR_KEY, public_key.as_slice()],
                )?;
            }
        }
        Ok(Self { connection })
    }

    pub fn load(&self, cutoff: u64) -> Result<Vec<LogRecord>, DurableError> {
        let mut logs = Vec::new();
        let mut statement = self.connection.prepare(
            "SELECT coordination_id, next_sequence, receipt_head
             FROM logs ORDER BY coordination_id",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            logs.push(LogRecord {
                coordination_id: fixed(row.get(0)?, "coordination id")?,
                next_sequence: from_sql(row.get(1)?),
                receipt_head: fixed(row.get(2)?, "receipt head")?,
                candidates: Vec::new(),
            });
        }
        for log in &mut logs {
            let mut candidates = self.connection.prepare_cached(
                "SELECT sequence, prior_receipt_hash, claimed_base_epoch, entry_hash,
                        signature, candidate, timestamp, submitter_capability_id
                 FROM candidates
                 WHERE coordination_id = ?1 AND timestamp >= ?2
                 ORDER BY sequence",
            )?;
            let mut rows =
                candidates.query(params![log.coordination_id.as_slice(), to_sql(cutoff)])?;
            while let Some(row) = rows.next()? {
                log.candidates.push(CandidateRecord {
                    sequence: from_sql(row.get(0)?),
                    prior_receipt_hash: fixed(row.get(1)?, "prior receipt hash")?,
                    claimed_base_epoch: from_sql(row.get(2)?),
                    entry_hash: fixed(row.get(3)?, "entry hash")?,
                    signature: fixed(row.get(4)?, "receipt signature")?,
                    candidate: row.get(5)?,
                    timestamp: from_sql(row.get(6)?),
                    submitter_capability_id: fixed(row.get(7)?, "submitter capability")?,
                });
            }
        }
        Ok(logs)
    }

    /// Persists a newly signed receipt together with the log head it advanced.
    pub fn record_candidate(
        &mut self,
        coordination_id: &[u8; 32],
        next_sequence: u64,
        receipt_head: &[u8; 32],
        candidate: &CandidateWrite<'_>,
    ) -> Result<(), DurableError> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO logs (coordination_id, next_sequence, receipt_head)
             VALUES (?1, ?2, ?3)
             ON CONFLICT (coordination_id) DO UPDATE SET
                 next_sequence = excluded.next_sequence,
                 receipt_head = excluded.receipt_head",
            params![
                coordination_id.as_slice(),
                to_sql(next_sequence),
                receipt_head.as_slice()
            ],
        )?;
        transaction.execute(
            "INSERT INTO candidates (coordination_id, sequence, prior_receipt_hash,
                                     claimed_base_epoch, entry_hash, signature, candidate,
                                     timestamp, submitter_capability_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                coordination_id.as_slice(),
                to_sql(candidate.sequence),
                candidate.prior_receipt_hash.as_slice(),
                to_sql(candidate.claimed_base_epoch),
                candidate.entry_hash.as_slice(),
                candidate.signature.as_slice(),
                candidate.candidate,
                to_sql(candidate.timestamp),
                candidate.submitter_capability_id.as_slice(),
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Drops expired candidates. Log heads are kept forever so a chain never
    /// restarts at sequence 1 after its candidates expire.
    pub fn expire(&mut self, cutoff: u64) -> Result<(), DurableError> {
        self.connection.execute(
            "DELETE FROM candidates WHERE timestamp < ?1",
            params![to_sql(cutoff)],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn legacy_group_migration_preserves_existing_authorization() {
        let directory = tempdir().unwrap();
        let path = directory.path().join(GROUP_DATABASE);
        let connection = Connection::open(&path).unwrap();
        let legacy_schema = GROUP_SCHEMA.replace(
            ",\n        registered_at INTEGER NOT NULL,\n        coordinator_active INTEGER NOT NULL",
            "",
        );
        let legacy_schema = legacy_schema.replace(
            "    CREATE TABLE retired_groups (\n        coordination_id BLOB PRIMARY KEY NOT NULL,\n        permanent_controller_public_key BLOB NOT NULL,\n        terminal INTEGER NOT NULL\n    ) WITHOUT ROWID;\n",
            "",
        );
        connection.execute_batch(&legacy_schema).unwrap();
        connection
            .execute(
                "INSERT INTO groups (coordination_id, permanent_controller_public_key,
             authorization_generation, next_sequence, revoked_at) VALUES (?1, ?2, 0, 1, NULL)",
                params![[9_u8; 32].as_slice(), [1_u8; 32].as_slice()],
            )
            .unwrap();
        connection.pragma_update(None, "user_version", 1).unwrap();
        drop(connection);

        GroupJournal::open(directory.path()).unwrap();
        let connection = Connection::open(&path).unwrap();
        let (registered_at, coordinator_active): (i64, bool) = connection
            .query_row(
                "SELECT registered_at, coordinator_active FROM groups WHERE coordination_id = ?1",
                params![[9_u8; 32].as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(registered_at > 0);
        assert!(coordinator_active);
    }
}
