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
            ",\n        registered_at INTEGER NOT NULL,\n        coordinator_active INTEGER NOT NULL,\n        last_activity_at INTEGER NOT NULL,\n        inactive INTEGER NOT NULL DEFAULT 0",
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
        let (registered_at, coordinator_active, last_activity_at, inactive): (i64, bool, i64, bool) = connection
            .query_row(
                "SELECT registered_at, coordinator_active, last_activity_at, inactive FROM groups WHERE coordination_id = ?1",
                params![[9_u8; 32].as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert!(registered_at > 0);
        assert!(coordinator_active);
        assert!(last_activity_at > 0);
        assert!(!inactive);
    }
}
