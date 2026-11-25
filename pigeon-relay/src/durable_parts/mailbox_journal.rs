// MARK: - Pairwise mailboxes

pub const MAILBOX_DATABASE: &str = "mailboxes.sqlite3";
const MAILBOX_SCHEMA_VERSION: i64 = 1;

// `seq` preserves deposit order across restarts; envelope ids are only unique,
// not ordered, once the id counter has been reseeded.
const MAILBOX_SCHEMA: &str = "
    CREATE TABLE envelopes (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        mailbox TEXT NOT NULL,
        id TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        UNIQUE (mailbox, id)
    );
    CREATE INDEX envelopes_by_timestamp ON envelopes(timestamp);
";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailboxEnvelopeRecord {
    pub mailbox: String,
    pub id: String,
    pub ciphertext: String,
    pub timestamp: u64,
}

/// Write-through journal for pairwise mailboxes. A `published` receipt is the
/// sender's signal to retire its outbound copy, so the relay copy must survive
/// a restart: it is often the only one while the recipient is offline or its
/// phone is locked.
pub struct MailboxJournal {
    connection: Connection,
}

impl MailboxJournal {
    pub fn open(dir: &Path) -> Result<Self, DurableError> {
        Self::with_connection(open(Some(&dir.join(MAILBOX_DATABASE)))?)
    }

    fn with_connection(mut connection: Connection) -> Result<Self, DurableError> {
        migrate(&mut connection, MAILBOX_SCHEMA, MAILBOX_SCHEMA_VERSION)?;
        Ok(Self { connection })
    }

    /// Every envelope at or after `cutoff`, in deposit order. Expired rows are
    /// deleted on the way in.
    pub fn load(&self, cutoff: u64) -> Result<Vec<MailboxEnvelopeRecord>, DurableError> {
        self.expire(cutoff)?;
        let mut statement = self.connection.prepare(
            "SELECT mailbox, id, ciphertext, timestamp FROM envelopes ORDER BY seq",
        )?;
        let mut rows = statement.query([])?;
        let mut records = Vec::new();
        while let Some(row) = rows.next()? {
            records.push(MailboxEnvelopeRecord {
                mailbox: row.get(0)?,
                id: row.get(1)?,
                ciphertext: row.get(2)?,
                timestamp: from_sql(row.get(3)?),
            });
        }
        Ok(records)
    }

    /// Stores one envelope and removes whatever the in-memory bounds evicted
    /// to make room for it, atomically.
    pub fn deposit(
        &mut self,
        record: &MailboxEnvelopeRecord,
        evicted: &[(String, String)],
    ) -> Result<(), DurableError> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO envelopes (mailbox, id, ciphertext, timestamp) VALUES (?1, ?2, ?3, ?4)",
            params![
                record.mailbox,
                record.id,
                record.ciphertext,
                to_sql(record.timestamp)
            ],
        )?;
        for (mailbox, id) in evicted {
            transaction.execute(
                "DELETE FROM envelopes WHERE mailbox = ?1 AND id = ?2",
                params![mailbox, id],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn ack(&self, mailbox: &str, id: &str) -> Result<(), DurableError> {
        self.connection.execute(
            "DELETE FROM envelopes WHERE mailbox = ?1 AND id = ?2",
            params![mailbox, id],
        )?;
        Ok(())
    }

    pub fn expire(&self, cutoff: u64) -> Result<(), DurableError> {
        self.connection.execute(
            "DELETE FROM envelopes WHERE timestamp < ?1",
            params![to_sql(cutoff)],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod mailbox_journal_tests {
    use super::*;

    fn record(mailbox: &str, id: &str, timestamp: u64) -> MailboxEnvelopeRecord {
        MailboxEnvelopeRecord {
            mailbox: mailbox.into(),
            id: id.into(),
            ciphertext: format!("ct-{id}"),
            timestamp,
        }
    }

    #[test]
    fn envelopes_survive_reopen_in_deposit_order_until_acked_or_expired() {
        let directory = tempfile::tempdir().unwrap();
        {
            let mut journal = MailboxJournal::open(directory.path()).unwrap();
            journal.deposit(&record("aa", "0000000000000009", 100), &[]).unwrap();
            journal.deposit(&record("aa", "0000000000000002", 200), &[]).unwrap();
            journal.deposit(&record("bb", "0000000000000003", 50), &[]).unwrap();
            journal.deposit(&record("aa", "0000000000000004", 300), &[("aa".into(), "0000000000000009".into())]).unwrap();
            journal.ack("aa", "0000000000000002").unwrap();
        }
        let journal = MailboxJournal::open(directory.path()).unwrap();
        assert_eq!(
            journal.load(60).unwrap(),
            vec![record("aa", "0000000000000004", 300)]
        );
        assert!(journal.load(400).unwrap().is_empty());
    }
}
