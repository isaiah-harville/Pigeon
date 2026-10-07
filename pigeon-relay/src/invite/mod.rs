//! Durable, bounded ciphertext inboxes for shareable group invites.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use tokio::sync::mpsc;

use crate::durable::DurableError;
use crate::mailbox::protocol::ServerMsg;

#[cfg(test)]
mod tests;

const DATABASE: &str = "invites.sqlite3";
const MAX_SUBSCRIBERS_PER_MAILBOX: usize = 2;

#[derive(Clone, Debug)]
pub struct Config {
    pub ttl_secs: u64,
    pub max_mailboxes: usize,
    pub max_entries_per_mailbox: usize,
    pub max_entry_bytes: usize,
    pub max_total_bytes: usize,
    pub max_deposits_per_minute: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Envelope {
    pub id: String,
    pub ciphertext: String,
    pub timestamp: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreError {
    AtCapacity,
    InvalidCiphertext,
}

pub struct Store {
    connection: Connection,
    config: Config,
    subscribers: HashMap<[u8; 32], Vec<Subscriber>>,
}

struct Subscriber {
    connection_id: u64,
    tx: mpsc::Sender<ServerMsg>,
}

#[derive(Clone)]
pub struct Service(pub Arc<Mutex<Store>>);

impl Service {
    pub fn open(dir: &Path, config: Config, now: u64) -> Result<Self, DurableError> {
        Ok(Self(Arc::new(Mutex::new(Store::open(dir, config, now)?))))
    }

    pub fn expire(&self, now: u64) {
        self.0
            .lock()
            .unwrap()
            .expire(now)
            .expect("invite expiry failed");
    }

    /// Deposits before sending a receipt or notifying live readers. This lock
    /// also serializes subscriptions with deposits, so no envelope is missed
    /// between registering a reader and fetching its durable backlog.
    pub fn deposit(
        &self,
        mailbox: [u8; 32],
        ciphertext: String,
        now: u64,
    ) -> Result<String, StoreError> {
        let mut store = self.0.lock().unwrap();
        let id = store.deposit(mailbox, ciphertext.clone(), now)?;
        if let Some(subscribers) = store.subscribers.get_mut(&mailbox) {
            subscribers.retain(|subscriber| {
                subscriber
                    .tx
                    .try_send(ServerMsg::Envelope {
                        id: id.clone(),
                        ciphertext: ciphertext.clone(),
                        ts: now,
                    })
                    .is_ok()
            });
        }
        Ok(id)
    }

    pub fn subscribe(
        &self,
        mailbox: [u8; 32],
        connection_id: u64,
        tx: mpsc::Sender<ServerMsg>,
    ) -> bool {
        let mut store = self.0.lock().unwrap();
        if let Some(subscribers) = store.subscribers.get_mut(&mailbox) {
            subscribers.retain(|subscriber| {
                subscriber.connection_id != connection_id && !subscriber.tx.is_closed()
            });
            if subscribers.len() >= MAX_SUBSCRIBERS_PER_MAILBOX {
                return false;
            }
        }
        let pending = store.fetch(mailbox).expect("invite fetch failed");
        if tx.capacity() < pending.len() + 1 {
            return false;
        }
        tx.try_send(ServerMsg::Ok {
            detail: "authenticated".into(),
        })
        .expect("checked channel capacity");
        for envelope in pending {
            tx.try_send(ServerMsg::Envelope {
                id: envelope.id,
                ciphertext: envelope.ciphertext,
                ts: envelope.timestamp,
            })
            .expect("checked channel capacity");
        }
        let subscribers = store.subscribers.entry(mailbox).or_default();
        subscribers.push(Subscriber { connection_id, tx });
        true
    }

    pub fn unsubscribe(&self, mailbox: [u8; 32], connection_id: u64) {
        let mut store = self.0.lock().unwrap();
        if let Some(subscribers) = store.subscribers.get_mut(&mailbox) {
            subscribers.retain(|subscriber| subscriber.connection_id != connection_id);
            if subscribers.is_empty() {
                store.subscribers.remove(&mailbox);
            }
        }
    }

    pub fn ack(&self, mailbox: [u8; 32], id: &str) -> Result<(), StoreError> {
        self.0.lock().unwrap().ack(mailbox, id)
    }
}

impl Store {
    pub fn open(dir: &Path, config: Config, now: u64) -> Result<Self, DurableError> {
        let mut connection = Connection::open(dir.join(DATABASE))?;
        connection.query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()))?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version == 0 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE envelopes (
                    id BLOB PRIMARY KEY NOT NULL,
                    mailbox BLOB NOT NULL,
                    ciphertext TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                ) WITHOUT ROWID;
                CREATE INDEX envelopes_by_mailbox ON envelopes(mailbox, timestamp);
                CREATE INDEX envelopes_by_expiry ON envelopes(expires_at);
                CREATE TABLE rate_windows (
                    scope BLOB PRIMARY KEY NOT NULL,
                    window_start INTEGER NOT NULL,
                    deposits INTEGER NOT NULL
                ) WITHOUT ROWID;",
            )?;
            transaction.pragma_update(None, "user_version", 1)?;
            transaction.commit()?;
        } else if version != 1 {
            return Err(DurableError::UnsupportedSchema(version));
        }
        let mut store = Self {
            connection,
            config,
            subscribers: HashMap::new(),
        };
        store
            .expire(now)
            .map_err(|_| DurableError::Corrupt("invite expiry failed"))?;
        Ok(store)
    }

    pub fn deposit(
        &mut self,
        mailbox: [u8; 32],
        ciphertext: String,
        now: u64,
    ) -> Result<String, StoreError> {
        if ciphertext.is_empty() || ciphertext.len() > self.config.max_entry_bytes {
            return Err(StoreError::InvalidCiphertext);
        }
        self.expire(now)?;
        let transaction = self
            .connection
            .transaction()
            .unwrap_or_else(|error| fail_stop(error.into()));
        let count: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM envelopes WHERE mailbox = ?1",
                params![mailbox.as_slice()],
                |row| row.get(0),
            )
            .unwrap_or_else(|error| fail_stop(error.into()));
        let mailboxes: i64 = transaction
            .query_row("SELECT COUNT(DISTINCT mailbox) FROM envelopes", [], |row| {
                row.get(0)
            })
            .unwrap_or_else(|error| fail_stop(error.into()));
        let bytes: i64 = transaction
            .query_row(
                "SELECT COALESCE(SUM(LENGTH(CAST(ciphertext AS BLOB))), 0) FROM envelopes",
                [],
                |row| row.get(0),
            )
            .unwrap_or_else(|error| fail_stop(error.into()));
        if count as usize >= self.config.max_entries_per_mailbox
            || (count == 0 && mailboxes as usize >= self.config.max_mailboxes)
            || (bytes as usize).saturating_add(ciphertext.len()) > self.config.max_total_bytes
            || !admit_rate(&transaction, &[], self.config.max_deposits_per_minute, now)
            || !admit_rate(
                &transaction,
                &mailbox,
                self.config.max_deposits_per_minute,
                now,
            )
        {
            return Err(StoreError::AtCapacity);
        }
        let mut id = [0_u8; 16];
        rand::thread_rng().fill_bytes(&mut id);
        transaction
            .execute(
                "INSERT INTO envelopes (id, mailbox, ciphertext, timestamp, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    id.as_slice(),
                    mailbox.as_slice(),
                    ciphertext,
                    now as i64,
                    now.saturating_add(self.config.ttl_secs) as i64
                ],
            )
            .unwrap_or_else(|error| fail_stop(error.into()));
        transaction
            .commit()
            .unwrap_or_else(|error| fail_stop(error.into()));
        Ok(hex::encode(id))
    }

    pub fn fetch(&self, mailbox: [u8; 32]) -> Result<Vec<Envelope>, StoreError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, ciphertext, timestamp FROM envelopes WHERE mailbox = ?1
             ORDER BY timestamp, id",
            )
            .unwrap_or_else(|error| fail_stop(error.into()));
        let rows = statement
            .query_map(params![mailbox.as_slice()], |row| {
                let id: Vec<u8> = row.get(0)?;
                Ok(Envelope {
                    id: hex::encode(id),
                    ciphertext: row.get(1)?,
                    timestamp: row.get::<_, i64>(2)? as u64,
                })
            })
            .unwrap_or_else(|error| fail_stop(error.into()));
        Ok(rows
            .map(|row| row.unwrap_or_else(|error| fail_stop(error.into())))
            .collect())
    }

    pub fn ack(&mut self, mailbox: [u8; 32], id: &str) -> Result<(), StoreError> {
        let Some(id) = hex::decode(id).ok().filter(|id| id.len() == 16) else {
            return Ok(());
        };
        self.connection
            .execute(
                "DELETE FROM envelopes WHERE mailbox = ?1 AND id = ?2",
                params![mailbox.as_slice(), id],
            )
            .unwrap_or_else(|error| fail_stop(error.into()));
        Ok(())
    }

    pub fn expire(&mut self, now: u64) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction()
            .unwrap_or_else(|error| fail_stop(error.into()));
        transaction
            .execute(
                "DELETE FROM envelopes WHERE expires_at <= ?1",
                params![now as i64],
            )
            .unwrap_or_else(|error| fail_stop(error.into()));
        transaction
            .execute(
                "DELETE FROM rate_windows WHERE window_start <= ?1",
                params![now.saturating_sub(60) as i64],
            )
            .unwrap_or_else(|error| fail_stop(error.into()));
        transaction
            .commit()
            .unwrap_or_else(|error| fail_stop(error.into()));
        Ok(())
    }
}

fn admit_rate(
    transaction: &rusqlite::Transaction<'_>,
    scope: &[u8],
    limit: usize,
    now: u64,
) -> bool {
    let current: Option<(i64, i64)> = transaction
        .query_row(
            "SELECT window_start, deposits FROM rate_windows WHERE scope = ?1",
            params![scope],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .unwrap_or_else(|error| fail_stop(error.into()));
    let (start, count) = current.unwrap_or((now as i64, 0));
    let (start, count) = if now.saturating_sub(start as u64) >= 60 {
        (now as i64, 0)
    } else {
        (start, count)
    };
    if count as usize >= limit {
        return false;
    }
    transaction.execute(
        "INSERT INTO rate_windows (scope, window_start, deposits) VALUES (?1, ?2, ?3)
         ON CONFLICT(scope) DO UPDATE SET window_start = excluded.window_start, deposits = excluded.deposits",
        params![scope, start, count + 1],
    ).unwrap_or_else(|error| fail_stop(error.into()));
    true
}

fn fail_stop(error: DurableError) -> ! {
    crate::durable::fail_stop(error)
}
