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
    pub last_activity_at: u64,
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
    pub last_activity_at: u64,
    pub coordinator_active: bool,
    pub capabilities: &'a [CapabilityRecord],
    /// Entries below this sequence were dropped from memory.
    pub first_live_sequence: u64,
}

pub struct GroupJournal {
    connection: Connection,
}
