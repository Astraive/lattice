//! SQLite-backed immutable event storage and bounded dependency staging.
//!
//! This crate stores canonical event bytes verbatim. The protocol profile is still
//! a proposal; limits here are local resource bounds, not interoperability claims.

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

/// Largest canonical event byte string accepted by the local store.
pub const MAX_CANONICAL_EVENT_BYTES: usize = 1024 * 1024;
/// Maximum number of parent or missing-dependency references on one event.
pub const MAX_EVENT_DEPENDENCIES: usize = 64;
/// Maximum combined canonical bytes retained in the pending queue.
pub const MAX_PENDING_BYTES: usize = 16 * 1024 * 1024;
/// Maximum number of incomplete events staged for missing dependencies.
pub const MAX_PENDING_EVENTS: usize = 4096;
/// Maximum opaque envelope bytes retained in one outbox row.
pub const MAX_OUTBOX_ENVELOPE_BYTES: usize = MAX_CANONICAL_EVENT_BYTES;
/// Maximum queued outbox entries.
pub const MAX_OUTBOX_EVENTS: usize = 1024;
/// Maximum total opaque envelope bytes retained in the outbox.
pub const MAX_OUTBOX_BYTES: usize = 16 * 1024 * 1024;
/// Maximum entries returned by one outbox page.
pub const MAX_OUTBOX_PAGE_SIZE: usize = 256;

const ID_BYTES: usize = 32;
const SCHEMA_VERSION: i64 = 4;
const MAX_PROTECTED_IDENTITY_BYTES: usize = 4096;
const MAX_PROTECTED_MLS_KEY_BYTES: usize = 4096;

/// A committed event and its parent references.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventRecord {
    pub event_id: [u8; ID_BYTES],
    pub author_id: [u8; ID_BYTES],
    pub author_seq: u64,
    pub canonical_bytes: Vec<u8>,
    pub parents: Vec<[u8; ID_BYTES]>,
}

/// An event staged until its missing dependencies become available.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingEvent {
    pub event_id: [u8; ID_BYTES],
    pub canonical_bytes: Vec<u8>,
    pub missing_dependencies: Vec<[u8; ID_BYTES]>,
}

/// Delivery state of a locally authored envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboxState {
    Queued,
    Forwarded,
    Delivered,
    Failed,
}

/// Durable outbox record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxEntry {
    pub event_id: [u8; ID_BYTES],
    pub envelope_bytes: Vec<u8>,
    pub next_attempt_ms: i64,
    pub attempt_count: u32,
    pub state: OutboxState,
}

/// Result of attempting to commit an authored event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommitOutcome {
    /// A new event and its parent edges were committed.
    Inserted,
    /// The exact event was already present; no stored bytes were changed.
    AlreadyPresent,
    /// This author sequence is already occupied by a different event ID.
    Equivocation { existing_event_id: [u8; ID_BYTES] },
}

/// Storage failures and rejected input.
#[derive(Debug)]
pub enum StoreError {
    Sqlite(rusqlite::Error),
    EmptyCanonicalBytes,
    EventTooLarge { actual: usize, maximum: usize },
    TooManyDependencies { actual: usize, maximum: usize },
    DuplicateDependency,
    InvalidSequence,
    SequenceMismatch { expected: u64, actual: u64 },
    SequenceExhausted,
    EventIdConflict,
    PendingEventLimit,
    PendingByteLimit,
    OutboxEnvelopeTooLarge { actual: usize, maximum: usize },
    OutboxEventLimit,
    OutboxByteLimit,
    OutboxPageLimit,
    OutboxConflict,
    OutboxMissing,
    InvalidOutboxSchedule,
    InvalidOutboxTransition,
    InvalidProtectedIdentity,
    InvalidProtectedMlsKey,
    CorruptData(&'static str),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite(error) => write!(formatter, "SQLite error: {error}"),
            Self::EmptyCanonicalBytes => formatter.write_str("canonical event bytes are empty"),
            Self::EventTooLarge { actual, maximum } => {
                write!(formatter, "event is {actual} bytes; maximum is {maximum}")
            }
            Self::TooManyDependencies { actual, maximum } => write!(
                formatter,
                "event has {actual} dependencies; maximum is {maximum}"
            ),
            Self::DuplicateDependency => {
                formatter.write_str("dependency list contains a duplicate")
            }
            Self::InvalidSequence => formatter.write_str("author sequence must be positive"),
            Self::SequenceMismatch { expected, actual } => write!(
                formatter,
                "author sequence must be {expected}, got {actual}"
            ),
            Self::SequenceExhausted => formatter.write_str("author sequence space is exhausted"),
            Self::EventIdConflict => {
                formatter.write_str("event ID is already associated with different data")
            }
            Self::PendingEventLimit => formatter.write_str("pending event count limit exceeded"),
            Self::PendingByteLimit => formatter.write_str("pending byte limit exceeded"),
            Self::OutboxEnvelopeTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "outbox envelope is {actual} bytes; maximum is {maximum}"
                )
            }
            Self::OutboxEventLimit => formatter.write_str("outbox event limit exceeded"),
            Self::OutboxByteLimit => formatter.write_str("outbox byte limit exceeded"),
            Self::OutboxConflict => {
                formatter.write_str("event already has a different outbox envelope")
            }
            Self::OutboxMissing => formatter.write_str("existing event has no outbox envelope"),
            Self::OutboxPageLimit => formatter.write_str("outbox page limit exceeded"),
            Self::InvalidOutboxSchedule => formatter.write_str("outbox schedule time is invalid"),
            Self::InvalidOutboxTransition => formatter.write_str("invalid outbox state transition"),
            Self::InvalidProtectedIdentity => {
                formatter.write_str("protected identity ciphertext has an invalid length")
            }
            Self::InvalidProtectedMlsKey => {
                formatter.write_str("protected MLS storage key ciphertext has an invalid length")
            }
            Self::CorruptData(message) => write!(formatter, "corrupt storage data: {message}"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

pub type Result<T, E = StoreError> = std::result::Result<T, E>;

/// Durable `SQLite` event store.
pub struct Store {
    connection: Connection,
}

impl Store {
    /// Opens a database, enables `SQLite` durability and foreign-key settings,
    /// and applies all pending schema migrations.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened or migrated, or if its
    /// schema version is newer than this crate supports.
    #[allow(clippy::too_many_lines)]
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()))?;

        let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(StoreError::CorruptData(
                "database schema is newer than this lattice-storage version",
            ));
        }
        if version < 1 {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(
                "CREATE TABLE events (
                    event_id BLOB PRIMARY KEY NOT NULL
                        CHECK(typeof(event_id) = 'blob' AND length(event_id) = 32),
                    author_id BLOB NOT NULL
                        CHECK(typeof(author_id) = 'blob' AND length(author_id) = 32),
                    author_seq INTEGER NOT NULL CHECK(author_seq > 0),
                    canonical_bytes BLOB NOT NULL
                        CHECK(typeof(canonical_bytes) = 'blob'
                            AND length(canonical_bytes) BETWEEN 1 AND 1048576),
                    UNIQUE(author_id, author_seq)
                );
                CREATE TABLE event_parents (
                    event_id BLOB NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
                    parent_id BLOB NOT NULL
                        CHECK(typeof(parent_id) = 'blob' AND length(parent_id) = 32),
                    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
                    PRIMARY KEY(event_id, ordinal),
                    UNIQUE(event_id, parent_id)
                );
                CREATE TABLE pending_events (
                    event_id BLOB PRIMARY KEY NOT NULL
                        CHECK(typeof(event_id) = 'blob' AND length(event_id) = 32),
                    canonical_bytes BLOB NOT NULL
                        CHECK(typeof(canonical_bytes) = 'blob'
                            AND length(canonical_bytes) BETWEEN 1 AND 1048576)
                );
                CREATE TABLE pending_dependencies (
                    pending_id BLOB NOT NULL
                        REFERENCES pending_events(event_id) ON DELETE CASCADE,
                    dependency_id BLOB NOT NULL
                        CHECK(typeof(dependency_id) = 'blob' AND length(dependency_id) = 32),
                    PRIMARY KEY(pending_id, dependency_id)
                );
                CREATE INDEX pending_dependencies_by_dependency
                    ON pending_dependencies(dependency_id);
                PRAGMA user_version = 1;",
            )?;
            transaction.commit()?;
        }
        if version < 2 {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(
                "CREATE TABLE outbox (
                    event_id BLOB PRIMARY KEY NOT NULL
                        REFERENCES events(event_id) ON DELETE CASCADE,
                    envelope_bytes BLOB NOT NULL
                        CHECK(typeof(envelope_bytes) = 'blob'
                            AND length(envelope_bytes) BETWEEN 1 AND 1048576),
                    next_attempt_ms INTEGER NOT NULL CHECK(next_attempt_ms >= 0),
                    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
                    state TEXT NOT NULL
                        CHECK(state IN ('queued', 'forwarded', 'delivered', 'failed'))
                );
                CREATE INDEX outbox_queued_schedule
                    ON outbox(state, next_attempt_ms, event_id);
                PRAGMA user_version = 2;",
            )?;
            transaction.commit()?;
        }
        if version < 3 {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(
                "CREATE TABLE protected_identity (
                    singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
                    ciphertext BLOB NOT NULL
                        CHECK(typeof(ciphertext) = 'blob'
                            AND length(ciphertext) BETWEEN 1 AND 4096)
                );
                PRAGMA user_version = 3;",
            )?;
            transaction.commit()?;
        }
        if version < 4 {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(
                "CREATE TABLE protected_mls_storage_key (
                    singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
                    ciphertext BLOB NOT NULL
                        CHECK(typeof(ciphertext) = 'blob'
                            AND length(ciphertext) BETWEEN 1 AND 4096)
                );
                PRAGMA user_version = 4;",
            )?;
            transaction.commit()?;
        }

        Ok(Self { connection })
    }
    /// Gives a platform provider exclusive access to the `SQLite` connection.
    ///
    /// Intended for one-time provider schema migration before transactions begin.
    ///
    /// # Errors
    ///
    /// Returns the error produced by `action` or by its storage operations.
    pub fn with_connection_mut<T, E>(
        &mut self,
        action: impl FnOnce(&mut Connection) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E>
    where
        E: From<StoreError>,
    {
        action(&mut self.connection)
    }

    /// Loads opaque OS-protected MLS storage key ciphertext.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails or stored data is invalid.
    pub fn load_protected_mls_storage_key(&self) -> Result<Option<Vec<u8>>> {
        self.connection
            .query_row(
                "SELECT ciphertext FROM protected_mls_storage_key WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    /// Persists OS-protected MLS storage key ciphertext once.
    ///
    /// Returns `false` when another initializer already stored the key.
    ///
    /// # Errors
    ///
    /// Returns an error if the ciphertext is outside the permitted bound or the
    /// database write fails.
    pub fn save_protected_mls_storage_key(&mut self, ciphertext: &[u8]) -> Result<bool> {
        if ciphertext.is_empty() || ciphertext.len() > MAX_PROTECTED_MLS_KEY_BYTES {
            return Err(StoreError::InvalidProtectedMlsKey);
        }
        let inserted = self.connection.execute(
            "INSERT OR IGNORE INTO protected_mls_storage_key(singleton, ciphertext)
             VALUES (1, ?1)",
            params![ciphertext],
        )?;
        Ok(inserted == 1)
    }

    /// Atomically stores an authored event and reserves its author sequence.
    ///
    /// Locally authored sequences start at one and advance without gaps. Repeating
    /// an identical insert is idempotent. Reusing an occupied sequence with a
    /// different event ID is reported as equivocation without modifying storage.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid event data, sequence conflicts, or database
    /// failures.
    pub fn commit_authored(
        &mut self,
        author_id: [u8; ID_BYTES],
        event_id: [u8; ID_BYTES],
        seq: u64,
        canonical_bytes: &[u8],
        parents: &[[u8; ID_BYTES]],
    ) -> Result<CommitOutcome> {
        self.with_transaction(|transaction| {
            Self::commit_authored_in_transaction(
                transaction,
                author_id,
                event_id,
                seq,
                canonical_bytes,
                parents,
            )
        })
    }

    /// Atomically stores an authored event and reserves its sequence using an
    /// existing transaction, allowing related state changes to commit together.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid event data, sequence conflicts, or database
    /// failures.
    pub fn commit_authored_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        author_id: [u8; ID_BYTES],
        event_id: [u8; ID_BYTES],
        seq: u64,
        canonical_bytes: &[u8],
        parents: &[[u8; ID_BYTES]],
    ) -> Result<CommitOutcome> {
        commit_event_in_transaction(
            transaction,
            author_id,
            event_id,
            seq,
            canonical_bytes,
            parents,
            true,
            None,
        )
    }

    /// Commits an authored event and its opaque delivery envelope atomically.
    /// A new row begins queued and is not considered delivered.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid event data, outbox bounds, sequence conflicts,
    /// or database failures.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_authored_with_outbox(
        &mut self,
        author_id: [u8; ID_BYTES],
        event_id: [u8; ID_BYTES],
        seq: u64,
        canonical_bytes: &[u8],
        parents: &[[u8; ID_BYTES]],
        envelope_bytes: &[u8],
        next_attempt_ms: i64,
    ) -> Result<CommitOutcome> {
        self.with_transaction(|transaction| {
            Self::commit_authored_with_outbox_in_transaction(
                transaction,
                author_id,
                event_id,
                seq,
                canonical_bytes,
                parents,
                envelope_bytes,
                next_attempt_ms,
            )
        })
    }

    /// Commits an authored event and its outbox envelope in an existing
    /// transaction so it can be committed with related state changes.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid event data, outbox bounds, sequence conflicts,
    /// or database failures.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_authored_with_outbox_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        author_id: [u8; ID_BYTES],
        event_id: [u8; ID_BYTES],
        seq: u64,
        canonical_bytes: &[u8],
        parents: &[[u8; ID_BYTES]],
        envelope_bytes: &[u8],
        next_attempt_ms: i64,
    ) -> Result<CommitOutcome> {
        validate_outbox_envelope(envelope_bytes)?;
        if next_attempt_ms < 0 {
            return Err(StoreError::InvalidOutboxSchedule);
        }
        commit_event_in_transaction(
            transaction,
            author_id,
            event_id,
            seq,
            canonical_bytes,
            parents,
            true,
            Some((envelope_bytes, next_attempt_ms)),
        )
    }

    /// Atomically stores an authenticated received event without requiring a
    /// contiguous local arrival order. Its author sequence must still be positive
    /// and unique; gaps can be reconciled by sync.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid event data, sequence conflicts, or database
    /// failures.
    pub fn commit_received(
        &mut self,
        author_id: [u8; ID_BYTES],
        event_id: [u8; ID_BYTES],
        seq: u64,
        canonical_bytes: &[u8],
        parents: &[[u8; ID_BYTES]],
    ) -> Result<CommitOutcome> {
        self.with_transaction(|transaction| {
            Self::commit_received_in_transaction(
                transaction,
                author_id,
                event_id,
                seq,
                canonical_bytes,
                parents,
            )
        })
    }

    /// Stores an authenticated received event in an existing transaction.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid event data, sequence conflicts, or database
    /// failures.
    pub fn commit_received_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        author_id: [u8; ID_BYTES],
        event_id: [u8; ID_BYTES],
        seq: u64,
        canonical_bytes: &[u8],
        parents: &[[u8; ID_BYTES]],
    ) -> Result<CommitOutcome> {
        commit_event_in_transaction(
            transaction,
            author_id,
            event_id,
            seq,
            canonical_bytes,
            parents,
            false,
            None,
        )
    }

    /// Runs application and provider writes inside one `SQLite` transaction.
    ///
    /// Errors from `action` roll back all writes. The closure error type must
    /// accept a storage error so begin and commit failures are reported there.
    ///
    /// # Errors
    ///
    /// Returns the error produced by `action` or by transaction begin/commit.
    pub fn with_transaction<T, E>(
        &mut self,
        action: impl FnOnce(&rusqlite::Transaction<'_>) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E>
    where
        E: From<StoreError>,
    {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StoreError::from)
            .map_err(E::from)?;
        let value = action(&transaction)?;
        transaction
            .commit()
            .map_err(StoreError::from)
            .map_err(E::from)?;
        Ok(value)
    }

    /// Loads one event, including its ordered parent references.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails or stored event data is invalid.
    pub fn load_event(&self, id: &[u8; ID_BYTES]) -> Result<Option<EventRecord>> {
        load_event_with_connection(&self.connection, id)
    }

    /// Returns the next sequence for a local author, starting at one.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails or the next sequence is exhausted.
    pub fn next_author_sequence(&self, author_id: &[u8; ID_BYTES]) -> Result<u64> {
        let last_seq: Option<i64> = self.connection.query_row(
            "SELECT MAX(author_seq) FROM events WHERE author_id = ?1",
            params![&author_id[..]],
            |row| row.get(0),
        )?;
        match last_seq {
            Some(last) => u64::try_from(last.checked_add(1).ok_or(StoreError::SequenceExhausted)?)
                .map_err(|_| StoreError::SequenceExhausted),
            None => Ok(1),
        }
    }
    /// Returns the next sequence for a local author using an existing transaction.
    ///
    /// Locally authored sequences start at one.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails or the next sequence is exhausted.
    pub fn next_author_sequence_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        author_id: &[u8; ID_BYTES],
    ) -> Result<u64> {
        let last_seq: Option<i64> = transaction.query_row(
            "SELECT MAX(author_seq) FROM events WHERE author_id = ?1",
            params![&author_id[..]],
            |row| row.get(0),
        )?;
        match last_seq {
            Some(last) => u64::try_from(last.checked_add(1).ok_or(StoreError::SequenceExhausted)?)
                .map_err(|_| StoreError::SequenceExhausted),
            None => Ok(1),
        }
    }
    /// Loads the single OS-protected local identity ciphertext, if one is saved.
    ///
    /// `SQLite` receives opaque ciphertext only; plaintext key bytes never cross
    /// this storage API.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails or stored data is invalid.
    pub fn load_protected_identity(&self) -> Result<Option<Vec<u8>>> {
        self.connection
            .query_row(
                "SELECT ciphertext FROM protected_identity WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Atomically saves ciphertext for the local device identity if none exists.
    ///
    /// Returns `true` only for the caller that created the slot. A concurrent or
    /// repeated initialization returns `false` and never replaces the first key.
    ///
    /// # Errors
    ///
    /// Returns an error if the ciphertext is outside the permitted bound or the
    /// database write fails.
    pub fn save_protected_identity(&mut self, ciphertext: &[u8]) -> Result<bool> {
        if ciphertext.is_empty() || ciphertext.len() > MAX_PROTECTED_IDENTITY_BYTES {
            return Err(StoreError::InvalidProtectedIdentity);
        }
        let changed = self.connection.execute(
            "INSERT INTO protected_identity(singleton, ciphertext)
             VALUES (1, ?1)
             ON CONFLICT(singleton) DO NOTHING",
            params![ciphertext],
        )?;
        Ok(changed == 1)
    }

    /// Returns an event-ID-ordered outbox page, optionally after an exclusive ID.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid page size, malformed stored data, or
    /// database failures.
    pub fn list_outbox_page(
        &self,
        after_event_id: Option<[u8; ID_BYTES]>,
        limit: usize,
    ) -> Result<Vec<OutboxEntry>> {
        if limit == 0 || limit > MAX_OUTBOX_PAGE_SIZE {
            return Err(StoreError::OutboxPageLimit);
        }
        let mut statement = self.connection.prepare(
            "SELECT event_id, envelope_bytes, next_attempt_ms, attempt_count, state
             FROM outbox
             WHERE (?1 IS NULL OR event_id > ?1)
             ORDER BY event_id LIMIT ?2",
        )?;
        let after = after_event_id.map(|id| id.to_vec());
        let rows = statement.query_map(
            params![after, i64::try_from(limit).unwrap_or(i64::MAX)],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )?;
        rows.map(|row| {
            let (event_id, envelope_bytes, next_attempt_ms, attempt_count, state) = row?;
            Ok(OutboxEntry {
                event_id: decode_id(event_id)?,
                envelope_bytes,
                next_attempt_ms,
                attempt_count: u32::try_from(attempt_count)
                    .map_err(|_| StoreError::CorruptData("invalid outbox attempt count"))?,
                state: decode_outbox_state(&state)?,
            })
        })
        .collect()
    }

    /// Records local relay/courier forwarding only. This never marks delivery.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid scheduling data, an invalid state transition,
    /// or database failures.
    pub fn mark_forwarded(&mut self, event_id: [u8; ID_BYTES], next_attempt_ms: i64) -> Result<()> {
        if next_attempt_ms < 0 {
            return Err(StoreError::InvalidOutboxSchedule);
        }
        let changed = self.connection.execute(
            "UPDATE outbox
             SET state = 'forwarded', next_attempt_ms = ?2, attempt_count = attempt_count + 1
             WHERE event_id = ?1 AND state IN ('queued', 'forwarded')
               AND attempt_count < 4294967295",
            params![&event_id[..], next_attempt_ms],
        )?;
        if changed == 1 {
            Ok(())
        } else {
            Err(StoreError::InvalidOutboxTransition)
        }
    }

    /// Records a destination's receipt. Only a forwarded envelope can become
    /// delivered; duplicate receipts are idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error if the receipt cannot be applied or the database query
    /// fails.
    pub fn record_destination_receipt(&mut self, event_id: [u8; ID_BYTES]) -> Result<()> {
        let changed = self.connection.execute(
            "UPDATE outbox SET state = 'delivered'
             WHERE event_id = ?1 AND state = 'forwarded'",
            params![&event_id[..]],
        )?;
        if changed == 1 || self.outbox_state(&event_id)? == Some(OutboxState::Delivered) {
            Ok(())
        } else {
            Err(StoreError::InvalidOutboxTransition)
        }
    }

    /// Marks an undelivered envelope failed or expired. Repeating failure is safe.
    ///
    /// # Errors
    ///
    /// Returns an error if the transition is invalid or the database operation
    /// fails.
    pub fn mark_failed(&mut self, event_id: [u8; ID_BYTES]) -> Result<()> {
        let changed = self.connection.execute(
            "UPDATE outbox SET state = 'failed'
             WHERE event_id = ?1 AND state IN ('queued', 'forwarded')",
            params![&event_id[..]],
        )?;
        if changed == 1 || self.outbox_state(&event_id)? == Some(OutboxState::Failed) {
            Ok(())
        } else {
            Err(StoreError::InvalidOutboxTransition)
        }
    }

    fn outbox_state(&self, event_id: &[u8; ID_BYTES]) -> Result<Option<OutboxState>> {
        let state: Option<String> = self
            .connection
            .query_row(
                "SELECT state FROM outbox WHERE event_id = ?1",
                params![&event_id[..]],
                |row| row.get(0),
            )
            .optional()?;
        state.map(|value| decode_outbox_state(&value)).transpose()
    }

    /// Stores or refreshes an incomplete event without changing accepted events.
    ///
    /// Both the event bytes and the total pending queue have explicit local bounds.
    /// Re-inserting the same ID with different bytes is rejected.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid dependencies or limits, conflicting event
    /// bytes, or database failures.
    pub fn store_pending(
        &mut self,
        id: [u8; ID_BYTES],
        canonical_bytes: &[u8],
        missing_deps: &[[u8; ID_BYTES]],
    ) -> Result<()> {
        validate_canonical_bytes(canonical_bytes)?;
        validate_dependencies(missing_deps)?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(accepted_bytes) = transaction
            .query_row(
                "SELECT canonical_bytes FROM events WHERE event_id = ?1",
                params![&id[..]],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
        {
            if accepted_bytes == canonical_bytes {
                transaction.commit()?;
                return Ok(());
            }
            return Err(StoreError::EventIdConflict);
        }

        let existing_bytes: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT canonical_bytes FROM pending_events WHERE event_id = ?1",
                params![&id[..]],
                |row| row.get(0),
            )
            .optional()?;
        if existing_bytes
            .as_ref()
            .is_some_and(|existing| existing.as_slice() != canonical_bytes)
        {
            return Err(StoreError::EventIdConflict);
        }

        let pending_count: i64 =
            transaction.query_row("SELECT COUNT(*) FROM pending_events", [], |row| row.get(0))?;
        if existing_bytes.is_none()
            && usize::try_from(pending_count).unwrap_or(usize::MAX) >= MAX_PENDING_EVENTS
        {
            return Err(StoreError::PendingEventLimit);
        }
        let pending_bytes: i64 = transaction.query_row(
            "SELECT COALESCE(SUM(length(canonical_bytes)), 0) FROM pending_events",
            [],
            |row| row.get(0),
        )?;
        let old_size = existing_bytes.as_ref().map_or(0, Vec::len);
        let next_size = usize::try_from(pending_bytes)
            .unwrap_or(usize::MAX)
            .saturating_sub(old_size)
            .saturating_add(canonical_bytes.len());
        if next_size > MAX_PENDING_BYTES {
            return Err(StoreError::PendingByteLimit);
        }

        transaction.execute(
            "INSERT INTO pending_events(event_id, canonical_bytes)
             VALUES (?1, ?2)
             ON CONFLICT(event_id) DO NOTHING",
            params![&id[..], canonical_bytes],
        )?;
        transaction.execute(
            "DELETE FROM pending_dependencies WHERE pending_id = ?1",
            params![&id[..]],
        )?;
        {
            let mut statement = transaction.prepare(
                "INSERT INTO pending_dependencies(pending_id, dependency_id)
                 VALUES (?1, ?2)",
            )?;
            for dependency_id in missing_deps {
                statement.execute(params![&id[..], &dependency_id[..]])?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    /// Lists pending events in stable ID order with their current dependencies.
    ///
    /// # Errors
    ///
    /// Returns an error if the pending-event query fails or stored data is invalid.
    pub fn list_pending(&self) -> Result<Vec<PendingEvent>> {
        let mut statement = self
            .connection
            .prepare("SELECT event_id, canonical_bytes FROM pending_events ORDER BY event_id")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut pending = Vec::new();
        for row in rows {
            let (event_id, canonical_bytes) = row?;
            let event_id = decode_id(event_id)?;
            let missing_dependencies = load_pending_dependencies(&self.connection, &event_id)?;
            pending.push(PendingEvent {
                event_id,
                canonical_bytes,
                missing_dependencies,
            });
        }
        Ok(pending)
    }

    /// Returns the number of events currently held in the pending queue.
    ///
    /// # Errors
    ///
    /// Returns an error if the count query fails or the result is invalid.
    pub fn pending_count(&self) -> Result<usize> {
        let count: i64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM pending_events", [], |row| row.get(0))?;
        usize::try_from(count).map_err(|_| StoreError::CorruptData("negative pending count"))
    }

    /// Marks a dependency as available and returns newly-ready pending events.
    ///
    /// Returned events remain in the pending queue until the caller commits them
    /// and calls [`Store::resolve_pending`] with each event ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the dependency update or query fails, or stored data is
    /// invalid.
    pub fn resolve_dependency(
        &mut self,
        dependency_id: [u8; ID_BYTES],
    ) -> Result<Vec<PendingEvent>> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let affected = {
            let mut statement = transaction.prepare(
                "SELECT pending_id FROM pending_dependencies
                 WHERE dependency_id = ?1 ORDER BY pending_id",
            )?;
            let rows =
                statement.query_map(params![&dependency_id[..]], |row| row.get::<_, Vec<u8>>(0))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        transaction.execute(
            "DELETE FROM pending_dependencies WHERE dependency_id = ?1",
            params![&dependency_id[..]],
        )?;
        let mut ready = Vec::new();
        for raw_id in affected {
            let event_id = decode_id(raw_id)?;
            let has_dependencies: bool = transaction.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM pending_dependencies WHERE pending_id = ?1
                )",
                params![&event_id[..]],
                |row| row.get(0),
            )?;
            if !has_dependencies {
                let canonical_bytes: Vec<u8> = transaction.query_row(
                    "SELECT canonical_bytes FROM pending_events WHERE event_id = ?1",
                    params![&event_id[..]],
                    |row| row.get(0),
                )?;
                ready.push(PendingEvent {
                    event_id,
                    canonical_bytes,
                    missing_dependencies: Vec::new(),
                });
            }
        }
        transaction.commit()?;
        Ok(ready)
    }

    /// Removes a pending event after it has been accepted or discarded.
    ///
    /// # Errors
    ///
    /// Returns an error if the database update fails.
    pub fn resolve_pending(&mut self, id: [u8; ID_BYTES]) -> Result<bool> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let removed = transaction.execute(
            "DELETE FROM pending_events WHERE event_id = ?1",
            params![&id[..]],
        )? > 0;
        transaction.commit()?;
        Ok(removed)
    }
}
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn commit_event_in_transaction(
    transaction: &rusqlite::Transaction<'_>,
    author_id: [u8; ID_BYTES],
    event_id: [u8; ID_BYTES],
    seq: u64,
    canonical_bytes: &[u8],
    parents: &[[u8; ID_BYTES]],
    require_contiguous_sequence: bool,
    outbox: Option<(&[u8], i64)>,
) -> Result<CommitOutcome> {
    validate_canonical_bytes(canonical_bytes)?;
    validate_dependencies(parents)?;
    let seq_i64 = i64::try_from(seq).map_err(|_| StoreError::InvalidSequence)?;
    if seq_i64 <= 0 {
        return Err(StoreError::InvalidSequence);
    }

    if let Some(existing) = load_event_with_connection(transaction, &event_id)? {
        if existing.author_id == author_id
            && existing.author_seq == seq
            && existing.canonical_bytes.as_slice() == canonical_bytes
            && existing.parents.as_slice() == parents
        {
            if let Some((envelope_bytes, _)) = outbox {
                let existing_envelope: Option<Vec<u8>> = transaction
                    .query_row(
                        "SELECT envelope_bytes FROM outbox WHERE event_id = ?1",
                        params![&event_id[..]],
                        |row| row.get(0),
                    )
                    .optional()?;
                match existing_envelope {
                    Some(existing) if existing.as_slice() == envelope_bytes => {}
                    Some(_) => return Err(StoreError::OutboxConflict),
                    None => return Err(StoreError::OutboxMissing),
                }
            }
            transaction.execute(
                "DELETE FROM pending_events WHERE event_id = ?1",
                params![&event_id[..]],
            )?;
            return Ok(CommitOutcome::AlreadyPresent);
        }
        return Err(StoreError::EventIdConflict);
    }

    let occupied: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT event_id FROM events WHERE author_id = ?1 AND author_seq = ?2",
            params![&author_id[..], seq_i64],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(existing_event_id) = occupied {
        return Ok(CommitOutcome::Equivocation {
            existing_event_id: decode_id(existing_event_id)?,
        });
    }

    if require_contiguous_sequence {
        let last_seq: Option<i64> = transaction.query_row(
            "SELECT MAX(author_seq) FROM events WHERE author_id = ?1",
            params![&author_id[..]],
            |row| row.get(0),
        )?;
        let expected = match last_seq {
            Some(last) => last.checked_add(1).ok_or(StoreError::SequenceExhausted)?,
            None => 1,
        };
        if seq_i64 != expected {
            return Err(StoreError::SequenceMismatch {
                expected: u64::try_from(expected).map_err(|_| StoreError::SequenceExhausted)?,
                actual: seq,
            });
        }
    }

    transaction.execute(
        "INSERT INTO events(event_id, author_id, author_seq, canonical_bytes)
         VALUES (?1, ?2, ?3, ?4)",
        params![&event_id[..], &author_id[..], seq_i64, canonical_bytes],
    )?;
    {
        let mut statement = transaction.prepare(
            "INSERT INTO event_parents(event_id, parent_id, ordinal)
             VALUES (?1, ?2, ?3)",
        )?;
        for (ordinal, parent_id) in parents.iter().enumerate() {
            statement.execute(params![
                &event_id[..],
                &parent_id[..],
                i64::try_from(ordinal).expect("dependency limit fits in i64")
            ])?;
        }
    }
    transaction.execute(
        "DELETE FROM pending_events WHERE event_id = ?1",
        params![&event_id[..]],
    )?;
    if let Some((envelope_bytes, next_attempt_ms)) = outbox {
        let count: i64 =
            transaction.query_row("SELECT COUNT(*) FROM outbox", [], |row| row.get(0))?;
        if usize::try_from(count).unwrap_or(usize::MAX) >= MAX_OUTBOX_EVENTS {
            return Err(StoreError::OutboxEventLimit);
        }
        let total_bytes: i64 = transaction.query_row(
            "SELECT COALESCE(SUM(length(envelope_bytes)), 0) FROM outbox",
            [],
            |row| row.get(0),
        )?;
        if usize::try_from(total_bytes)
            .unwrap_or(usize::MAX)
            .saturating_add(envelope_bytes.len())
            > MAX_OUTBOX_BYTES
        {
            return Err(StoreError::OutboxByteLimit);
        }
        transaction.execute(
            "INSERT INTO outbox(
                event_id, envelope_bytes, next_attempt_ms, attempt_count, state
             ) VALUES (?1, ?2, ?3, 0, 'queued')",
            params![&event_id[..], envelope_bytes, next_attempt_ms],
        )?;
    }
    Ok(CommitOutcome::Inserted)
}

fn validate_canonical_bytes(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() {
        return Err(StoreError::EmptyCanonicalBytes);
    }
    if bytes.len() > MAX_CANONICAL_EVENT_BYTES {
        return Err(StoreError::EventTooLarge {
            actual: bytes.len(),
            maximum: MAX_CANONICAL_EVENT_BYTES,
        });
    }
    Ok(())
}

fn validate_dependencies(dependencies: &[[u8; ID_BYTES]]) -> Result<()> {
    if dependencies.len() > MAX_EVENT_DEPENDENCIES {
        return Err(StoreError::TooManyDependencies {
            actual: dependencies.len(),
            maximum: MAX_EVENT_DEPENDENCIES,
        });
    }
    for (index, dependency) in dependencies.iter().enumerate() {
        if dependencies[..index].contains(dependency) {
            return Err(StoreError::DuplicateDependency);
        }
    }
    Ok(())
}

fn load_event_with_connection(
    connection: &Connection,
    id: &[u8; ID_BYTES],
) -> Result<Option<EventRecord>> {
    let event: Option<(Vec<u8>, i64, Vec<u8>)> = connection
        .query_row(
            "SELECT author_id, author_seq, canonical_bytes
             FROM events WHERE event_id = ?1",
            params![&id[..]],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((author_id, author_seq, canonical_bytes)) = event else {
        return Ok(None);
    };
    let parents = {
        let mut statement = connection.prepare(
            "SELECT parent_id FROM event_parents
             WHERE event_id = ?1 ORDER BY ordinal",
        )?;
        let rows = statement.query_map(params![&id[..]], |row| row.get::<_, Vec<u8>>(0))?;
        rows.map(|row| decode_id(row?))
            .collect::<Result<Vec<_>>>()?
    };
    Ok(Some(EventRecord {
        event_id: *id,
        author_id: decode_id(author_id)?,
        author_seq: u64::try_from(author_seq)
            .map_err(|_| StoreError::CorruptData("invalid author sequence"))?,
        canonical_bytes,
        parents,
    }))
}

fn load_pending_dependencies(
    connection: &Connection,
    pending_id: &[u8; ID_BYTES],
) -> Result<Vec<[u8; ID_BYTES]>> {
    let mut statement = connection.prepare(
        "SELECT dependency_id FROM pending_dependencies
         WHERE pending_id = ?1 ORDER BY dependency_id",
    )?;
    let rows = statement.query_map(params![&pending_id[..]], |row| row.get::<_, Vec<u8>>(0))?;
    rows.map(|row| decode_id(row?)).collect()
}

fn decode_id(bytes: Vec<u8>) -> Result<[u8; ID_BYTES]> {
    bytes
        .try_into()
        .map_err(|_| StoreError::CorruptData("identifier is not 32 bytes"))
}

fn validate_outbox_envelope(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() {
        return Err(StoreError::EmptyCanonicalBytes);
    }
    if bytes.len() > MAX_OUTBOX_ENVELOPE_BYTES {
        return Err(StoreError::OutboxEnvelopeTooLarge {
            actual: bytes.len(),
            maximum: MAX_OUTBOX_ENVELOPE_BYTES,
        });
    }
    Ok(())
}

fn decode_outbox_state(state: &str) -> Result<OutboxState> {
    match state {
        "queued" => Ok(OutboxState::Queued),
        "forwarded" => Ok(OutboxState::Forwarded),
        "delivered" => Ok(OutboxState::Delivered),
        "failed" => Ok(OutboxState::Failed),
        _ => Err(StoreError::CorruptData("invalid outbox state")),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{
        CommitOutcome, MAX_CANONICAL_EVENT_BYTES, MAX_EVENT_DEPENDENCIES, MAX_OUTBOX_EVENTS,
        MAX_PENDING_EVENTS, OutboxState, Store, StoreError,
    };

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    struct TempDatabase(std::path::PathBuf);

    impl TempDatabase {
        fn new() -> Self {
            let nonce = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock is after UNIX epoch")
                .as_nanos();
            Self(std::env::temp_dir().join(format!(
                "lattice-storage-{}-{nanos}-{nonce}.sqlite",
                std::process::id()
            )))
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempDatabase {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            let _ = std::fs::remove_file(format!("{}-wal", self.0.display()));
            let _ = std::fs::remove_file(format!("{}-shm", self.0.display()));
        }
    }

    fn id(value: u8) -> [u8; 32] {
        [value; 32]
    }

    #[test]
    fn identical_event_commit_is_idempotent_and_preserves_bytes() {
        let database = TempDatabase::new();
        let mut store = Store::open(database.path()).expect("open database");
        let author = id(1);
        let event = id(2);
        let parent = id(3);
        let bytes = [0xA1, 0x01, 0x02];

        assert_eq!(
            store
                .commit_authored(author, event, 1, &bytes, &[parent])
                .expect("first commit"),
            CommitOutcome::Inserted
        );
        assert_eq!(
            store
                .commit_authored(author, event, 1, &bytes, &[parent])
                .expect("repeat commit"),
            CommitOutcome::AlreadyPresent
        );
        let stored = store
            .load_event(&event)
            .expect("load event")
            .expect("event exists");
        assert_eq!(stored.canonical_bytes, bytes);
        assert_eq!(stored.parents, [parent]);
    }

    #[test]
    fn protected_identity_ciphertext_is_bounded_atomic_and_durable() {
        let database = TempDatabase::new();
        let ciphertext = [0xA5, 0x7C, 0x11];
        {
            let mut store = Store::open(database.path()).expect("open database");
            assert_eq!(
                store.load_protected_identity().expect("empty identity"),
                None
            );
            assert!(
                store
                    .save_protected_identity(&ciphertext)
                    .expect("save protected identity")
            );
            assert!(
                !store
                    .save_protected_identity(&[0x33, 0x44])
                    .expect("second create must not replace")
            );
            assert_eq!(
                store.load_protected_identity().expect("load identity"),
                Some(ciphertext.to_vec())
            );
        }
        let store = Store::open(database.path()).expect("reopen database");
        assert_eq!(
            store
                .load_protected_identity()
                .expect("identity survives reopen"),
            Some(ciphertext.to_vec())
        );
    }

    #[test]
    fn protected_identity_ciphertext_rejects_invalid_lengths() {
        let database = TempDatabase::new();
        let mut store = Store::open(database.path()).expect("open database");
        assert!(matches!(
            store.save_protected_identity(&[]),
            Err(StoreError::InvalidProtectedIdentity)
        ));
        assert!(matches!(
            store.save_protected_identity(&vec![0; super::MAX_PROTECTED_IDENTITY_BYTES + 1]),
            Err(StoreError::InvalidProtectedIdentity)
        ));
        assert_eq!(
            store
                .load_protected_identity()
                .expect("identity remains absent"),
            None
        );
    }

    #[test]
    fn v1_schema_upgrade_preserves_events_and_adds_outbox_and_identity_storage() {
        let database = TempDatabase::new();
        let event = id(91);
        {
            let mut store = Store::open(database.path()).expect("create latest schema");
            store
                .commit_authored(id(90), event, 1, &[0xA1], &[])
                .expect("save event before downgrade simulation");
        }
        {
            let connection =
                rusqlite::Connection::open(database.path()).expect("open schema for fixture");
            connection
                .execute_batch(
                    "DROP TABLE protected_identity;
                     DROP TABLE protected_mls_storage_key;
                     DROP INDEX outbox_queued_schedule;
                     DROP TABLE outbox;
                     PRAGMA user_version = 1;",
                )
                .expect("restore v1 schema fixture");
        }

        let mut store = Store::open(database.path()).expect("upgrade v1 database");
        assert_eq!(
            store
                .load_event(&event)
                .expect("load migrated event")
                .expect("event survives migration")
                .canonical_bytes,
            [0xA1]
        );
        assert!(
            store
                .save_protected_identity(&[0xCC, 0xDD])
                .expect("new v3 identity slot")
        );
        assert_eq!(
            store.load_protected_identity().expect("load new identity"),
            Some(vec![0xCC, 0xDD])
        );
        assert!(
            store
                .save_protected_mls_storage_key(&[0xAA, 0xBB])
                .expect("store protected MLS key after migration")
        );
        assert_eq!(
            store
                .load_protected_mls_storage_key()
                .expect("load protected MLS key"),
            Some(vec![0xAA, 0xBB])
        );
    }
    #[test]
    fn occupied_author_sequence_reports_equivocation_without_replacement() {
        let database = TempDatabase::new();
        let mut store = Store::open(database.path()).expect("open database");
        let author = id(4);
        let first = id(5);
        let second = id(6);
        let original_bytes = [0x01, 0x02];

        store
            .commit_authored(author, first, 1, &original_bytes, &[])
            .expect("commit original");
        assert_eq!(
            store
                .commit_authored(author, second, 1, &[0x03], &[])
                .expect("detect equivocation"),
            CommitOutcome::Equivocation {
                existing_event_id: first
            }
        );
        assert_eq!(
            store
                .load_event(&first)
                .expect("load original")
                .expect("original exists")
                .canonical_bytes,
            original_bytes
        );
        assert!(
            store
                .load_event(&second)
                .expect("load conflicting ID")
                .is_none()
        );
    }

    #[test]
    fn received_events_allow_gaps_and_preserve_equivocation_evidence() {
        let database = TempDatabase::new();
        let mut store = Store::open(database.path()).expect("open database");
        let author = id(20);
        let sequence_two = id(21);
        let sequence_one = id(22);
        let conflicting_id = id(23);
        let parent = id(24);
        let original_bytes = [0xA2, 0x01, 0x02];

        assert_eq!(
            store
                .commit_received(author, sequence_two, 2, &original_bytes, &[parent])
                .expect("receive sequence two before sequence one"),
            CommitOutcome::Inserted
        );
        assert_eq!(
            store
                .commit_received(author, sequence_two, 2, &original_bytes, &[parent])
                .expect("repeat received event"),
            CommitOutcome::AlreadyPresent
        );
        assert_eq!(
            store
                .commit_received(author, sequence_one, 1, &[0xA1], &[])
                .expect("receive earlier sequence"),
            CommitOutcome::Inserted
        );
        assert_eq!(
            store
                .commit_received(author, conflicting_id, 2, &[0xA2, 0x01, 0x03], &[])
                .expect("detect received equivocation"),
            CommitOutcome::Equivocation {
                existing_event_id: sequence_two
            }
        );
        assert!(matches!(
            store.commit_received(author, sequence_two, 2, &[0xFF], &[parent]),
            Err(StoreError::EventIdConflict)
        ));

        let stored = store
            .load_event(&sequence_two)
            .expect("load sequence two")
            .expect("sequence two remains stored");
        assert_eq!(stored.author_id, author);
        assert_eq!(stored.author_seq, 2);
        assert_eq!(stored.canonical_bytes, original_bytes);
        assert_eq!(stored.parents, [parent]);
        assert!(
            store
                .load_event(&conflicting_id)
                .expect("load conflicting ID")
                .is_none()
        );
    }

    #[test]
    fn transaction_scoped_sequence_reader_observes_uncommitted_event() {
        let database = TempDatabase::new();
        let mut store = Store::open(database.path()).expect("open database");
        let author = id(49);
        store
            .with_connection_mut(|connection| {
                let transaction = connection
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                assert_eq!(
                    Store::next_author_sequence_in_transaction(&transaction, &author)?,
                    1
                );
                transaction.execute(
                    "INSERT INTO events(event_id, author_id, author_seq, canonical_bytes)
                     VALUES (?1, ?2, 1, ?3)",
                    rusqlite::params![&id(48)[..], &author[..], &[0xA1_u8][..]],
                )?;
                assert_eq!(
                    Store::next_author_sequence_in_transaction(&transaction, &author)?,
                    2
                );
                transaction.rollback()?;
                Ok::<_, StoreError>(())
            })
            .expect("read sequence in transaction");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn authored_event_and_outbox_transition_durably_without_false_delivery() {
        let database = TempDatabase::new();
        let author = id(50);
        let event = id(51);
        {
            let mut store = Store::open(database.path()).expect("open database");
            assert_eq!(
                store
                    .next_author_sequence(&author)
                    .expect("next initial sequence"),
                1
            );
            assert_eq!(
                store
                    .commit_authored_with_outbox(
                        author,
                        event,
                        1,
                        &[0xA1],
                        &[],
                        &[0x01, 0x02],
                        100,
                    )
                    .expect("commit event with envelope"),
                CommitOutcome::Inserted
            );
            let queued = store
                .list_outbox_page(None, 10)
                .expect("list queued envelope");
            assert_eq!(queued.len(), 1);
            assert_eq!(queued[0].state, OutboxState::Queued);
            assert_eq!(queued[0].envelope_bytes, [0x01, 0x02]);
            assert_eq!(queued[0].attempt_count, 0);
            assert_eq!(
                store
                    .commit_authored_with_outbox(
                        author,
                        event,
                        1,
                        &[0xA1],
                        &[],
                        &[0x01, 0x02],
                        999,
                    )
                    .expect("repeat identical event and envelope"),
                CommitOutcome::AlreadyPresent
            );

            store
                .mark_forwarded(event, 200)
                .expect("record relay forwarding");
            let forwarded = store
                .list_outbox_page(None, 10)
                .expect("list forwarded envelope");
            assert_eq!(forwarded[0].state, OutboxState::Forwarded);
            assert_eq!(forwarded[0].attempt_count, 1);
            assert!(matches!(
                store.commit_authored_with_outbox(author, event, 1, &[0xA1], &[], &[0x03], 300),
                Err(StoreError::OutboxConflict)
            ));
            assert_eq!(
                store
                    .commit_authored_with_outbox(
                        author,
                        event,
                        1,
                        &[0xA1],
                        &[],
                        &[0x01, 0x02],
                        300,
                    )
                    .expect("repeat identical forwarded envelope"),
                CommitOutcome::AlreadyPresent
            );

            assert!(matches!(
                store.record_destination_receipt(id(99)),
                Err(StoreError::InvalidOutboxTransition)
            ));
        }

        let mut store = Store::open(database.path()).expect("reopen outbox database");
        let forwarded = store
            .list_outbox_page(None, 10)
            .expect("load durable outbox state");
        assert_eq!(forwarded[0].state, OutboxState::Forwarded);
        assert_eq!(forwarded[0].next_attempt_ms, 200);
        store
            .record_destination_receipt(event)
            .expect("record destination receipt");
        assert_eq!(
            store
                .list_outbox_page(None, 10)
                .expect("list delivered envelope")[0]
                .state,
            OutboxState::Delivered
        );
        assert_eq!(
            store
                .next_author_sequence(&author)
                .expect("next sequence after commit"),
            2
        );
        let event_without_outbox = id(52);
        store
            .commit_authored(author, event_without_outbox, 2, &[0xA2], &[])
            .expect("commit event without envelope");
        assert!(matches!(
            store.commit_authored_with_outbox(
                author,
                event_without_outbox,
                2,
                &[0xA2],
                &[],
                &[0x04],
                0
            ),
            Err(StoreError::OutboxMissing)
        ));
        assert_eq!(
            store.list_outbox_page(None, 10).expect("list outbox").len(),
            1
        );
    }

    #[test]
    fn outbox_limit_failure_rolls_back_event_and_sequence_reservation() {
        let database = TempDatabase::new();
        let mut store = Store::open(database.path()).expect("open database");
        let author = id(60);
        for seq in 1..=MAX_OUTBOX_EVENTS {
            let seq = u64::try_from(seq).expect("sequence fits in u64");
            store
                .commit_authored_with_outbox(
                    author,
                    {
                        let mut event_id = [0; 32];
                        event_id[..8].copy_from_slice(&seq.to_be_bytes());
                        event_id
                    },
                    seq,
                    &[0x01],
                    &[],
                    &[0x02],
                    0,
                )
                .expect("fill bounded outbox");
        }

        let excess_event = id(61);
        let next_seq = u64::try_from(MAX_OUTBOX_EVENTS + 1).expect("sequence fits in u64");
        assert!(matches!(
            store.commit_authored_with_outbox(
                author,
                excess_event,
                next_seq,
                &[0x03],
                &[],
                &[0x04],
                0
            ),
            Err(StoreError::OutboxEventLimit)
        ));
        assert!(
            store
                .load_event(&excess_event)
                .expect("load rolled back event")
                .is_none()
        );
        assert_eq!(
            store
                .next_author_sequence(&author)
                .expect("sequence after rollback"),
            next_seq
        );

        let oversized = vec![0; super::MAX_OUTBOX_ENVELOPE_BYTES + 1];
        assert!(matches!(
            store.commit_authored_with_outbox(
                author,
                excess_event,
                next_seq,
                &[0x03],
                &[],
                &oversized,
                0
            ),
            Err(StoreError::OutboxEnvelopeTooLarge { .. })
        ));
        assert!(
            store
                .load_event(&excess_event)
                .expect("load event rejected for oversized envelope")
                .is_none()
        );
    }

    #[test]
    fn failed_outbox_entry_cannot_be_reported_delivered() {
        let database = TempDatabase::new();
        let mut store = Store::open(database.path()).expect("open database");
        let event = id(70);
        store
            .commit_authored_with_outbox(id(69), event, 1, &[0x01], &[], &[0x02], 0)
            .expect("commit event");
        store.mark_failed(event).expect("mark expired event failed");
        assert_eq!(
            store.list_outbox_page(None, 1).expect("list outbox")[0].state,
            OutboxState::Failed
        );
        assert!(matches!(
            store.record_destination_receipt(event),
            Err(StoreError::InvalidOutboxTransition)
        ));
    }

    #[test]
    fn event_size_and_dependency_bounds_are_enforced() {
        let database = TempDatabase::new();
        let mut store = Store::open(database.path()).expect("open database");
        let oversized = vec![0; MAX_CANONICAL_EVENT_BYTES + 1];
        assert!(matches!(
            store.commit_received(id(30), id(31), 1, &oversized, &[]),
            Err(StoreError::EventTooLarge { .. })
        ));

        let excessive_parents = vec![id(32); MAX_EVENT_DEPENDENCIES + 1];
        assert!(matches!(
            store.commit_received(id(30), id(33), 1, &[0x01], &excessive_parents),
            Err(StoreError::TooManyDependencies { .. })
        ));
        assert!(
            store
                .load_event(&id(31))
                .expect("load oversized event")
                .is_none()
        );
        assert!(
            store
                .load_event(&id(33))
                .expect("load event with too many parents")
                .is_none()
        );
    }

    #[test]
    fn composed_event_writes_commit_or_roll_back_with_the_callers_transaction() {
        let database = TempDatabase::new();
        let mut store = Store::open(database.path()).expect("open database");
        store
            .connection
            .execute(
                "CREATE TABLE transaction_marker (marker INTEGER PRIMARY KEY)",
                [],
            )
            .expect("create transaction marker");

        let author = id(40);
        let rolled_back_event = id(41);
        let aborted: super::Result<(), StoreError> = store.with_transaction(|transaction| {
            transaction.execute("INSERT INTO transaction_marker VALUES (1)", [])?;
            Store::commit_authored_in_transaction(
                transaction,
                author,
                rolled_back_event,
                1,
                &[0x01],
                &[],
            )?;
            Err(StoreError::InvalidSequence)
        });
        assert!(matches!(aborted, Err(StoreError::InvalidSequence)));
        assert!(
            store
                .load_event(&rolled_back_event)
                .expect("query rolled-back event")
                .is_none()
        );
        let marker_count: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM transaction_marker", [], |row| {
                row.get(0)
            })
            .expect("query rolled-back marker");
        assert_eq!(marker_count, 0);

        let committed_event = id(42);
        store
            .with_transaction(|transaction| {
                transaction.execute("INSERT INTO transaction_marker VALUES (2)", [])?;
                Store::commit_authored_in_transaction(
                    transaction,
                    author,
                    committed_event,
                    1,
                    &[0x02],
                    &[],
                )?;
                Ok::<_, StoreError>(())
            })
            .expect("commit related writes together");
        assert!(
            store
                .load_event(&committed_event)
                .expect("query committed event")
                .is_some()
        );
        let marker_count: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM transaction_marker", [], |row| {
                row.get(0)
            })
            .expect("query committed marker");
        assert_eq!(marker_count, 1);
    }

    #[test]
    fn authored_commits_still_reject_sequence_gaps() {
        let database = TempDatabase::new();
        let mut store = Store::open(database.path()).expect("open database");
        assert!(matches!(
            store.commit_authored(id(40), id(41), 2, &[0x02], &[]),
            Err(StoreError::SequenceMismatch {
                expected: 1,
                actual: 2
            })
        ));
        assert_eq!(
            store
                .commit_authored(id(40), id(42), 1, &[0x01], &[])
                .expect("commit first authored sequence"),
            CommitOutcome::Inserted
        );
    }

    #[test]
    fn committed_events_survive_reopening_the_database() {
        let database = TempDatabase::new();
        let event = id(8);
        {
            let mut store = Store::open(database.path()).expect("open database");
            store
                .commit_authored(id(7), event, 1, &[0xA2, 0x01, 0x02], &[])
                .expect("commit event");
        }
        let store = Store::open(database.path()).expect("reopen database");
        assert_eq!(
            store
                .load_event(&event)
                .expect("load durable event")
                .expect("event exists")
                .canonical_bytes,
            [0xA2, 0x01, 0x02]
        );
    }

    #[test]
    fn pending_queue_is_bounded_and_dependencies_resolve_atomically() {
        let database = TempDatabase::new();
        let mut store = Store::open(database.path()).expect("open database");
        let dependency = id(9);
        let first = id(10);
        let second = id(11);
        store
            .store_pending(first, &[0x01], &[dependency])
            .expect("store first pending event");
        store
            .store_pending(second, &[0x02], &[dependency])
            .expect("store second pending event");
        assert_eq!(store.pending_count().expect("count pending"), 2);
        let staged = store.list_pending().expect("list pending events");
        assert_eq!(staged.len(), 2);
        assert_eq!(staged[0].canonical_bytes, [0x01]);
        assert_eq!(staged[0].missing_dependencies, [dependency]);
        let ready = store
            .resolve_dependency(dependency)
            .expect("resolve dependency");
        assert_eq!(
            ready
                .iter()
                .map(|pending| pending.event_id)
                .collect::<Vec<_>>(),
            [first, second]
        );
        assert!(store.resolve_pending(first).expect("remove pending event"));
        assert_eq!(store.pending_count().expect("count pending"), 1);

        for index in 1..MAX_PENDING_EVENTS {
            let pending_id = [u8::try_from(index % 255 + 1).expect("byte range"); 32];
            let pending_id = {
                let mut bytes = pending_id;
                bytes[..8].copy_from_slice(
                    &u64::try_from(index)
                        .expect("index fits in u64")
                        .to_be_bytes(),
                );
                bytes
            };
            store
                .store_pending(pending_id, &[0x03], &[])
                .expect("fill pending queue");
        }
        let mut excess_id = id(12);
        excess_id[..8].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(matches!(
            store.store_pending(excess_id, &[0x04], &[]),
            Err(StoreError::PendingEventLimit)
        ));
    }
}
