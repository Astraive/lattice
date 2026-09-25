//! SQLite-backed immutable event storage and bounded dependency staging.
//!
//! This crate stores canonical event bytes verbatim. The protocol profile is still
//! a proposal; limits here are local resource bounds, not interoperability claims.

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
mod courier_queue;
mod trusted_identities;
pub use courier_queue::{
    CourierQueueEntry, CourierQueueError, CourierQueueReceipt, CourierQueueStatus,
    DEFAULT_COURIER_LIMITS,
};

pub use trusted_identities::TrustedIdentityRecord;

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
/// Maximum committed events returned by one sync-source page.
pub const MAX_EVENT_PAGE_SIZE: usize = 16;
/// Maximum locally created Space Genesis records returned by one page.
pub const MAX_SPACE_GENESIS_PAGE_SIZE: usize = 32;
/// Maximum locally retained text-message rows.
pub const MAX_LOCAL_SPACE_MESSAGES: usize = 4096;
/// Maximum locally retained encrypted text-message bytes.
pub const MAX_LOCAL_SPACE_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum locally retained messages returned by one query.
pub const MAX_LOCAL_SPACE_MESSAGE_PAGE_SIZE: usize = 100;

/// Maximum locally accepted membership transitions per generation.
pub const MAX_SPACE_MEMBERSHIP_TRANSITIONS: usize = 64;
/// Maximum locally recorded generation conflict rows.
pub const MAX_SPACE_MEMBERSHIP_CONFLICTS: usize = 4_096;
const ID_BYTES: usize = 32;
/// Latest `SQLite` schema version understood by this crate.
pub const CURRENT_SCHEMA_VERSION: i64 = 12;
const SCHEMA_VERSION: i64 = CURRENT_SCHEMA_VERSION;
const MAX_PROTECTED_IDENTITY_BYTES: usize = 4096;
const MAX_PROTECTED_MLS_KEY_BYTES: usize = 4096;
const MAX_SPACE_GENESIS_GROUP_ID_BYTES: usize = 256;
const MAX_SPACE_GENESIS_ENCRYPTED_STATE_BYTES: usize = 1024 * 1024;
const MAX_CACHED_SPACE_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_SPACE_MEMBERSHIP_ENCRYPTED_STATE_BYTES: usize = 1024 * 1024;
const MAX_SPACE_WELCOME_BOOTSTRAP_PACKAGE_BYTES: usize = 1024 * 1024;
/// Encrypted local message content and signed-event routing metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedSpaceMessage {
    pub event_id: [u8; ID_BYTES],
    pub space_id: [u8; 16],
    pub group_reference: [u8; 32],
    pub channel_id: [u8; 16],
    pub author_id: [u8; ID_BYTES],
    pub author_seq: u64,
    pub lamport: u64,
    pub encrypted_content: Vec<u8>,
    pub outbox_state: Option<OutboxState>,
}

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

/// Encrypted reducer state associated with a space's Genesis event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpaceGenesisSnapshot {
    pub space_id: [u8; 16],
    pub group_reference: [u8; 32],
    pub group_id: Vec<u8>,
    pub event_id: [u8; 32],
    pub encrypted_state: Vec<u8>,
}

/// AEAD-protected evidence needed to replay one accepted local MLS membership transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpaceMembershipTransitionSnapshot {
    pub space_id: [u8; 16],
    pub group_reference: [u8; 32],
    pub parent_epoch: u64,
    pub policy_revision: u64,
    pub control_event_id: [u8; ID_BYTES],
    pub transition_event_id: [u8; ID_BYTES],
    pub encrypted_state: Vec<u8>,
}

/// Encrypted package retained from an accepted Welcome for durable Space bootstrap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpaceWelcomeBootstrapSnapshot {
    pub space_id: [u8; 16],
    pub group_reference: [u8; 32],
    pub root_event_id: [u8; ID_BYTES],
    pub encrypted_package: Vec<u8>,
}

/// Exact signed control events that established two valid sibling MLS commits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpaceMembershipConflictSnapshot {
    pub space_id: [u8; 16],
    pub group_reference: [u8; 32],
    pub parent_epoch: u64,
    pub first_control_event_id: [u8; ID_BYTES],
    pub second_control_event_id: [u8; ID_BYTES],
}

/// Exclusive keyset cursor for bounded local Space Genesis enumeration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpaceGenesisCursor {
    /// Persisted Space identifier.
    pub space_id: [u8; 16],
    /// Persisted MLS group reference for this Space generation.
    pub group_reference: [u8; 32],
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
    EventPageLimit,
    OutboxConflict,
    OutboxMissing,
    InvalidOutboxSchedule,
    InvalidOutboxTransition,
    InvalidProtectedIdentity,
    InvalidProtectedMlsKey,
    InvalidSpaceGenesisSnapshot,
    InvalidSpaceWelcomeBootstrapSnapshot,
    InvalidSpaceMembershipTransitionSnapshot,
    SpaceMembershipTransitionLimit,
    InvalidSpaceMembershipConflictSnapshot,
    SpaceMembershipConflictLimit,
    CachedSpaceMessageLimit,
    CachedSpaceMessageByteLimit,
    CachedSpaceMessagePageLimit,
    CachedSpaceMessageMissing,
    InvalidCachedSpaceMessage,
    TrustedIdentityConflict,
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
            Self::EventPageLimit => formatter.write_str("event page limit exceeded"),
            Self::InvalidOutboxSchedule => formatter.write_str("outbox schedule time is invalid"),
            Self::InvalidOutboxTransition => formatter.write_str("invalid outbox state transition"),
            Self::InvalidProtectedIdentity => {
                formatter.write_str("protected identity ciphertext has an invalid length")
            }
            Self::InvalidProtectedMlsKey => {
                formatter.write_str("protected MLS storage key ciphertext has an invalid length")
            }
            Self::InvalidSpaceGenesisSnapshot => {
                formatter.write_str("space Genesis snapshot has an invalid length")
            }
            Self::InvalidSpaceMembershipTransitionSnapshot => {
                formatter.write_str("space membership transition snapshot is invalid")
            }
            Self::SpaceMembershipTransitionLimit => {
                formatter.write_str("space membership transition limit exceeded")
            }
            Self::InvalidSpaceMembershipConflictSnapshot => {
                formatter.write_str("space membership conflict snapshot is invalid")
            }
            Self::InvalidSpaceWelcomeBootstrapSnapshot => {
                formatter.write_str("space Welcome bootstrap snapshot is invalid")
            }
            Self::SpaceMembershipConflictLimit => {
                formatter.write_str("space membership conflict limit exceeded")
            }
            Self::CachedSpaceMessageLimit => {
                formatter.write_str("cached Space message count limit exceeded")
            }
            Self::CachedSpaceMessageByteLimit => {
                formatter.write_str("cached Space message byte limit exceeded")
            }
            Self::CachedSpaceMessagePageLimit => {
                formatter.write_str("cached Space message page limit exceeded")
            }
            Self::InvalidCachedSpaceMessage => {
                formatter.write_str("cached Space message is invalid")
            }
            Self::CachedSpaceMessageMissing => {
                formatter.write_str("cached Space message to update was not found")
            }
            Self::TrustedIdentityConflict => formatter.write_str(
                "trusted identity fingerprint is already associated with different bundle bytes",
            ),
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

fn classify_database_error(error: rusqlite::Error) -> StoreError {
    match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if matches!(
                failure.code,
                rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase
            ) =>
        {
            StoreError::CorruptData("SQLite database image is malformed or unsupported")
        }
        error => StoreError::Sqlite(error),
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
        if version < 5 {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(
                "CREATE TABLE space_genesis_snapshots (
                    space_id BLOB NOT NULL
                        CHECK(typeof(space_id) = 'blob' AND length(space_id) = 16),
                    group_reference BLOB NOT NULL
                        CHECK(typeof(group_reference) = 'blob' AND length(group_reference) = 32),
                    group_id BLOB NOT NULL
                        CHECK(typeof(group_id) = 'blob' AND length(group_id) BETWEEN 1 AND 256),
                    event_id BLOB NOT NULL UNIQUE
                        REFERENCES events(event_id) ON DELETE CASCADE
                        CHECK(typeof(event_id) = 'blob' AND length(event_id) = 32),
                    encrypted_state BLOB NOT NULL
                        CHECK(typeof(encrypted_state) = 'blob'
                            AND length(encrypted_state) BETWEEN 1 AND 1048576),
                    PRIMARY KEY(space_id, group_reference)
                );
                PRAGMA user_version = 5;",
            )?;
            transaction.commit()?;
        }
        if version < 6 {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(
                "CREATE TABLE trusted_identities (
                    fingerprint BLOB PRIMARY KEY NOT NULL
                        CHECK(typeof(fingerprint) = 'blob' AND length(fingerprint) = 32),
                    public_bundle BLOB NOT NULL
                        CHECK(typeof(public_bundle) = 'blob' AND length(public_bundle) = 65)
                );
                PRAGMA user_version = 6;",
            )?;
            transaction.commit()?;
        }
        if version < 7 {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(
                "CREATE TABLE cached_space_messages (
                    event_id BLOB PRIMARY KEY NOT NULL
                        REFERENCES events(event_id) ON DELETE CASCADE
                        CHECK(typeof(event_id) = 'blob' AND length(event_id) = 32),
                    space_id BLOB NOT NULL
                        CHECK(typeof(space_id) = 'blob' AND length(space_id) = 16),
                    group_reference BLOB NOT NULL
                        CHECK(typeof(group_reference) = 'blob'
                            AND length(group_reference) = 32),
                    channel_id BLOB NOT NULL
                        CHECK(typeof(channel_id) = 'blob' AND length(channel_id) = 16),
                    author_id BLOB NOT NULL
                        CHECK(typeof(author_id) = 'blob' AND length(author_id) = 32),
                    author_seq INTEGER NOT NULL CHECK(author_seq > 0),
                    lamport INTEGER NOT NULL CHECK(lamport >= 0),
                    encrypted_content BLOB NOT NULL
                        CHECK(typeof(encrypted_content) = 'blob'
                            AND length(encrypted_content) BETWEEN 1 AND 1048576)
                );
                CREATE INDEX cached_space_messages_by_channel
                    ON cached_space_messages(
                        space_id, group_reference, channel_id, lamport,
                        author_id, author_seq, event_id
                    );
                PRAGMA user_version = 7;",
            )?;
            transaction.commit()?;
        }
        if version < 8 {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(
                "CREATE TABLE space_membership_transition_snapshots (
                    space_id BLOB NOT NULL
                        CHECK(typeof(space_id) = 'blob' AND length(space_id) = 16),
                    group_reference BLOB NOT NULL
                        CHECK(typeof(group_reference) = 'blob'
                            AND length(group_reference) = 32),
                    parent_epoch INTEGER NOT NULL CHECK(parent_epoch >= 0),
                    control_event_id BLOB NOT NULL UNIQUE
                        REFERENCES events(event_id) ON DELETE CASCADE
                        CHECK(typeof(control_event_id) = 'blob'
                            AND length(control_event_id) = 32),
                    transition_event_id BLOB NOT NULL UNIQUE
                        REFERENCES events(event_id) ON DELETE CASCADE
                        CHECK(typeof(transition_event_id) = 'blob'
                            AND length(transition_event_id) = 32),
                    policy_revision INTEGER NOT NULL CHECK(policy_revision >= 0),
                    encrypted_state BLOB NOT NULL
                        CHECK(typeof(encrypted_state) = 'blob'
                            AND length(encrypted_state) BETWEEN 1 AND 1048576),
                    PRIMARY KEY(space_id, group_reference, parent_epoch),
                    CHECK(control_event_id <> transition_event_id)
                );
                PRAGMA user_version = 8;",
            )?;
            transaction.commit()?;
        }
        if version < 9 {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(
                "CREATE TABLE space_membership_conflicts (
                    space_id BLOB NOT NULL
                        CHECK(typeof(space_id) = 'blob' AND length(space_id) = 16),
                    group_reference BLOB NOT NULL
                        CHECK(typeof(group_reference) = 'blob'
                            AND length(group_reference) = 32),
                    parent_epoch INTEGER NOT NULL CHECK(parent_epoch >= 0),
                    first_control_event_id BLOB NOT NULL
                        REFERENCES events(event_id) ON DELETE CASCADE
                        CHECK(typeof(first_control_event_id) = 'blob'
                            AND length(first_control_event_id) = 32),
                    second_control_event_id BLOB NOT NULL
                        REFERENCES events(event_id) ON DELETE CASCADE
                        CHECK(typeof(second_control_event_id) = 'blob'
                            AND length(second_control_event_id) = 32),
                    PRIMARY KEY(space_id, group_reference),
                    CHECK(first_control_event_id <> second_control_event_id)
                );
                PRAGMA user_version = 9;",
            )?;
            transaction.commit()?;
        }
        if version < 10 {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(
                "CREATE TABLE space_welcome_bootstrap_snapshots (
                    space_id BLOB NOT NULL
                        CHECK(typeof(space_id) = 'blob' AND length(space_id) = 16),
                    group_reference BLOB NOT NULL
                        CHECK(typeof(group_reference) = 'blob'
                            AND length(group_reference) = 32),
                    root_event_id BLOB NOT NULL UNIQUE
                        REFERENCES events(event_id) ON DELETE CASCADE
                        CHECK(typeof(root_event_id) = 'blob' AND length(root_event_id) = 32),
                    encrypted_package BLOB NOT NULL
                        CHECK(typeof(encrypted_package) = 'blob'
                            AND length(encrypted_package) BETWEEN 1 AND 1048576),
                    PRIMARY KEY(space_id, group_reference)
                );
                PRAGMA user_version = 10;",
            )?;
            transaction.commit()?;
        }
        if version < 11 {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(
                "CREATE TABLE courier_configuration (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
                    max_object_bytes INTEGER NOT NULL CHECK(max_object_bytes BETWEEN 0 AND 16777216),
                    max_peer_bytes INTEGER NOT NULL CHECK(max_peer_bytes BETWEEN 0 AND 16777216),
                    max_peer_items INTEGER NOT NULL CHECK(max_peer_items BETWEEN 0 AND 4096),
                    max_total_bytes INTEGER NOT NULL CHECK(max_total_bytes BETWEEN 0 AND 67108864),
                    max_total_items INTEGER NOT NULL CHECK(max_total_items BETWEEN 0 AND 65536)
                );
                INSERT INTO courier_configuration
                    (singleton, enabled, max_object_bytes, max_peer_bytes,
                     max_peer_items, max_total_bytes, max_total_items)
                    VALUES (1, 0, 1048576, 4194304, 256, 16777216, 4096);
                CREATE TABLE courier_queue (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    peer_id BLOB NOT NULL
                        CHECK(typeof(peer_id) = 'blob' AND length(peer_id) = 16),
                    envelope_id BLOB NOT NULL UNIQUE
                        CHECK(typeof(envelope_id) = 'blob' AND length(envelope_id) = 16),
                    event_id BLOB NOT NULL UNIQUE
                        CHECK(typeof(event_id) = 'blob' AND length(event_id) = 32),
                    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms >= 0),
                    hop_limit INTEGER NOT NULL CHECK(hop_limit BETWEEN 1 AND 65535),
                    remaining_copy_budget INTEGER NOT NULL
                        CHECK(remaining_copy_budget BETWEEN 0 AND hop_limit),
                    traffic_class INTEGER NOT NULL CHECK(traffic_class BETWEEN 0 AND 2),
                    encrypted_opaque_bytes BLOB NOT NULL
                        CHECK(typeof(encrypted_opaque_bytes) = 'blob'
                            AND length(encrypted_opaque_bytes) BETWEEN 1 AND 16777216)
                );
                CREATE INDEX courier_queue_peer_sequence
                    ON courier_queue(peer_id, sequence);
                CREATE INDEX courier_queue_expiry
                    ON courier_queue(expires_at_ms);
                PRAGMA user_version = 11;",
            )?;
            transaction.commit()?;
        }
        if version < 12 {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(
                "CREATE TABLE key_package_lifecycle (
                    key_package_ref BLOB PRIMARY KEY NOT NULL
                        CHECK(typeof(key_package_ref) = 'blob' AND length(key_package_ref) = 32),
                    expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
                    state TEXT NOT NULL CHECK(state IN ('available', 'consumed', 'expired', 'lost'))
                );
                CREATE INDEX key_package_lifecycle_available
                    ON key_package_lifecycle(state, expires_at);
                PRAGMA user_version = 12;",
            )?;
            transaction.commit()?;
        }

        Ok(Self { connection })
    }

    /// Opens an existing database without applying migrations or changing
    /// persistent settings.
    ///
    /// Use this for diagnostic or inspection commands that must not upgrade
    /// user data as a side effect.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened read-only.
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self> {
        let connection =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        Ok(Self { connection })
    }

    /// Reports the `SQLite` application schema version without changing it.
    ///
    /// # Errors
    ///
    /// Returns an error if `PRAGMA user_version` cannot be read.
    pub fn schema_version(&self) -> Result<i64> {
        self.connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(classify_database_error)
    }

    /// Runs `SQLite`'s bounded quick integrity check.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` cannot perform the check.
    pub fn integrity_check(&self) -> Result<bool> {
        let status: String = self
            .connection
            .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
            .map_err(classify_database_error)?;
        Ok(status == "ok")
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
    /// Records a locally published MLS `KeyPackage` in the same transaction as
    /// its `OpenMLS` private key.
    ///
    /// # Errors
    ///
    /// Returns an error if the reference or expiry is invalid, the reference
    /// was already tracked, or `SQLite` rejects the write.
    pub fn record_key_package_in_transaction(
        transaction: &Transaction<'_>,
        key_package_ref: &[u8; ID_BYTES],
        expires_at: u64,
    ) -> Result<()> {
        let expires_at = i64::try_from(expires_at)
            .map_err(|_| StoreError::CorruptData("KeyPackage expiry exceeds SQLite range"))?;
        transaction.execute(
            "INSERT INTO key_package_lifecycle(key_package_ref, expires_at, state)
             VALUES (?1, ?2, 'available')",
            params![&key_package_ref[..], expires_at],
        )?;
        Ok(())
    }

    /// Marks a matching locally published `KeyPackage` as consumed.
    ///
    /// A `KeyPackage` supplied by a prior application version may not have an
    /// inventory row; in that case `OpenMLS` remains authoritative and no row is
    /// created.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` rejects the update.
    pub fn consume_key_package_in_transaction(
        transaction: &Transaction<'_>,
        key_package_ref: &[u8; ID_BYTES],
    ) -> Result<bool> {
        Ok(transaction.execute(
            "UPDATE key_package_lifecycle SET state = 'consumed'
             WHERE key_package_ref = ?1 AND state = 'available'",
            params![&key_package_ref[..]],
        )? > 0)
    }
    /// Removes a package that can no longer be delivered from the available
    /// inventory.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` rejects the update.
    pub fn lose_key_package_in_transaction(
        transaction: &Transaction<'_>,
        key_package_ref: &[u8; ID_BYTES],
    ) -> Result<bool> {
        Ok(transaction.execute(
            "UPDATE key_package_lifecycle SET state = 'lost'
             WHERE key_package_ref = ?1 AND state = 'available'",
            params![&key_package_ref[..]],
        )? > 0)
    }

    /// Counts unexpired locally published packages available for one-time use.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn available_key_package_count(&mut self, now: u64) -> Result<usize> {
        let now = i64::try_from(now)
            .map_err(|_| StoreError::CorruptData("current time exceeds SQLite range"))?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "UPDATE key_package_lifecycle SET state = 'expired'
             WHERE state = 'available' AND expires_at <= ?1",
            params![now],
        )?;
        let count: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM key_package_lifecycle
             WHERE state = 'available' AND expires_at > ?1",
            params![now],
            |row| row.get(0),
        )?;
        transaction.commit()?;
        usize::try_from(count)
            .map_err(|_| StoreError::CorruptData("invalid KeyPackage inventory count"))
    }

    /// Saves an encrypted space Genesis snapshot inside its event's transaction.
    ///
    /// The referenced Genesis event must already exist in this transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the group ID or encrypted state is outside its
    /// permitted bounds, the event row is missing, a key is already stored, or
    /// the database write fails.
    pub fn save_space_genesis_snapshot_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        snapshot: &SpaceGenesisSnapshot,
    ) -> Result<()> {
        if snapshot.group_id.is_empty()
            || snapshot.group_id.len() > MAX_SPACE_GENESIS_GROUP_ID_BYTES
            || snapshot.encrypted_state.is_empty()
            || snapshot.encrypted_state.len() > MAX_SPACE_GENESIS_ENCRYPTED_STATE_BYTES
        {
            return Err(StoreError::InvalidSpaceGenesisSnapshot);
        }
        transaction.execute(
            "INSERT INTO space_genesis_snapshots(
                space_id, group_reference, group_id, event_id, encrypted_state
            ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                &snapshot.space_id[..],
                &snapshot.group_reference[..],
                &snapshot.group_id,
                &snapshot.event_id[..],
                &snapshot.encrypted_state
            ],
        )?;
        Ok(())
    }
    /// Saves an accepted Welcome bootstrap package in the event transaction.
    ///
    /// The referenced root event must already exist in this transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the ciphertext is outside its permitted bounds, the
    /// root event row is missing, a key or root event is already stored, or
    /// the database write fails.
    pub fn save_space_welcome_bootstrap_snapshot_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        snapshot: &SpaceWelcomeBootstrapSnapshot,
    ) -> Result<()> {
        if snapshot.encrypted_package.is_empty()
            || snapshot.encrypted_package.len() > MAX_SPACE_WELCOME_BOOTSTRAP_PACKAGE_BYTES
        {
            return Err(StoreError::InvalidSpaceWelcomeBootstrapSnapshot);
        }
        transaction.execute(
            "INSERT INTO space_welcome_bootstrap_snapshots(
                space_id, group_reference, root_event_id, encrypted_package
            ) VALUES (?1, ?2, ?3, ?4)",
            params![
                &snapshot.space_id[..],
                &snapshot.group_reference[..],
                &snapshot.root_event_id[..],
                &snapshot.encrypted_package,
            ],
        )?;
        Ok(())
    }
    /// Persists one AEAD-protected accepted membership transition atomically
    /// with the signed control and policy events.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid bounds, a missing event row, the per-space
    /// transition limit, a duplicate epoch, or a `SQLite` failure.
    pub fn save_space_membership_transition_snapshot_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        snapshot: &SpaceMembershipTransitionSnapshot,
    ) -> Result<()> {
        if snapshot.control_event_id == snapshot.transition_event_id
            || snapshot.encrypted_state.is_empty()
            || snapshot.encrypted_state.len() > MAX_SPACE_MEMBERSHIP_ENCRYPTED_STATE_BYTES
        {
            return Err(StoreError::InvalidSpaceMembershipTransitionSnapshot);
        }
        let parent_epoch = i64::try_from(snapshot.parent_epoch)
            .map_err(|_| StoreError::InvalidSpaceMembershipTransitionSnapshot)?;
        let policy_revision = i64::try_from(snapshot.policy_revision)
            .map_err(|_| StoreError::InvalidSpaceMembershipTransitionSnapshot)?;
        let count: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM space_membership_transition_snapshots
             WHERE space_id = ?1 AND group_reference = ?2",
            params![&snapshot.space_id[..], &snapshot.group_reference[..]],
            |row| row.get(0),
        )?;
        if usize::try_from(count).unwrap_or(usize::MAX) >= MAX_SPACE_MEMBERSHIP_TRANSITIONS {
            return Err(StoreError::SpaceMembershipTransitionLimit);
        }
        transaction.execute(
            "INSERT INTO space_membership_transition_snapshots(
                space_id, group_reference, parent_epoch, control_event_id,
                transition_event_id, policy_revision, encrypted_state
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                &snapshot.space_id[..],
                &snapshot.group_reference[..],
                parent_epoch,
                &snapshot.control_event_id[..],
                &snapshot.transition_event_id[..],
                policy_revision,
                &snapshot.encrypted_state,
            ],
        )?;
        Ok(())
    }
    /// Saves one verified competing-Commit record with both signed controls.
    ///
    /// Callers must have validated both exact MLS Commits against the same
    /// locally current parent before invoking this transaction helper.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid metadata, missing control events, duplicate
    /// generation state, the global row limit, or a `SQLite` write failure.
    pub fn save_space_membership_conflict_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        snapshot: &SpaceMembershipConflictSnapshot,
    ) -> Result<()> {
        if snapshot.first_control_event_id == snapshot.second_control_event_id {
            return Err(StoreError::InvalidSpaceMembershipConflictSnapshot);
        }
        let parent_epoch = i64::try_from(snapshot.parent_epoch)
            .map_err(|_| StoreError::InvalidSpaceMembershipConflictSnapshot)?;
        let count: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM space_membership_conflicts",
            [],
            |row| row.get(0),
        )?;
        if usize::try_from(count).unwrap_or(usize::MAX) >= MAX_SPACE_MEMBERSHIP_CONFLICTS {
            return Err(StoreError::SpaceMembershipConflictLimit);
        }
        transaction.execute(
            "INSERT INTO space_membership_conflicts(
                space_id, group_reference, parent_epoch,
                first_control_event_id, second_control_event_id
            ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                &snapshot.space_id[..],
                &snapshot.group_reference[..],
                parent_epoch,
                &snapshot.first_control_event_id[..],
                &snapshot.second_control_event_id[..],
            ],
        )?;
        Ok(())
    }

    /// Saves one locally encrypted text message in its authored-event transaction.
    ///
    /// # Errors
    ///
    /// Returns an error when message metadata, total cache bounds, foreign keys,
    /// or `SQLite` writes are invalid.
    pub fn save_cached_space_message_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        message: &CachedSpaceMessage,
    ) -> Result<()> {
        if message.encrypted_content.is_empty()
            || message.encrypted_content.len() > MAX_CACHED_SPACE_MESSAGE_BYTES
            || message.author_seq == 0
            || message.author_seq > i64::MAX as u64
            || message.lamport > i64::MAX as u64
        {
            return Err(StoreError::InvalidCachedSpaceMessage);
        }
        let count: i64 =
            transaction.query_row("SELECT COUNT(*) FROM cached_space_messages", [], |row| {
                row.get(0)
            })?;
        if usize::try_from(count).unwrap_or(usize::MAX) >= MAX_LOCAL_SPACE_MESSAGES {
            return Err(StoreError::CachedSpaceMessageLimit);
        }
        let bytes: i64 = transaction.query_row(
            "SELECT COALESCE(SUM(length(encrypted_content)), 0)
             FROM cached_space_messages",
            [],
            |row| row.get(0),
        )?;
        if usize::try_from(bytes)
            .unwrap_or(usize::MAX)
            .saturating_add(message.encrypted_content.len())
            > MAX_LOCAL_SPACE_MESSAGE_BYTES
        {
            return Err(StoreError::CachedSpaceMessageByteLimit);
        }
        transaction.execute(
            "INSERT INTO cached_space_messages(
                event_id, space_id, group_reference, channel_id, author_id,
                author_seq, lamport, encrypted_content
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                &message.event_id[..],
                &message.space_id[..],
                &message.group_reference[..],
                &message.channel_id[..],
                &message.author_id[..],
                i64::try_from(message.author_seq)
                    .map_err(|_| StoreError::InvalidCachedSpaceMessage)?,
                i64::try_from(message.lamport)
                    .map_err(|_| StoreError::InvalidCachedSpaceMessage)?,
                &message.encrypted_content
            ],
        )?;
        Ok(())
    }

    /// Replaces one cached message projection while retaining its immutable
    /// source event metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the source row does not match this Space/channel,
    /// the encrypted content exceeds cache bounds, or the update fails.
    pub fn replace_cached_space_message_content_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        event_id: &[u8; ID_BYTES],
        space_id: &[u8; 16],
        group_reference: &[u8; 32],
        channel_id: &[u8; 16],
        encrypted_content: &[u8],
    ) -> Result<()> {
        if encrypted_content.is_empty() || encrypted_content.len() > MAX_CACHED_SPACE_MESSAGE_BYTES
        {
            return Err(StoreError::InvalidCachedSpaceMessage);
        }
        let old_bytes: Option<i64> = transaction
            .query_row(
                "SELECT length(encrypted_content) FROM cached_space_messages
                 WHERE event_id = ?1 AND space_id = ?2
                   AND group_reference = ?3 AND channel_id = ?4",
                params![
                    &event_id[..],
                    &space_id[..],
                    &group_reference[..],
                    &channel_id[..],
                ],
                |row| row.get(0),
            )
            .optional()?;
        let old_bytes = old_bytes.ok_or(StoreError::CachedSpaceMessageMissing)?;
        let total_bytes: i64 = transaction.query_row(
            "SELECT COALESCE(SUM(length(encrypted_content)), 0)
             FROM cached_space_messages",
            [],
            |row| row.get(0),
        )?;
        let retained = usize::try_from(total_bytes.checked_sub(old_bytes).ok_or(
            StoreError::CorruptData("cached Space message byte total is inconsistent"),
        )?)
        .map_err(|_| StoreError::CorruptData("cached Space message byte total is negative"))?;
        if retained.saturating_add(encrypted_content.len()) > MAX_LOCAL_SPACE_MESSAGE_BYTES {
            return Err(StoreError::CachedSpaceMessageByteLimit);
        }
        let changed = transaction.execute(
            "UPDATE cached_space_messages SET encrypted_content = ?1
             WHERE event_id = ?2 AND space_id = ?3
               AND group_reference = ?4 AND channel_id = ?5",
            params![
                encrypted_content,
                &event_id[..],
                &space_id[..],
                &group_reference[..],
                &channel_id[..],
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::CachedSpaceMessageMissing);
        }
        Ok(())
    }

    /// Checks whether one generation/channel retains a text projection.
    ///
    /// # Errors
    ///
    /// Returns an error if the lookup fails.
    pub fn has_cached_space_message_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        event_id: &[u8; ID_BYTES],
        space_id: &[u8; 16],
        group_reference: &[u8; 32],
        channel_id: &[u8; 16],
    ) -> Result<bool> {
        transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM cached_space_messages
                    WHERE event_id = ?1 AND space_id = ?2
                      AND group_reference = ?3 AND channel_id = ?4
                )",
                params![
                    &event_id[..],
                    &space_id[..],
                    &group_reference[..],
                    &channel_id[..],
                ],
                |row| row.get(0),
            )
            .map_err(StoreError::from)
    }

    /// Returns the newest bounded local message cache for one channel, oldest first.
    ///
    /// This is a local text projection, not a synchronized transcript. It may
    /// contain locally authored and received messages, and is limited to the
    /// latest bounded page.
    ///
    /// # Errors
    ///
    /// Returns an error when the requested page is invalid or stored metadata
    /// is malformed.
    pub fn list_cached_space_messages(
        &self,
        space_id: &[u8; 16],
        group_reference: &[u8; 32],
        channel_id: &[u8; 16],
        limit: usize,
    ) -> Result<Vec<CachedSpaceMessage>> {
        if limit == 0 || limit > MAX_LOCAL_SPACE_MESSAGE_PAGE_SIZE {
            return Err(StoreError::CachedSpaceMessagePageLimit);
        }
        self.list_cached_space_messages_with_limit(space_id, group_reference, channel_id, limit)
    }
    /// Lists every cached message in one channel for bounded offline search.
    ///
    /// The result is capped by the store-wide [`MAX_LOCAL_SPACE_MESSAGES`] row
    /// limit and encrypted-content byte quota.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails, stored metadata is malformed, or
    /// `SQLite` cannot represent the bounded result limit.
    pub fn list_all_cached_space_messages(
        &self,
        space_id: &[u8; 16],
        group_reference: &[u8; 32],
        channel_id: &[u8; 16],
    ) -> Result<Vec<CachedSpaceMessage>> {
        self.list_cached_space_messages_with_limit(
            space_id,
            group_reference,
            channel_id,
            MAX_LOCAL_SPACE_MESSAGES,
        )
    }
    fn list_cached_space_messages_with_limit(
        &self,
        space_id: &[u8; 16],
        group_reference: &[u8; 32],
        channel_id: &[u8; 16],
        limit: usize,
    ) -> Result<Vec<CachedSpaceMessage>> {
        let limit = i64::try_from(limit).map_err(|_| StoreError::CachedSpaceMessagePageLimit)?;
        let mut statement = self.connection.prepare(
            "SELECT m.event_id, m.space_id, m.group_reference, m.channel_id,
                    m.author_id, m.author_seq, m.lamport, m.encrypted_content, o.state
             FROM cached_space_messages AS m
             LEFT JOIN outbox AS o ON o.event_id = m.event_id
             WHERE m.space_id = ?1 AND m.group_reference = ?2 AND m.channel_id = ?3
             ORDER BY m.lamport DESC, m.author_id DESC, m.author_seq DESC, m.event_id DESC
             LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![&space_id[..], &group_reference[..], &channel_id[..], limit],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                ))
            },
        )?;
        let mut messages = rows
            .map(|row| {
                let (
                    event_id,
                    space_id,
                    group_reference,
                    channel_id,
                    author_id,
                    author_seq,
                    lamport,
                    encrypted_content,
                    outbox_state,
                ) = row?;
                if encrypted_content.is_empty()
                    || encrypted_content.len() > MAX_CACHED_SPACE_MESSAGE_BYTES
                    || author_seq <= 0
                    || lamport < 0
                {
                    return Err(StoreError::CorruptData("invalid cached Space message"));
                }
                Ok(CachedSpaceMessage {
                    event_id: event_id
                        .try_into()
                        .map_err(|_| StoreError::CorruptData("invalid cached message event ID"))?,
                    space_id: space_id
                        .try_into()
                        .map_err(|_| StoreError::CorruptData("invalid cached message Space ID"))?,
                    group_reference: group_reference.try_into().map_err(|_| {
                        StoreError::CorruptData("invalid cached message group reference")
                    })?,
                    channel_id: channel_id.try_into().map_err(|_| {
                        StoreError::CorruptData("invalid cached message channel ID")
                    })?,
                    author_id: author_id
                        .try_into()
                        .map_err(|_| StoreError::CorruptData("invalid cached message author ID"))?,
                    author_seq: u64::try_from(author_seq)
                        .map_err(|_| StoreError::CorruptData("invalid cached message sequence"))?,
                    lamport: u64::try_from(lamport)
                        .map_err(|_| StoreError::CorruptData("invalid cached message Lamport"))?,
                    encrypted_content,
                    outbox_state: outbox_state
                        .as_deref()
                        .map(decode_outbox_state)
                        .transpose()?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        messages.reverse();
        Ok(messages)
    }

    /// Lists local Space Genesis keys in bounded, stable keyset pages.
    ///
    /// Pass the final cursor from one page to continue after it. Rows are
    /// ordered by Space ID and then MLS group reference.
    ///
    /// # Errors
    ///
    /// Returns an error if the page limit cannot be represented by `SQLite`, the
    /// query fails, or stored keys are malformed.
    pub fn list_space_genesis_page(
        &self,
        after: Option<SpaceGenesisCursor>,
    ) -> Result<Vec<SpaceGenesisCursor>> {
        let after_space_id = after.map(|cursor| cursor.space_id);
        let after_group_reference = after.map(|cursor| cursor.group_reference);
        let page_limit = i64::try_from(MAX_SPACE_GENESIS_PAGE_SIZE)
            .map_err(|_| StoreError::CorruptData("invalid Space Genesis page limit"))?;
        let mut statement = self.connection.prepare(
            "SELECT space_id, group_reference
             FROM space_genesis_snapshots
             WHERE (?1 IS NULL OR (space_id, group_reference) > (?1, ?2))
             ORDER BY space_id, group_reference
             LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![
                after_space_id.as_ref().map(|space_id| &space_id[..]),
                after_group_reference
                    .as_ref()
                    .map(|group_reference| &group_reference[..]),
                page_limit
            ],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )?;
        rows.map(|row| {
            let (space_id, group_reference) = row?;
            Ok(SpaceGenesisCursor {
                space_id: space_id.try_into().map_err(|_| {
                    StoreError::CorruptData("invalid space Genesis snapshot space ID")
                })?,
                group_reference: group_reference.try_into().map_err(|_| {
                    StoreError::CorruptData("invalid space Genesis snapshot group reference")
                })?,
            })
        })
        .collect()
    }

    /// Loads and validates a snapshot for one space and MLS group reference.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails or the stored snapshot is
    /// malformed.
    pub fn load_space_genesis_snapshot(
        &self,
        space_id: &[u8; 16],
        group_reference: &[u8; 32],
    ) -> Result<Option<SpaceGenesisSnapshot>> {
        let stored = self
            .connection
            .query_row(
                "SELECT space_id, group_reference, group_id, event_id, encrypted_state
                 FROM space_genesis_snapshots
                 WHERE space_id = ?1 AND group_reference = ?2",
                params![&space_id[..], &group_reference[..]],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((space_id, group_reference, group_id, event_id, encrypted_state)) = stored else {
            return Ok(None);
        };

        let space_id = space_id
            .try_into()
            .map_err(|_| StoreError::CorruptData("invalid space Genesis snapshot space ID"))?;
        let group_reference = group_reference.try_into().map_err(|_| {
            StoreError::CorruptData("invalid space Genesis snapshot group reference")
        })?;
        let event_id = event_id
            .try_into()
            .map_err(|_| StoreError::CorruptData("invalid space Genesis snapshot event ID"))?;
        if group_id.is_empty() || group_id.len() > MAX_SPACE_GENESIS_GROUP_ID_BYTES {
            return Err(StoreError::CorruptData(
                "invalid space Genesis snapshot group ID",
            ));
        }
        if encrypted_state.is_empty()
            || encrypted_state.len() > MAX_SPACE_GENESIS_ENCRYPTED_STATE_BYTES
        {
            return Err(StoreError::CorruptData(
                "invalid space Genesis snapshot encrypted state",
            ));
        }
        Ok(Some(SpaceGenesisSnapshot {
            space_id,
            group_reference,
            group_id,
            event_id,
            encrypted_state,
        }))
    }
    /// Loads and validates a saved Welcome bootstrap package.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails or the stored row is
    /// malformed.
    pub fn load_space_welcome_bootstrap_snapshot(
        &self,
        space_id: &[u8; 16],
        group_reference: &[u8; 32],
    ) -> Result<Option<SpaceWelcomeBootstrapSnapshot>> {
        let stored = self
            .connection
            .query_row(
                "SELECT space_id, group_reference, root_event_id, encrypted_package
                 FROM space_welcome_bootstrap_snapshots
                 WHERE space_id = ?1 AND group_reference = ?2",
                params![&space_id[..], &group_reference[..]],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((space_id, group_reference, root_event_id, encrypted_package)) = stored else {
            return Ok(None);
        };
        let space_id = space_id
            .try_into()
            .map_err(|_| StoreError::CorruptData("invalid Welcome bootstrap space ID"))?;
        let group_reference = group_reference
            .try_into()
            .map_err(|_| StoreError::CorruptData("invalid Welcome bootstrap group reference"))?;
        let root_event_id = root_event_id
            .try_into()
            .map_err(|_| StoreError::CorruptData("invalid Welcome bootstrap root event ID"))?;
        if encrypted_package.is_empty()
            || encrypted_package.len() > MAX_SPACE_WELCOME_BOOTSTRAP_PACKAGE_BYTES
        {
            return Err(StoreError::CorruptData(
                "invalid Welcome bootstrap encrypted package",
            ));
        }
        Ok(Some(SpaceWelcomeBootstrapSnapshot {
            space_id,
            group_reference,
            root_event_id,
            encrypted_package,
        }))
    }

    /// Loads the bounded ordered membership transition evidence for one local
    /// Space generation.
    ///
    /// # Errors
    ///
    /// Returns an error when the database query fails, stored row limits are
    /// exceeded, or any field is malformed.
    pub fn list_space_membership_transition_snapshots(
        &self,
        space_id: &[u8; 16],
        group_reference: &[u8; 32],
    ) -> Result<Vec<SpaceMembershipTransitionSnapshot>> {
        let mut statement = self.connection.prepare(
            "SELECT space_id, group_reference, parent_epoch, control_event_id,
                    transition_event_id, policy_revision, encrypted_state
             FROM space_membership_transition_snapshots
             WHERE space_id = ?1 AND group_reference = ?2
             ORDER BY parent_epoch
             LIMIT ?3",
        )?;
        let limit = i64::try_from(MAX_SPACE_MEMBERSHIP_TRANSITIONS + 1)
            .map_err(|_| StoreError::CorruptData("invalid membership transition limit"))?;
        let rows =
            statement.query_map(params![&space_id[..], &group_reference[..], limit], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                ))
            })?;
        let stored = rows.collect::<Result<Vec<_>, _>>()?;
        if stored.len() > MAX_SPACE_MEMBERSHIP_TRANSITIONS {
            return Err(StoreError::CorruptData(
                "too many membership transition snapshots",
            ));
        }
        stored
            .into_iter()
            .map(
                |(
                    stored_space_id,
                    stored_group_reference,
                    parent_epoch,
                    control_event_id,
                    transition_event_id,
                    policy_revision,
                    encrypted_state,
                )| {
                    if parent_epoch < 0
                        || policy_revision < 0
                        || encrypted_state.is_empty()
                        || encrypted_state.len() > MAX_SPACE_MEMBERSHIP_ENCRYPTED_STATE_BYTES
                    {
                        return Err(StoreError::CorruptData(
                            "invalid membership transition snapshot",
                        ));
                    }
                    let space_id = stored_space_id.try_into().map_err(|_| {
                        StoreError::CorruptData("invalid membership transition Space ID")
                    })?;
                    let group_reference = stored_group_reference.try_into().map_err(|_| {
                        StoreError::CorruptData("invalid membership transition group reference")
                    })?;
                    let control_event_id = control_event_id.try_into().map_err(|_| {
                        StoreError::CorruptData("invalid membership control event ID")
                    })?;
                    let transition_event_id = transition_event_id.try_into().map_err(|_| {
                        StoreError::CorruptData("invalid membership policy event ID")
                    })?;
                    if control_event_id == transition_event_id {
                        return Err(StoreError::CorruptData(
                            "membership transition references one event twice",
                        ));
                    }
                    Ok(SpaceMembershipTransitionSnapshot {
                        space_id,
                        group_reference,
                        parent_epoch: u64::try_from(parent_epoch).map_err(|_| {
                            StoreError::CorruptData("invalid membership parent epoch")
                        })?,
                        policy_revision: u64::try_from(policy_revision).map_err(|_| {
                            StoreError::CorruptData("invalid membership policy revision")
                        })?,
                        control_event_id,
                        transition_event_id,
                        encrypted_state,
                    })
                },
            )
            .collect()
    }
    /// Loads durable competing-Commit markers for one generation.
    ///
    /// # Errors
    ///
    /// Returns an error when the row is malformed or storage cannot be read.
    pub fn load_space_membership_conflict(
        &self,
        space_id: &[u8; 16],
        group_reference: &[u8; 32],
    ) -> Result<Option<SpaceMembershipConflictSnapshot>> {
        let stored = self
            .connection
            .query_row(
                "SELECT parent_epoch, first_control_event_id, second_control_event_id
                 FROM space_membership_conflicts
                 WHERE space_id = ?1 AND group_reference = ?2",
                params![&space_id[..], &group_reference[..]],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((parent_epoch, first_control_event_id, second_control_event_id)) = stored else {
            return Ok(None);
        };
        if parent_epoch < 0 || first_control_event_id == second_control_event_id {
            return Err(StoreError::CorruptData(
                "invalid membership conflict snapshot",
            ));
        }
        Ok(Some(SpaceMembershipConflictSnapshot {
            space_id: *space_id,
            group_reference: *group_reference,
            parent_epoch: u64::try_from(parent_epoch)
                .map_err(|_| StoreError::CorruptData("invalid membership conflict epoch"))?,
            first_control_event_id: first_control_event_id.try_into().map_err(|_| {
                StoreError::CorruptData("invalid first membership conflict event ID")
            })?,
            second_control_event_id: second_control_event_id.try_into().map_err(|_| {
                StoreError::CorruptData("invalid second membership conflict event ID")
            })?,
        }))
    }

    /// Loads one event, including its ordered parent references.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails or stored event data is invalid.
    pub fn load_event(&self, id: &[u8; ID_BYTES]) -> Result<Option<EventRecord>> {
        load_event_with_connection(&self.connection, id)
    }
    /// Loads the event occupying one author's exact one-based sequence.
    ///
    /// # Errors
    ///
    /// Returns an error for sequence zero, malformed stored data, or database
    /// failures.
    pub fn load_event_by_author_sequence(
        &self,
        author_id: &[u8; ID_BYTES],
        sequence: u64,
    ) -> Result<Option<EventRecord>> {
        let sequence = i64::try_from(sequence).map_err(|_| StoreError::InvalidSequence)?;
        if sequence <= 0 {
            return Err(StoreError::InvalidSequence);
        }
        let event_id: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT event_id FROM events WHERE author_id = ?1 AND author_seq = ?2",
                params![&author_id[..], sequence],
                |row| row.get(0),
            )
            .optional()?;
        event_id
            .map(|event_id| {
                let event_id = decode_id(event_id)?;
                self.load_event(&event_id)?.ok_or(StoreError::CorruptData(
                    "event disappeared during author-sequence lookup",
                ))
            })
            .transpose()
    }

    /// Returns committed events in event-ID order using a bounded keyset page.
    ///
    /// This exposes accepted event bytes to sync callers without requiring an
    /// unbounded full-store read. Pending records are not included.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid page size, malformed stored event data,
    /// or database failures.
    pub fn list_event_page(
        &self,
        after_event_id: Option<[u8; ID_BYTES]>,
        limit: usize,
    ) -> Result<Vec<EventRecord>> {
        if limit == 0 || limit > MAX_EVENT_PAGE_SIZE {
            return Err(StoreError::EventPageLimit);
        }
        let mut statement = self.connection.prepare(
            "SELECT event_id FROM events
             WHERE (?1 IS NULL OR event_id > ?1)
             ORDER BY event_id LIMIT ?2",
        )?;
        let after = after_event_id.map(|id| id.to_vec());
        let rows = statement.query_map(
            params![after, i64::try_from(limit).unwrap_or(i64::MAX)],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        rows.map(|row| {
            let event_id = decode_id(row?)?;
            self.load_event(&event_id)?.ok_or(StoreError::CorruptData(
                "event disappeared during page read",
            ))
        })
        .collect()
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
        let removed = Self::resolve_pending_in_transaction(&transaction, id)?;
        transaction.commit()?;
        Ok(removed)
    }

    /// Removes one retained event from a caller-owned transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the database update fails.
    pub fn resolve_pending_in_transaction(
        transaction: &Transaction<'_>,
        id: [u8; ID_BYTES],
    ) -> Result<bool> {
        Ok(transaction.execute(
            "DELETE FROM pending_events WHERE event_id = ?1",
            params![&id[..]],
        )? > 0)
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
        CommitOutcome, MAX_CANONICAL_EVENT_BYTES, MAX_EVENT_DEPENDENCIES, MAX_EVENT_PAGE_SIZE,
        MAX_OUTBOX_EVENTS, MAX_PENDING_EVENTS, OutboxState, SpaceGenesisSnapshot,
        SpaceMembershipConflictSnapshot, SpaceMembershipTransitionSnapshot,
        SpaceWelcomeBootstrapSnapshot, Store, StoreError, TrustedIdentityRecord,
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

    #[test]
    fn read_only_store_open_does_not_apply_old_schema_migrations() {
        let database = TempDatabase::new();
        let connection = rusqlite::Connection::open(database.path()).expect("create database");
        connection
            .pragma_update(None, "user_version", 2)
            .expect("set old schema version");
        drop(connection);

        let store = Store::open_read_only(database.path()).expect("open read-only store");
        assert_eq!(store.schema_version().expect("read schema version"), 2);
        assert!(store.integrity_check().expect("check database integrity"));
        drop(store);

        let connection = rusqlite::Connection::open_with_flags(
            database.path(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("reopen database read-only");
        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .expect("confirm unchanged version"),
            2
        );
        let identity_table_count = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'protected_identity'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("check protected identity table");
        assert_eq!(identity_table_count, 0);
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
    fn committed_event_pages_are_ordered_and_bounded() {
        let database = TempDatabase::new();
        let mut store = Store::open(database.path()).expect("open database");
        for (event, sequence) in [(id(5), 1), (id(8), 2), (id(2), 3)] {
            store
                .commit_authored(id(1), event, sequence, &[0xA1, 0x01, 0x02], &[])
                .expect("commit event");
        }
        assert_eq!(
            store
                .load_event_by_author_sequence(&id(1), 3)
                .expect("load exact author sequence")
                .expect("sequence is committed")
                .event_id,
            id(2)
        );
        assert!(
            store
                .load_event_by_author_sequence(&id(1), 4)
                .expect("load absent author sequence")
                .is_none()
        );
        assert!(matches!(
            store.load_event_by_author_sequence(&id(1), 0),
            Err(StoreError::InvalidSequence)
        ));

        let first = store
            .list_event_page(None, 2)
            .expect("load first event page");
        assert_eq!(
            first.iter().map(|event| event.event_id).collect::<Vec<_>>(),
            [id(2), id(5)]
        );
        let second = store
            .list_event_page(Some(id(5)), 2)
            .expect("load second event page");
        assert_eq!(
            second
                .iter()
                .map(|event| event.event_id)
                .collect::<Vec<_>>(),
            [id(8)]
        );
        assert!(matches!(
            store.list_event_page(None, 0),
            Err(StoreError::EventPageLimit)
        ));
        assert!(matches!(
            store.list_event_page(None, MAX_EVENT_PAGE_SIZE + 1),
            Err(StoreError::EventPageLimit)
        ));
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
                    "DROP TABLE courier_queue;
                     DROP TABLE courier_configuration;
                     DROP TABLE space_welcome_bootstrap_snapshots;
                     DROP TABLE space_membership_conflicts;
                     DROP TABLE space_membership_transition_snapshots;
                     DROP TABLE cached_space_messages;
                     DROP TABLE key_package_lifecycle;
                     DROP TABLE protected_identity;
                     DROP TABLE protected_mls_storage_key;
                     DROP TABLE space_genesis_snapshots;
                     DROP TABLE trusted_identities;
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
    fn v4_schema_upgrade_adds_genesis_snapshots_and_preserves_events() {
        let database = TempDatabase::new();
        let event = id(95);
        {
            let mut store = Store::open(database.path()).expect("create latest schema");
            store
                .commit_authored(id(94), event, 1, &[0xA7], &[])
                .expect("save event before downgrade simulation");
        }
        {
            let connection =
                rusqlite::Connection::open(database.path()).expect("open schema for fixture");
            connection
                .execute_batch(
                    "DROP TABLE courier_queue;
                     DROP TABLE courier_configuration;
                     DROP TABLE space_welcome_bootstrap_snapshots;
                     DROP TABLE space_membership_conflicts;
                     DROP TABLE space_membership_transition_snapshots;
                     DROP TABLE cached_space_messages;
                     DROP TABLE key_package_lifecycle;
                     DROP TABLE space_genesis_snapshots;
                     DROP TABLE trusted_identities;
                     PRAGMA user_version = 4;",
                )
                .expect("restore v4 schema fixture");
        }

        let store = Store::open(database.path()).expect("upgrade v4 database");
        let version: i64 = store
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read upgraded schema version");
        assert_eq!(version, 12);
        assert_eq!(
            store
                .load_event(&event)
                .expect("load migrated event")
                .expect("event survives migration")
                .canonical_bytes,
            [0xA7]
        );
        assert_eq!(
            store
                .load_space_genesis_snapshot(&[0x11; 16], &[0x22; 32])
                .expect("query new snapshot table"),
            None
        );
    }
    #[test]
    fn v5_schema_upgrade_adds_trusted_identity_storage_and_preserves_events() {
        let database = TempDatabase::new();
        let event = id(98);
        {
            let mut store = Store::open(database.path()).expect("create latest schema");
            store
                .commit_authored(id(97), event, 1, &[0xA9], &[])
                .expect("save event before downgrade simulation");
        }
        {
            let connection =
                rusqlite::Connection::open(database.path()).expect("open schema for fixture");
            connection
                .execute_batch(
                    "DROP TABLE courier_queue;
                     DROP TABLE courier_configuration;
                     DROP TABLE space_welcome_bootstrap_snapshots;
                     DROP TABLE space_membership_conflicts;
                     DROP TABLE space_membership_transition_snapshots;
                     DROP TABLE cached_space_messages;
                     DROP TABLE key_package_lifecycle;
                     DROP TABLE trusted_identities;
                     PRAGMA user_version = 5;",
                )
                .expect("restore v5 schema fixture");
        }
        let store = Store::open(database.path()).expect("upgrade v5 database");
        let version: i64 = store
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read upgraded schema version");
        assert_eq!(version, 12);
        assert_eq!(
            store
                .load_event(&event)
                .expect("load migrated event")
                .expect("event survives migration")
                .canonical_bytes,
            [0xA9]
        );
        assert_eq!(
            store
                .load_trusted_identity(&[0x31; 32])
                .expect("query migrated table"),
            None
        );
    }

    #[test]
    fn trusted_identity_persists_exact_bytes_idempotently_and_rejects_conflicts() {
        let database = TempDatabase::new();
        let record = TrustedIdentityRecord {
            fingerprint: [0x31; 32],
            public_bundle: [0xA7; 65],
        };
        {
            let mut store = Store::open(database.path()).expect("open database");
            assert_eq!(
                store
                    .load_trusted_identity(&record.fingerprint)
                    .expect("empty pin"),
                None
            );
            store.save_trusted_identity(record).expect("save first pin");
            store
                .save_trusted_identity(record)
                .expect("repeat exact pin");
            assert!(matches!(
                store.save_trusted_identity(TrustedIdentityRecord {
                    fingerprint: record.fingerprint,
                    public_bundle: [0xB8; 65],
                }),
                Err(StoreError::TrustedIdentityConflict)
            ));
            assert_eq!(
                store
                    .load_trusted_identity(&record.fingerprint)
                    .expect("load pin"),
                Some(record)
            );
        }
        let store = Store::open(database.path()).expect("reopen database");
        assert_eq!(
            store
                .load_trusted_identity(&record.fingerprint)
                .expect("pin survives reopen"),
            Some(record)
        );
    }

    #[test]
    fn trusted_identity_schema_rejects_malformed_widths() {
        let database = TempDatabase::new();
        let store = Store::open(database.path()).expect("open database");
        assert!(
            store
                .connection
                .execute(
                    "INSERT INTO trusted_identities(fingerprint, public_bundle)
                     VALUES (?1, ?2)",
                    rusqlite::params![vec![0x31_u8; 31], vec![0xA7_u8; 65]],
                )
                .is_err()
        );
        assert!(
            store
                .connection
                .execute(
                    "INSERT INTO trusted_identities(fingerprint, public_bundle)
                     VALUES (?1, ?2)",
                    rusqlite::params![vec![0x31_u8; 32], vec![0xA7_u8; 64]],
                )
                .is_err()
        );
    }

    #[test]
    fn genesis_snapshot_is_visible_inside_its_event_transaction_and_loads_after_commit() {
        let database = TempDatabase::new();
        let mut store = Store::open(database.path()).expect("open database");
        let event = id(96);
        let snapshot = SpaceGenesisSnapshot {
            space_id: [0x11; 16],
            group_reference: [0x22; 32],
            group_id: vec![0xA1, 0x80, 0x03],
            event_id: event,
            encrypted_state: vec![0xD3, 0x5A, 0x00, 0xC7],
        };

        store
            .with_transaction(|transaction| {
                Store::commit_authored_in_transaction(transaction, id(97), event, 1, &[0xB1], &[])?;
                Store::save_space_genesis_snapshot_in_transaction(transaction, &snapshot)?;
                let stored_ciphertext: Vec<u8> = transaction.query_row(
                    "SELECT encrypted_state FROM space_genesis_snapshots
                     WHERE space_id = ?1 AND group_reference = ?2",
                    rusqlite::params![&snapshot.space_id[..], &snapshot.group_reference[..]],
                    |row| row.get(0),
                )?;
                assert_eq!(stored_ciphertext, snapshot.encrypted_state);
                Ok::<_, StoreError>(())
            })
            .expect("commit event and snapshot together");

        assert_eq!(
            store
                .load_space_genesis_snapshot(&snapshot.space_id, &snapshot.group_reference)
                .expect("load saved snapshot"),
            Some(snapshot)
        );
    }

    #[test]
    fn welcome_bootstrap_snapshot_round_trips_transactionally_and_enforces_bounds() {
        let database = TempDatabase::new();
        let mut store = Store::open(database.path()).expect("open database");
        assert_eq!(store.schema_version().expect("read schema version"), 12);
        let snapshot = SpaceWelcomeBootstrapSnapshot {
            space_id: [0x11; 16],
            group_reference: [0x22; 32],
            root_event_id: id(112),
            encrypted_package: vec![0xD3, 0x5A, 0x00, 0xC7],
        };
        assert_eq!(
            store
                .load_space_welcome_bootstrap_snapshot(
                    &snapshot.space_id,
                    &snapshot.group_reference,
                )
                .expect("query absent bootstrap package"),
            None
        );

        store
            .with_transaction(|transaction| {
                Store::commit_authored_in_transaction(
                    transaction,
                    id(113),
                    snapshot.root_event_id,
                    1,
                    &[0xB1],
                    &[],
                )?;
                Store::save_space_welcome_bootstrap_snapshot_in_transaction(transaction, &snapshot)
            })
            .expect("commit root event and bootstrap package");
        assert_eq!(
            store
                .load_space_welcome_bootstrap_snapshot(
                    &snapshot.space_id,
                    &snapshot.group_reference,
                )
                .expect("load saved bootstrap package"),
            Some(snapshot.clone())
        );

        for encrypted_package in [Vec::new(), vec![0xA4; 1_048_577]] {
            let invalid = SpaceWelcomeBootstrapSnapshot {
                encrypted_package,
                ..snapshot.clone()
            };
            assert!(matches!(
                store.with_transaction(|transaction| {
                    Store::save_space_welcome_bootstrap_snapshot_in_transaction(
                        transaction,
                        &invalid,
                    )
                }),
                Err(StoreError::InvalidSpaceWelcomeBootstrapSnapshot)
            ));
        }
        let malformed_root = id(114);
        store
            .commit_authored(id(115), malformed_root, 1, &[0xB2], &[])
            .expect("commit malformed fixture root event");

        store
            .connection
            .pragma_update(None, "ignore_check_constraints", true)
            .expect("allow malformed fixture row");
        store
            .connection
            .execute(
                "INSERT INTO space_welcome_bootstrap_snapshots(
                    space_id, group_reference, root_event_id, encrypted_package
                ) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    [0x31_u8; 16].as_slice(),
                    [0x42_u8; 32].as_slice(),
                    &malformed_root[..],
                    Vec::<u8>::new(),
                ],
            )
            .expect("insert malformed fixture row");
        store
            .connection
            .pragma_update(None, "ignore_check_constraints", false)
            .expect("restore SQL checks");
        assert!(matches!(
            store.load_space_welcome_bootstrap_snapshot(&[0x31; 16], &[0x42; 32]),
            Err(StoreError::CorruptData(_))
        ));
    }

    #[test]
    fn key_package_inventory_persists_consumption_and_expiry_transitions() {
        let database = TempDatabase::new();
        let mut store = Store::open(database.path()).expect("open database");
        let unexpired = [0xA1; 32];
        let expiring = [0xB2; 32];
        store
            .with_transaction(|transaction| {
                Store::record_key_package_in_transaction(transaction, &unexpired, 100)?;
                Store::record_key_package_in_transaction(transaction, &expiring, 10)
            })
            .expect("persist package inventory");
        assert_eq!(
            store
                .available_key_package_count(9)
                .expect("count available packages"),
            2
        );
        store
            .with_transaction(|transaction| {
                assert!(Store::consume_key_package_in_transaction(
                    transaction,
                    &unexpired
                )?);
                assert!(!Store::consume_key_package_in_transaction(
                    transaction,
                    &unexpired
                )?);
                Ok::<_, StoreError>(())
            })
            .expect("consume package once");
        assert_eq!(
            store
                .available_key_package_count(10)
                .expect("expire stale package"),
            0
        );
        drop(store);

        let mut reopened = Store::open(database.path()).expect("reopen inventory");
        assert_eq!(
            reopened
                .available_key_package_count(0)
                .expect("consumed state survives reopen"),
            0
        );
        let state: String = reopened
            .connection
            .query_row(
                "SELECT state FROM key_package_lifecycle WHERE key_package_ref = ?1",
                rusqlite::params![&expiring[..]],
                |row| row.get(0),
            )
            .expect("read persisted expiry state");
        assert_eq!(state, "expired");
    }

    #[test]
    fn membership_transition_snapshot_round_trips_with_both_event_rows() {
        let database = TempDatabase::new();
        let mut store = Store::open(database.path()).expect("open database");
        let snapshot = SpaceMembershipTransitionSnapshot {
            space_id: [0x11; 16],
            group_reference: [0x22; 32],
            parent_epoch: 3,
            policy_revision: 5,
            control_event_id: id(96),
            transition_event_id: id(97),
            encrypted_state: vec![0xD3, 0x5A, 0x00, 0xC7],
        };
        store
            .with_transaction(|transaction| {
                Store::commit_authored_in_transaction(
                    transaction,
                    id(98),
                    snapshot.control_event_id,
                    1,
                    &[0xA1],
                    &[],
                )?;
                Store::commit_authored_in_transaction(
                    transaction,
                    id(98),
                    snapshot.transition_event_id,
                    2,
                    &[0xA2],
                    &[],
                )?;
                Store::save_space_membership_transition_snapshot_in_transaction(
                    transaction,
                    &snapshot,
                )
            })
            .expect("commit event rows and transition evidence together");

        assert_eq!(
            store
                .list_space_membership_transition_snapshots(
                    &snapshot.space_id,
                    &snapshot.group_reference,
                )
                .expect("read membership transition evidence"),
            vec![snapshot]
        );
    }

    #[test]
    fn membership_conflict_snapshot_round_trips_with_both_control_rows() {
        let database = TempDatabase::new();
        let mut store = Store::open(database.path()).expect("open database");
        let snapshot = SpaceMembershipConflictSnapshot {
            space_id: [0x31; 16],
            group_reference: [0x42; 32],
            parent_epoch: 7,
            first_control_event_id: id(101),
            second_control_event_id: id(102),
        };
        store
            .with_transaction(|transaction| {
                Store::commit_authored_in_transaction(
                    transaction,
                    id(103),
                    snapshot.first_control_event_id,
                    1,
                    &[0xA1],
                    &[],
                )?;
                Store::commit_authored_in_transaction(
                    transaction,
                    id(103),
                    snapshot.second_control_event_id,
                    2,
                    &[0xA2],
                    &[],
                )?;
                Store::save_space_membership_conflict_in_transaction(transaction, &snapshot)
            })
            .expect("commit controls and conflict marker together");

        assert_eq!(
            store
                .load_space_membership_conflict(&snapshot.space_id, &snapshot.group_reference)
                .expect("load conflict marker"),
            Some(snapshot)
        );
    }

    #[test]
    fn genesis_snapshot_pages_are_bounded_stable_and_exclusive() {
        let database = TempDatabase::new();
        let mut store = Store::open(database.path()).expect("open database");
        for value in 1_u8..=33 {
            let event_id = id(value);
            store
                .commit_authored(id(200), event_id, u64::from(value), &[value], &[])
                .expect("commit fixture event");
            store
                .with_transaction(|transaction| {
                    Store::save_space_genesis_snapshot_in_transaction(
                        transaction,
                        &SpaceGenesisSnapshot {
                            space_id: [value; 16],
                            group_reference: [value; 32],
                            group_id: vec![value],
                            event_id,
                            encrypted_state: vec![0xA5],
                        },
                    )
                })
                .expect("save fixture snapshot");
        }

        let first_page = store
            .list_space_genesis_page(None)
            .expect("list first page");
        assert_eq!(first_page.len(), super::MAX_SPACE_GENESIS_PAGE_SIZE);
        assert_eq!(
            first_page
                .iter()
                .map(|cursor| cursor.space_id[0])
                .collect::<Vec<_>>(),
            (1_u8..=32).collect::<Vec<_>>()
        );

        let second_page = store
            .list_space_genesis_page(first_page.last().copied())
            .expect("list second page");
        assert_eq!(second_page.len(), 1);
        assert_eq!(second_page[0].space_id, [33; 16]);
        assert!(
            store
                .list_space_genesis_page(second_page.last().copied())
                .expect("list exhausted page")
                .is_empty()
        );
    }

    #[test]
    fn genesis_snapshot_requires_event_and_rejects_duplicate_keys_and_events() {
        let database = TempDatabase::new();
        let mut store = Store::open(database.path()).expect("open database");
        let event = id(98);
        let other_event = id(99);
        store
            .commit_authored(id(100), event, 1, &[0xC1], &[])
            .expect("commit first event");
        store
            .commit_authored(id(101), other_event, 1, &[0xC2], &[])
            .expect("commit second event");
        let snapshot = SpaceGenesisSnapshot {
            space_id: [0x31; 16],
            group_reference: [0x41; 32],
            group_id: vec![0xA2],
            event_id: event,
            encrypted_state: vec![0xD4, 0xE5],
        };

        store
            .with_transaction(|transaction| {
                Store::save_space_genesis_snapshot_in_transaction(transaction, &snapshot)
            })
            .expect("save initial snapshot");

        assert!(matches!(
            store.with_transaction(|transaction| {
                Store::save_space_genesis_snapshot_in_transaction(transaction, &snapshot)
            }),
            Err(StoreError::Sqlite(_))
        ));
        let same_event_different_key = SpaceGenesisSnapshot {
            space_id: [0x32; 16],
            group_reference: [0x42; 32],
            ..snapshot.clone()
        };
        assert!(matches!(
            store.with_transaction(|transaction| {
                Store::save_space_genesis_snapshot_in_transaction(
                    transaction,
                    &same_event_different_key,
                )
            }),
            Err(StoreError::Sqlite(_))
        ));

        let missing_event = SpaceGenesisSnapshot {
            space_id: [0x33; 16],
            group_reference: [0x43; 32],
            event_id: id(102),
            ..snapshot
        };
        assert!(matches!(
            store.with_transaction(|transaction| {
                Store::save_space_genesis_snapshot_in_transaction(transaction, &missing_event)
            }),
            Err(StoreError::Sqlite(_))
        ));
    }

    #[test]
    fn genesis_snapshot_bounds_are_enforced_by_api_and_schema() {
        let database = TempDatabase::new();
        let mut store = Store::open(database.path()).expect("open database");
        let event = id(103);
        store
            .commit_authored(id(104), event, 1, &[0xC3], &[])
            .expect("commit event");
        let valid = SpaceGenesisSnapshot {
            space_id: [0x51; 16],
            group_reference: [0x61; 32],
            group_id: vec![0xA3],
            event_id: event,
            encrypted_state: vec![0xD5],
        };
        for invalid in [
            SpaceGenesisSnapshot {
                group_id: Vec::new(),
                ..valid.clone()
            },
            SpaceGenesisSnapshot {
                group_id: vec![0xA4; 257],
                ..valid.clone()
            },
            SpaceGenesisSnapshot {
                encrypted_state: Vec::new(),
                ..valid.clone()
            },
            SpaceGenesisSnapshot {
                encrypted_state: vec![0xD6; 1_048_577],
                ..valid.clone()
            },
        ] {
            assert!(matches!(
                store.with_transaction(|transaction| {
                    Store::save_space_genesis_snapshot_in_transaction(transaction, &invalid)
                }),
                Err(StoreError::InvalidSpaceGenesisSnapshot)
            ));
        }

        store
            .with_transaction(|transaction| {
                transaction
                    .execute(
                        "INSERT INTO space_genesis_snapshots(
                        space_id, group_reference, group_id, event_id, encrypted_state
                    ) VALUES (?1, ?2, ?3, ?4, ?5)",
                        rusqlite::params![
                            &[0x52_u8; 16][..],
                            &[0x62_u8; 32][..],
                            &[] as &[u8],
                            &event[..],
                            &[0xD7_u8][..]
                        ],
                    )
                    .expect_err("SQL rejects empty group IDs");
                transaction
                    .execute(
                        "INSERT INTO space_genesis_snapshots(
                        space_id, group_reference, group_id, event_id, encrypted_state
                    ) VALUES (?1, ?2, ?3, ?4, ?5)",
                        rusqlite::params![
                            &[0x52_u8; 16][..],
                            &[0x62_u8; 32][..],
                            &[0xA5_u8][..],
                            &event[..],
                            &[] as &[u8]
                        ],
                    )
                    .expect_err("SQL rejects empty encrypted state");
                Ok::<_, StoreError>(())
            })
            .expect("check SQL snapshot bounds");

        let boundary = SpaceGenesisSnapshot {
            space_id: [0x53; 16],
            group_reference: [0x63; 32],
            group_id: vec![0xA5; 256],
            event_id: event,
            encrypted_state: vec![0xD7; 1_048_576],
        };
        store
            .with_transaction(|transaction| {
                Store::save_space_genesis_snapshot_in_transaction(transaction, &boundary)
            })
            .expect("save maximum-sized snapshot");
        assert_eq!(
            store
                .load_space_genesis_snapshot(&boundary.space_id, &boundary.group_reference)
                .expect("load maximum-sized snapshot"),
            Some(boundary)
        );
    }

    #[test]
    fn genesis_snapshot_rolls_back_with_enclosing_transaction_error() {
        let database = TempDatabase::new();
        let mut store = Store::open(database.path()).expect("open database");
        let event = id(105);
        let snapshot = SpaceGenesisSnapshot {
            space_id: [0x71; 16],
            group_reference: [0x81; 32],
            group_id: vec![0xA6],
            event_id: event,
            encrypted_state: vec![0xD8, 0xE9],
        };
        let result: super::Result<(), StoreError> = store.with_transaction(|transaction| {
            Store::commit_authored_in_transaction(transaction, id(106), event, 1, &[0xC4], &[])?;
            Store::save_space_genesis_snapshot_in_transaction(transaction, &snapshot)?;
            Err(StoreError::InvalidSequence)
        });
        assert!(matches!(result, Err(StoreError::InvalidSequence)));
        assert!(
            store
                .load_event(&event)
                .expect("query rolled-back event")
                .is_none()
        );
        assert_eq!(
            store
                .load_space_genesis_snapshot(&snapshot.space_id, &snapshot.group_reference)
                .expect("query rolled-back snapshot"),
            None
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
