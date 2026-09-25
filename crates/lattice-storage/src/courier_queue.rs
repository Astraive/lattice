//! Persistent, opt-in storage for bounded encrypted opaque courier envelopes.
//!
//! Queue admission and relay transfer are local storage operations only. They
//! do not inspect payloads, authenticate peers, or signal destination delivery.

use std::fmt;

use lattice_mesh::{
    CourierLimits, CourierMetadata, EnvelopeId, EventId, LimitError, PeerId, TrafficClass, Usage,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::{Store, StoreError};

/// Default persistent courier ceilings. Queue retention remains disabled until opted in.
pub const DEFAULT_COURIER_LIMITS: CourierLimits =
    CourierLimits::new(1024 * 1024, 4 * 1024 * 1024, 256, 16 * 1024 * 1024, 4096);

/// Current persisted opt-in and quota usage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CourierQueueStatus {
    /// Whether this store retains envelopes for voluntary forwarding.
    pub enabled: bool,
    /// Configured limits, bounded by `lattice-mesh` process-wide ceilings.
    pub limits: CourierLimits,
    /// Current queued count and opaque-byte total.
    pub usage: Usage,
}

/// Admission receipt. It confirms only local queue retention.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CourierQueueReceipt {
    pub peer_id: PeerId,
    pub envelope_id: EnvelopeId,
    pub sequence: u64,
}

/// Owned opaque envelope removed from the source queue for a single relay copy.
#[derive(Debug, Eq, PartialEq)]
pub struct CourierQueueEntry {
    pub peer_id: PeerId,
    pub metadata: CourierMetadata,
    pub encrypted_opaque_bytes: Vec<u8>,
    pub sequence: u64,
}

/// Rejected courier operation or storage failure.
#[derive(Debug)]
pub enum CourierQueueError {
    Storage(StoreError),
    InvalidLimits(LimitError),
    Disabled,
    InvalidMetadata,
    EmptyOpaqueBytes,
    ObjectTooLarge { actual: usize, maximum: usize },
    QuotaExceeded,
    DuplicateEnvelope,
    DuplicateEvent,
    EnvelopeMissing,
    Expired,
    InvalidHopLimit,
    InvalidHopBudget,
    HopBudgetExhausted,
    SequenceExhausted,
    CorruptData(&'static str),
}

impl fmt::Display for CourierQueueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(formatter, "courier storage error: {error}"),
            Self::InvalidLimits(error) => write!(formatter, "invalid courier limits: {error:?}"),
            Self::Disabled => formatter.write_str("persistent courier queue is disabled"),
            Self::InvalidMetadata => formatter.write_str("courier metadata is invalid"),
            Self::EmptyOpaqueBytes => formatter.write_str("opaque envelope bytes are empty"),
            Self::ObjectTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "opaque envelope is {actual} bytes; maximum is {maximum}"
                )
            }
            Self::QuotaExceeded => formatter.write_str("courier queue quota exceeded"),
            Self::DuplicateEnvelope => formatter.write_str("courier envelope ID is already queued"),
            Self::DuplicateEvent => formatter.write_str("courier event ID is already queued"),
            Self::EnvelopeMissing => formatter.write_str("courier source envelope was not found"),
            Self::Expired => formatter.write_str("courier envelope has expired"),
            Self::InvalidHopLimit => formatter.write_str("courier hop limit is invalid"),
            Self::InvalidHopBudget => formatter.write_str("courier copy budget exceeds hop limit"),
            Self::HopBudgetExhausted => formatter.write_str("courier copy budget is exhausted"),
            Self::SequenceExhausted => formatter.write_str("courier queue sequence is exhausted"),
            Self::CorruptData(message) => {
                write!(formatter, "corrupt courier queue data: {message}")
            }
        }
    }
}

impl std::error::Error for CourierQueueError {}

impl From<StoreError> for CourierQueueError {
    fn from(error: StoreError) -> Self {
        Self::Storage(error)
    }
}

type Result<T, E = CourierQueueError> = std::result::Result<T, E>;

impl From<rusqlite::Error> for CourierQueueError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(error.into())
    }
}

impl Store {
    /// Persists the courier opt-in and limits. Disabling clears all retained
    /// courier bytes; changing limits evicts the oldest entries until they fit.
    ///
    /// # Errors
    ///
    /// Returns an error if limits exceed the hard bounds or `SQLite` fails.
    pub fn configure_courier_queue(
        &mut self,
        enabled: bool,
        limits: CourierLimits,
    ) -> Result<CourierQueueStatus> {
        limits
            .validate()
            .map_err(CourierQueueError::InvalidLimits)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "UPDATE courier_configuration SET enabled = ?1, max_object_bytes = ?2,
                max_peer_bytes = ?3, max_peer_items = ?4, max_total_bytes = ?5,
                max_total_items = ?6 WHERE singleton = 1",
            params![
                enabled,
                to_i64_usize(limits.max_object_bytes)?,
                to_i64_usize(limits.max_peer_bytes)?,
                to_i64_usize(limits.max_peer_items)?,
                to_i64_usize(limits.max_total_bytes)?,
                to_i64_usize(limits.max_total_items)?,
            ],
        )?;
        if enabled {
            trim_to_limits(&transaction, limits)?;
        } else {
            transaction.execute("DELETE FROM courier_queue", [])?;
        }
        let status = status_in_transaction(&transaction)?;
        transaction.commit()?;
        Ok(status)
    }

    /// Reads persisted opt-in, limits, and current queue usage.
    ///
    /// # Errors
    ///
    /// Returns an error if persisted settings are invalid or `SQLite` fails.
    pub fn courier_queue_status(&self) -> Result<CourierQueueStatus> {
        let (enabled, limits) = read_configuration(&self.connection)?;
        let usage = read_total_usage(&self.connection)?;
        Ok(CourierQueueStatus {
            enabled,
            limits,
            usage,
        })
    }

    /// Retains encrypted opaque bytes only when the persisted local opt-in is
    /// enabled. Expired rows are removed before deduplication and quota checks.
    ///
    /// # Errors
    ///
    /// Returns an error for disabled storage, invalid/expired metadata, duplicate
    /// IDs, quota rejection, or `SQLite` failures.
    pub fn queue_courier_envelope(
        &mut self,
        peer_id: PeerId,
        metadata: &CourierMetadata,
        encrypted_opaque_bytes: &[u8],
        now_ms: u64,
    ) -> Result<CourierQueueReceipt> {
        let now = to_i64_time(now_ms)?;
        let expires = to_i64_time(metadata.expires_at_ms())?;
        validate_metadata(metadata, now_ms)?;
        if encrypted_opaque_bytes.is_empty() {
            return Err(CourierQueueError::EmptyOpaqueBytes);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (enabled, limits) = read_configuration(&transaction)?;
        if !enabled {
            return Err(CourierQueueError::Disabled);
        }
        transaction.execute("DELETE FROM courier_queue WHERE expires_at_ms <= ?1", [now])?;
        let bytes = encrypted_opaque_bytes.len();
        if bytes > limits.max_object_bytes {
            return Err(CourierQueueError::ObjectTooLarge {
                actual: bytes,
                maximum: limits.max_object_bytes,
            });
        }
        if bytes > limits.max_peer_bytes
            || bytes > limits.max_total_bytes
            || limits.max_peer_items == 0
            || limits.max_total_items == 0
        {
            return Err(CourierQueueError::QuotaExceeded);
        }
        let envelope_id = metadata.envelope_id();
        let event_id = metadata.event_id();
        if exists(&transaction, "envelope_id", envelope_id.as_bytes())? {
            return Err(CourierQueueError::DuplicateEnvelope);
        }
        if exists(&transaction, "event_id", event_id.as_bytes())? {
            return Err(CourierQueueError::DuplicateEvent);
        }
        while !peer_fits(&transaction, peer_id, bytes, limits)? {
            if !evict_oldest_peer(&transaction, peer_id)? {
                return Err(CourierQueueError::QuotaExceeded);
            }
        }
        while !total_fits(&transaction, bytes, limits)? {
            if !evict_oldest_total(&transaction)? {
                return Err(CourierQueueError::QuotaExceeded);
            }
        }
        let traffic_class = encode_traffic_class(metadata.traffic_class());
        transaction.execute(
            "INSERT INTO courier_queue
                (peer_id, envelope_id, event_id, expires_at_ms, hop_limit,
                 remaining_copy_budget, traffic_class, encrypted_opaque_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                peer_id.as_bytes().as_slice(),
                envelope_id.as_bytes().as_slice(),
                event_id.as_bytes().as_slice(),
                expires,
                i64::from(metadata.hop_limit()),
                i64::from(metadata.remaining_copy_budget()),
                traffic_class,
                encrypted_opaque_bytes,
            ],
        )?;
        let sequence = transaction.last_insert_rowid();
        let sequence = u64::try_from(sequence).map_err(|_| CourierQueueError::SequenceExhausted)?;
        transaction.commit()?;
        Ok(CourierQueueReceipt {
            peer_id,
            envelope_id,
            sequence,
        })
    }

    /// Consumes one queued source and returns its next opaque copy to the
    /// caller. The returned copy is no longer retained by this queue.
    ///
    /// # Errors
    ///
    /// Returns an error if storage is disabled, the source is missing/expired,
    /// metadata is invalid, the copy budget is exhausted, or `SQLite` fails.
    pub fn take_courier_for_relay(
        &mut self,
        envelope_id: EnvelopeId,
        new_envelope_id: EnvelopeId,
        now_ms: u64,
    ) -> Result<CourierQueueEntry> {
        let now = to_i64_time(now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (enabled, _) = read_configuration(&transaction)?;
        if !enabled {
            return Err(CourierQueueError::Disabled);
        }
        let row = transaction
            .query_row(
                "SELECT sequence, peer_id, event_id, expires_at_ms, hop_limit,
                        remaining_copy_budget, traffic_class, encrypted_opaque_bytes
                 FROM courier_queue WHERE envelope_id = ?1",
                params![envelope_id.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, Vec<u8>>(7)?,
                    ))
                },
            )
            .optional()?;
        let Some((source_sequence, peer, event, expires, hop, budget, class, bytes)) = row else {
            return Err(CourierQueueError::EnvelopeMissing);
        };
        if expires <= now {
            transaction.execute(
                "DELETE FROM courier_queue WHERE sequence = ?1",
                [source_sequence],
            )?;
            transaction.commit()?;
            return Err(CourierQueueError::Expired);
        }
        if hop <= 0 || hop > i64::from(u16::MAX) {
            return Err(CourierQueueError::InvalidHopLimit);
        }
        if budget < 0 || budget > hop || budget > i64::from(u16::MAX) {
            return Err(CourierQueueError::InvalidHopBudget);
        }
        if budget == 0 {
            return Err(CourierQueueError::HopBudgetExhausted);
        }
        let peer_id = decode_peer(peer)?;
        let event_id = decode_event(event)?;
        let expires_at_ms = u64::try_from(expires)
            .map_err(|_| CourierQueueError::CorruptData("negative expiry"))?;
        let hop_limit =
            u16::try_from(hop).map_err(|_| CourierQueueError::CorruptData("invalid hop limit"))?;
        let remaining_copy_budget = u16::try_from(budget - 1)
            .map_err(|_| CourierQueueError::CorruptData("invalid copy budget"))?;
        let traffic_class = decode_traffic_class(class)?;
        let sequence = u64::try_from(source_sequence)
            .map_err(|_| CourierQueueError::CorruptData("invalid insertion sequence"))?;
        transaction.execute(
            "DELETE FROM courier_queue WHERE sequence = ?1",
            [source_sequence],
        )?;
        transaction.commit()?;
        Ok(CourierQueueEntry {
            peer_id,
            metadata: CourierMetadata::new(
                new_envelope_id,
                event_id,
                expires_at_ms,
                hop_limit,
                remaining_copy_budget,
                traffic_class,
            ),
            encrypted_opaque_bytes: bytes,
            sequence,
        })
    }

    /// Removes all rows whose absolute Unix-millisecond expiry has been reached.
    ///
    /// # Errors
    ///
    /// Returns an error if the time is outside `SQLite`'s integer range or `SQLite` fails.
    pub fn purge_expired_courier_envelopes(&mut self, now_ms: u64) -> Result<usize> {
        let now = to_i64_time(now_ms)?;
        let changed = self
            .connection
            .execute("DELETE FROM courier_queue WHERE expires_at_ms <= ?1", [now])?;
        Ok(changed)
    }
}

fn validate_metadata(metadata: &CourierMetadata, now_ms: u64) -> Result<()> {
    if metadata.expires_at_ms() <= now_ms {
        return Err(CourierQueueError::Expired);
    }
    if metadata.hop_limit() == 0 {
        return Err(CourierQueueError::InvalidHopLimit);
    }
    if metadata.remaining_copy_budget() > metadata.hop_limit() {
        return Err(CourierQueueError::InvalidHopBudget);
    }
    Ok(())
}

fn read_configuration(connection: &Connection) -> Result<(bool, CourierLimits)> {
    let values = connection.query_row(
        "SELECT enabled, max_object_bytes, max_peer_bytes, max_peer_items,
                max_total_bytes, max_total_items
         FROM courier_configuration WHERE singleton = 1",
        [],
        |row| {
            Ok((
                row.get::<_, bool>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        },
    )?;
    let limits = CourierLimits::new(
        usize_from_db(values.1)?,
        usize_from_db(values.2)?,
        usize_from_db(values.3)?,
        usize_from_db(values.4)?,
        usize_from_db(values.5)?,
    );
    limits
        .validate()
        .map_err(CourierQueueError::InvalidLimits)?;
    Ok((values.0, limits))
}

fn status_in_transaction(tx: &Transaction<'_>) -> Result<CourierQueueStatus> {
    let (enabled, limits) = read_configuration(tx)?;
    Ok(CourierQueueStatus {
        enabled,
        limits,
        usage: read_total_usage(tx)?,
    })
}

fn read_total_usage(connection: &Connection) -> Result<Usage> {
    let (items, bytes): (i64, i64) = connection.query_row(
        "SELECT COUNT(*), COALESCE(SUM(length(encrypted_opaque_bytes)), 0) FROM courier_queue",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok(Usage {
        items: usize_from_db(items)?,
        bytes: usize_from_db(bytes)?,
    })
}

fn peer_usage(connection: &Connection, peer_id: PeerId) -> Result<Usage> {
    let (items, bytes): (i64, i64) = connection.query_row(
        "SELECT COUNT(*), COALESCE(SUM(length(encrypted_opaque_bytes)), 0)
         FROM courier_queue WHERE peer_id = ?1",
        params![peer_id.as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok(Usage {
        items: usize_from_db(items)?,
        bytes: usize_from_db(bytes)?,
    })
}

fn peer_fits(
    tx: &Transaction<'_>,
    peer_id: PeerId,
    incoming: usize,
    limits: CourierLimits,
) -> Result<bool> {
    let usage = peer_usage(tx, peer_id)?;
    Ok(usage.items < limits.max_peer_items
        && usage
            .bytes
            .checked_add(incoming)
            .is_some_and(|next| next <= limits.max_peer_bytes))
}

fn total_fits(tx: &Transaction<'_>, incoming: usize, limits: CourierLimits) -> Result<bool> {
    let usage = read_total_usage(tx)?;
    Ok(usage.items < limits.max_total_items
        && usage
            .bytes
            .checked_add(incoming)
            .is_some_and(|next| next <= limits.max_total_bytes))
}

fn trim_to_limits(tx: &Transaction<'_>, limits: CourierLimits) -> Result<()> {
    loop {
        let object_evicted = tx.execute(
            "DELETE FROM courier_queue WHERE length(encrypted_opaque_bytes) > ?1",
            [to_i64_usize(limits.max_object_bytes)?],
        )? > 0;
        let peers = {
            let mut statement =
                tx.prepare("SELECT DISTINCT peer_id FROM courier_queue ORDER BY peer_id")?;
            let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        let mut evicted = false;
        for peer in peers {
            let peer = decode_peer(peer)?;
            while !peer_fits(tx, peer, 0, limits)? {
                if !evict_oldest_peer(tx, peer)? {
                    break;
                }
                evicted = true;
            }
        }
        let mut global_eviction = false;
        while !total_fits(tx, 0, limits)? {
            if !evict_oldest_total(tx)? {
                break;
            }
            global_eviction = true;
        }
        if !object_evicted && !evicted && !global_eviction {
            break;
        }
    }
    Ok(())
}

fn evict_oldest_peer(tx: &Transaction<'_>, peer_id: PeerId) -> Result<bool> {
    Ok(tx.execute(
        "DELETE FROM courier_queue WHERE sequence =
            (SELECT sequence FROM courier_queue WHERE peer_id = ?1 ORDER BY sequence LIMIT 1)",
        params![peer_id.as_bytes().as_slice()],
    )? > 0)
}

fn evict_oldest_total(tx: &Transaction<'_>) -> Result<bool> {
    Ok(tx.execute(
        "DELETE FROM courier_queue WHERE sequence =
            (SELECT sequence FROM courier_queue ORDER BY sequence LIMIT 1)",
        [],
    )? > 0)
}

fn exists(tx: &Transaction<'_>, column: &str, value: &[u8]) -> Result<bool> {
    let query = match column {
        "envelope_id" => "SELECT EXISTS(SELECT 1 FROM courier_queue WHERE envelope_id = ?1)",
        "event_id" => "SELECT EXISTS(SELECT 1 FROM courier_queue WHERE event_id = ?1)",
        _ => return Err(CourierQueueError::CorruptData("invalid internal column")),
    };
    Ok(tx.query_row(query, params![value], |row| row.get(0))?)
}

fn encode_traffic_class(class: TrafficClass) -> i64 {
    match class {
        TrafficClass::Control => 0,
        TrafficClass::Interactive => 1,
        TrafficClass::Bulk => 2,
    }
}

fn decode_traffic_class(value: i64) -> Result<TrafficClass> {
    match value {
        0 => Ok(TrafficClass::Control),
        1 => Ok(TrafficClass::Interactive),
        2 => Ok(TrafficClass::Bulk),
        _ => Err(CourierQueueError::CorruptData("invalid traffic class")),
    }
}

fn decode_peer(value: Vec<u8>) -> Result<PeerId> {
    let bytes: [u8; 16] = value
        .try_into()
        .map_err(|_| CourierQueueError::CorruptData("invalid peer ID"))?;
    Ok(PeerId::new(bytes))
}

fn decode_event(value: Vec<u8>) -> Result<EventId> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| CourierQueueError::CorruptData("invalid event ID"))?;
    Ok(EventId::new(bytes))
}

fn usize_from_db(value: i64) -> Result<usize> {
    usize::try_from(value)
        .map_err(|_| CourierQueueError::CorruptData("negative or oversized counter"))
}

fn to_i64_usize(value: usize) -> Result<i64> {
    i64::try_from(value).map_err(|_| CourierQueueError::SequenceExhausted)
}

fn to_i64_time(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| CourierQueueError::InvalidMetadata)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn metadata(envelope: u8, event: u8, expiry: u64, budget: u16) -> CourierMetadata {
        CourierMetadata::new(
            EnvelopeId::new([envelope; 16]),
            EventId::new([event; 32]),
            expiry,
            3,
            budget,
            TrafficClass::Interactive,
        )
    }

    fn test_database_path() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "lattice-courier-{}-{nonce}.sqlite",
            std::process::id()
        ))
    }

    #[test]
    fn courier_queue_is_opt_in_persistent_and_consumes_relay_budget() {
        let path = test_database_path();
        let mut store = Store::open(&path).expect("open");
        let initial = store.courier_queue_status().expect("status");
        assert!(!initial.enabled);
        assert_eq!(initial.limits, DEFAULT_COURIER_LIMITS);
        assert!(matches!(
            store.queue_courier_envelope(
                PeerId::new([9; 16]),
                &metadata(1, 2, 100, 2),
                b"ciphertext",
                10,
            ),
            Err(CourierQueueError::Disabled)
        ));

        store
            .configure_courier_queue(true, DEFAULT_COURIER_LIMITS)
            .expect("opt in");
        let peer = PeerId::new([9; 16]);
        store
            .queue_courier_envelope(peer, &metadata(1, 2, 100, 2), b"ciphertext", 10)
            .expect("admit");
        drop(store);

        let mut store = Store::open(&path).expect("reopen");
        let status = store.courier_queue_status().expect("persisted status");
        assert!(status.enabled);
        assert_eq!(
            status.usage,
            Usage {
                items: 1,
                bytes: 10
            }
        );
        let relayed = store
            .take_courier_for_relay(EnvelopeId::new([1; 16]), EnvelopeId::new([3; 16]), 20)
            .expect("relay copy");
        assert_eq!(relayed.peer_id, peer);
        assert_eq!(relayed.metadata.event_id(), EventId::new([2; 32]));
        assert_eq!(relayed.metadata.remaining_copy_budget(), 1);
        assert_eq!(relayed.encrypted_opaque_bytes, b"ciphertext");
        assert_eq!(
            store
                .courier_queue_status()
                .expect("consumed source")
                .usage
                .items,
            0
        );
        store
            .queue_courier_envelope(peer, &metadata(4, 4, 100, 0), b"ciphertext", 20)
            .expect("admit exhausted source");
        assert!(matches!(
            store.take_courier_for_relay(EnvelopeId::new([4; 16]), EnvelopeId::new([5; 16]), 20,),
            Err(CourierQueueError::HopBudgetExhausted)
        ));
        assert_eq!(
            store
                .courier_queue_status()
                .expect("retained source")
                .usage
                .items,
            1
        );
        store
            .configure_courier_queue(false, DEFAULT_COURIER_LIMITS)
            .expect("opt out");
        assert_eq!(
            store.courier_queue_status().expect("cleared").usage.items,
            0
        );
        drop(store);
        std::fs::remove_file(path).expect("remove test database");
    }

    #[test]
    fn courier_queue_deduplicates_expires_and_evicts_fifo_within_quotas() {
        let mut store = Store::open(":memory:").expect("open");
        let limits = CourierLimits::new(3, 5, 2, 5, 2);
        store.configure_courier_queue(true, limits).expect("opt in");
        let peer = PeerId::new([7; 16]);
        store
            .queue_courier_envelope(peer, &metadata(1, 1, 50, 1), b"one", 10)
            .expect("first");
        assert!(matches!(
            store.queue_courier_envelope(peer, &metadata(2, 1, 50, 1), b"two", 10),
            Err(CourierQueueError::DuplicateEvent)
        ));
        store
            .queue_courier_envelope(peer, &metadata(2, 2, 50, 1), b"two", 10)
            .expect("second evicts oldest bytes");
        assert!(matches!(
            store.take_courier_for_relay(EnvelopeId::new([1; 16]), EnvelopeId::new([3; 16]), 10),
            Err(CourierQueueError::EnvelopeMissing)
        ));
        assert_eq!(
            store.courier_queue_status().expect("usage").usage,
            Usage { items: 1, bytes: 3 }
        );
        assert_eq!(store.purge_expired_courier_envelopes(50).expect("purge"), 1);
        assert_eq!(store.courier_queue_status().expect("empty").usage.items, 0);
    }

    #[test]
    fn courier_queue_rejects_invalid_limits_and_metadata() {
        let mut store = Store::open(":memory:").expect("open");
        let excessive = CourierLimits::new(lattice_mesh::HARD_MAX_OBJECT_BYTES + 1, 1, 1, 1, 1);
        assert!(matches!(
            store.configure_courier_queue(true, excessive),
            Err(CourierQueueError::InvalidLimits(_))
        ));
        store
            .configure_courier_queue(true, DEFAULT_COURIER_LIMITS)
            .expect("opt in");
        assert!(matches!(
            store.queue_courier_envelope(
                PeerId::new([1; 16]),
                &metadata(1, 1, 10, 1),
                b"ciphertext",
                10,
            ),
            Err(CourierQueueError::Expired)
        ));
        assert!(matches!(
            store.queue_courier_envelope(
                PeerId::new([1; 16]),
                &CourierMetadata::new(
                    EnvelopeId::new([1; 16]),
                    EventId::new([1; 32]),
                    100,
                    0,
                    0,
                    TrafficClass::Bulk,
                ),
                b"ciphertext",
                10,
            ),
            Err(CourierQueueError::InvalidHopLimit)
        ));
    }
}
