//! Bounded opaque-envelope courier accounting.
//!
//! This crate accounts for encrypted opaque courier bytes only. It does not
//! decrypt payloads, inspect plaintext, authenticate peers, or report delivery
//! to a destination. A successful admission means only that the item is queued
//! in this courier cache. Locally authored event history is not represented by
//! this cache and therefore cannot be selected for courier eviction.

use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Package's published crate name.
pub const CRATE_NAME: &str = "lattice-mesh";

/// Stable identity of one opaque envelope. Rewrapping an event uses a new
/// envelope ID while preserving its event ID.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EnvelopeId([u8; 16]);

impl EnvelopeId {
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Stable 32-byte identity of the event carried by an envelope. Rewrapped
/// envelopes preserve this identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventId([u8; 32]);

impl EventId {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Opaque identity used to enforce per-peer courier quotas.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PeerId([u8; 16]);

impl PeerId {
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// A scheduling classification carried as metadata; it does not grant
/// authorization or imply a delivery guarantee.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TrafficClass {
    Control,
    Interactive,
    Bulk,
}

/// Metadata for one encrypted opaque envelope.
///
/// It is deliberately neither `Copy` nor `Clone`; forwarding an item must
/// consume the source cache entry through [`CourierCache::take_for_relay`].
#[derive(Debug, Eq, PartialEq)]
pub struct CourierMetadata {
    envelope_id: EnvelopeId,
    event_id: EventId,
    expires_at_ms: u64,
    hop_limit: u16,
    remaining_copy_budget: u16,
    traffic_class: TrafficClass,
}

impl CourierMetadata {
    #[must_use]
    pub const fn new(
        envelope_id: EnvelopeId,
        event_id: EventId,
        expires_at_ms: u64,
        hop_limit: u16,
        remaining_copy_budget: u16,
        traffic_class: TrafficClass,
    ) -> Self {
        Self {
            envelope_id,
            event_id,
            expires_at_ms,
            hop_limit,
            remaining_copy_budget,
            traffic_class,
        }
    }

    #[must_use]
    pub const fn envelope_id(&self) -> EnvelopeId {
        self.envelope_id
    }

    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    #[must_use]
    pub const fn hop_limit(&self) -> u16 {
        self.hop_limit
    }

    #[must_use]
    pub const fn remaining_copy_budget(&self) -> u16 {
        self.remaining_copy_budget
    }

    #[must_use]
    pub const fn traffic_class(&self) -> TrafficClass {
        self.traffic_class
    }

    fn relay_copy(&self, new_envelope_id: EnvelopeId, now_ms: u64) -> Result<Self, DropReason> {
        self.validate_at(now_ms)?;
        let remaining_copy_budget = self
            .remaining_copy_budget
            .checked_sub(1)
            .ok_or(DropReason::HopBudgetExhausted)?;
        Ok(Self::new(
            new_envelope_id,
            self.event_id,
            self.expires_at_ms,
            self.hop_limit,
            remaining_copy_budget,
            self.traffic_class,
        ))
    }

    fn validate_at(&self, now_ms: u64) -> Result<(), DropReason> {
        if self.expires_at_ms <= now_ms {
            return Err(DropReason::Expired);
        }
        if self.hop_limit == 0 {
            return Err(DropReason::InvalidHopLimit);
        }
        if self.remaining_copy_budget > self.hop_limit {
            return Err(DropReason::InvalidHopBudget);
        }
        Ok(())
    }
}

/// Process-independent ceilings; caller limits may be stricter but not higher.
pub const HARD_MAX_OBJECT_BYTES: usize = 16 * 1024 * 1024;
pub const HARD_MAX_PEER_BYTES: usize = 16 * 1024 * 1024;
pub const HARD_MAX_PEER_ITEMS: usize = 4_096;
pub const HARD_MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;
pub const HARD_MAX_TOTAL_ITEMS: usize = 65_536;

/// Error returned when a requested cache limit exceeds a hard ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitError {
    ObjectBytesAboveHardLimit,
    PeerBytesAboveHardLimit,
    PeerItemsAboveHardLimit,
    TotalBytesAboveHardLimit,
    TotalItemsAboveHardLimit,
}

/// Configured upper bounds. Zero is valid and disables admission at that
/// particular bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CourierLimits {
    /// Maximum encrypted opaque bytes in one queued envelope.
    pub max_object_bytes: usize,
    /// Maximum queued bytes attributed to one peer.
    pub max_peer_bytes: usize,
    /// Maximum queued envelopes attributed to one peer.
    pub max_peer_items: usize,
    /// Maximum queued bytes across all peers.
    pub max_total_bytes: usize,
    /// Maximum queued envelopes across all peers.
    pub max_total_items: usize,
}

impl CourierLimits {
    #[must_use]
    pub const fn new(
        max_object_bytes: usize,
        max_peer_bytes: usize,
        max_peer_items: usize,
        max_total_bytes: usize,
        max_total_items: usize,
    ) -> Self {
        Self {
            max_object_bytes,
            max_peer_bytes,
            max_peer_items,
            max_total_bytes,
            max_total_items,
        }
    }
    /// # Errors
    ///
    /// Returns the first hard limit exceeded by the configured values.
    pub fn validate(self) -> Result<(), LimitError> {
        if self.max_object_bytes > HARD_MAX_OBJECT_BYTES {
            return Err(LimitError::ObjectBytesAboveHardLimit);
        }
        if self.max_peer_bytes > HARD_MAX_PEER_BYTES {
            return Err(LimitError::PeerBytesAboveHardLimit);
        }
        if self.max_peer_items > HARD_MAX_PEER_ITEMS {
            return Err(LimitError::PeerItemsAboveHardLimit);
        }
        if self.max_total_bytes > HARD_MAX_TOTAL_BYTES {
            return Err(LimitError::TotalBytesAboveHardLimit);
        }
        if self.max_total_items > HARD_MAX_TOTAL_ITEMS {
            return Err(LimitError::TotalItemsAboveHardLimit);
        }
        Ok(())
    }
}

/// Reason an opaque envelope was not admitted or could not be relayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DropReason {
    Expired,
    InvalidHopLimit,
    InvalidHopBudget,
    HopBudgetExhausted,
    EmptyOpaqueBytes,
    ObjectTooLarge,
    QuotaExceeded,
    DuplicateEnvelope,
    DuplicateEvent,
    SourceEnvelopeNotFound,
    SequenceExhausted,
    AccountingOverflow,
    AccountingInvariantViolation,
}

/// A receipt for queue admission. It deliberately has no delivery status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueReceipt {
    peer_id: PeerId,
    envelope_id: EnvelopeId,
    sequence: u64,
}

impl QueueReceipt {
    #[must_use]
    pub const fn peer_id(self) -> PeerId {
        self.peer_id
    }

    #[must_use]
    pub const fn envelope_id(self) -> EnvelopeId {
        self.envelope_id
    }

    /// Monotonic insertion order used for deterministic FIFO eviction.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

/// Read-only view of a queued courier item. Opaque bytes are exposed only as a
/// borrowed byte slice and are never parsed or decrypted here.
pub struct CachedEnvelope {
    peer_id: PeerId,
    metadata: CourierMetadata,
    encrypted_opaque_bytes: Box<[u8]>,
    sequence: u64,
}

impl CachedEnvelope {
    #[must_use]
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    #[must_use]
    pub const fn metadata(&self) -> &CourierMetadata {
        &self.metadata
    }

    #[must_use]
    pub fn encrypted_opaque_bytes(&self) -> &[u8] {
        &self.encrypted_opaque_bytes
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// Current byte and item accounting for a peer or the whole cache.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Usage {
    /// Number of queued envelopes.
    pub items: usize,
    /// Total encrypted opaque byte count.
    pub bytes: usize,
}

/// Bounded FIFO courier cache. It stores only opaque courier envelopes; event
/// history and locally authored records are outside this type's ownership.
pub struct CourierCache {
    limits: CourierLimits,
    entries: BTreeMap<u64, CachedEnvelope>,
    envelope_sequences: HashMap<EnvelopeId, u64>,
    event_sequences: HashMap<EventId, u64>,
    peer_sequences: HashMap<PeerId, BTreeSet<u64>>,
    peer_usage: HashMap<PeerId, Usage>,
    total_usage: Usage,
    next_sequence: u64,
}

impl CourierCache {
    /// # Errors
    ///
    /// Returns a limit error if `limits` exceeds a process-independent hard ceiling.
    pub fn new(limits: CourierLimits) -> Result<Self, LimitError> {
        limits.validate()?;
        Ok(Self {
            limits,
            entries: BTreeMap::new(),
            envelope_sequences: HashMap::new(),
            event_sequences: HashMap::new(),
            peer_sequences: HashMap::new(),
            peer_usage: HashMap::new(),
            total_usage: Usage::default(),
            next_sequence: 0,
        })
    }
    #[must_use]
    pub const fn limits(&self) -> CourierLimits {
        self.limits
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.total_usage.items
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total_usage.items == 0
    }

    #[must_use]
    pub const fn total_usage(&self) -> Usage {
        self.total_usage
    }

    #[must_use]
    pub fn peer_usage(&self, peer_id: PeerId) -> Usage {
        self.peer_usage.get(&peer_id).copied().unwrap_or_default()
    }

    #[must_use]
    pub fn get(&self, envelope_id: EnvelopeId) -> Option<&CachedEnvelope> {
        let sequence = self.envelope_sequences.get(&envelope_id)?;
        self.entries.get(sequence)
    }

    /// Atomically relinquish one queued source before preparing its sole next
    /// courier copy. On success, the source is absent from this cache and the
    /// returned metadata/bytes are owned by the caller; the caller must admit
    /// them to a destination cache or drop them. This is queue transfer only,
    /// not transport or destination delivery.
    /// # Errors
    ///
    /// Returns a drop reason if the source is missing, its metadata is invalid,
    /// or the cache accounting invariant is violated.
    pub fn take_for_relay(
        &mut self,
        envelope_id: EnvelopeId,
        new_envelope_id: EnvelopeId,
        now_ms: u64,
    ) -> Result<(PeerId, CourierMetadata, Box<[u8]>), DropReason> {
        let sequence = *self
            .envelope_sequences
            .get(&envelope_id)
            .ok_or(DropReason::SourceEnvelopeNotFound)?;
        let metadata = self
            .entries
            .get(&sequence)
            .ok_or(DropReason::AccountingInvariantViolation)?
            .metadata
            .relay_copy(new_envelope_id, now_ms)?;
        let entry = self.remove_sequence(sequence)?;
        Ok((entry.peer_id, metadata, entry.encrypted_opaque_bytes))
    }

    /// Remove entries whose absolute expiry is reached on the supplied time
    /// base. Removal follows insertion order and is deterministic.
    /// # Errors
    ///
    /// Returns a drop reason if cache accounting invariants are violated.
    pub fn purge_expired(&mut self, now_ms: u64) -> Result<usize, DropReason> {
        let mut expired_sequences = Vec::new();
        for (sequence, entry) in &self.entries {
            if entry.metadata.expires_at_ms <= now_ms {
                expired_sequences.push(*sequence);
            }
        }

        let mut removed = 0usize;
        for sequence in expired_sequences {
            self.remove_sequence(sequence)?;
            removed = removed
                .checked_add(1)
                .ok_or(DropReason::AccountingOverflow)?;
        }
        Ok(removed)
    }

    /// Admit encrypted opaque bytes for courier queueing. Success reports only
    /// queue acceptance, never destination delivery.
    /// # Errors
    ///
    /// Returns a drop reason if the metadata, payload, quotas, duplicates, or
    /// cache accounting state prevents admission.
    pub fn admit(
        &mut self,
        peer_id: PeerId,
        metadata: CourierMetadata,
        encrypted_opaque_bytes: Vec<u8>,
        now_ms: u64,
    ) -> Result<QueueReceipt, DropReason> {
        metadata.validate_at(now_ms)?;
        if encrypted_opaque_bytes.is_empty() {
            return Err(DropReason::EmptyOpaqueBytes);
        }
        let object_bytes = encrypted_opaque_bytes.len();
        if object_bytes > self.limits.max_object_bytes {
            return Err(DropReason::ObjectTooLarge);
        }
        if object_bytes > self.limits.max_peer_bytes
            || object_bytes > self.limits.max_total_bytes
            || self.limits.max_peer_items == 0
            || self.limits.max_total_items == 0
        {
            return Err(DropReason::QuotaExceeded);
        }

        // Expired entries no longer participate in duplicate suppression or
        // quota accounting. The caller's explicit time controls this cleanup.
        self.purge_expired(now_ms)?;

        if self.envelope_sequences.contains_key(&metadata.envelope_id) {
            return Err(DropReason::DuplicateEnvelope);
        }
        if self.event_sequences.contains_key(&metadata.event_id) {
            return Err(DropReason::DuplicateEvent);
        }

        let sequence = self.next_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(DropReason::SequenceExhausted)?;
        self.make_room(peer_id, object_bytes)?;

        let old_peer_usage = self.peer_usage(peer_id);
        let peer_usage = Usage {
            items: old_peer_usage
                .items
                .checked_add(1)
                .ok_or(DropReason::AccountingOverflow)?,
            bytes: old_peer_usage
                .bytes
                .checked_add(object_bytes)
                .ok_or(DropReason::AccountingOverflow)?,
        };
        let total_usage = Usage {
            items: self
                .total_usage
                .items
                .checked_add(1)
                .ok_or(DropReason::AccountingOverflow)?,
            bytes: self
                .total_usage
                .bytes
                .checked_add(object_bytes)
                .ok_or(DropReason::AccountingOverflow)?,
        };

        let envelope_id = metadata.envelope_id();
        let event_id = metadata.event_id();
        let entry = CachedEnvelope {
            peer_id,
            metadata,
            encrypted_opaque_bytes: encrypted_opaque_bytes.into_boxed_slice(),
            sequence,
        };
        self.entries.insert(sequence, entry);
        self.envelope_sequences.insert(envelope_id, sequence);
        self.event_sequences.insert(event_id, sequence);
        self.peer_sequences
            .entry(peer_id)
            .or_default()
            .insert(sequence);
        self.peer_usage.insert(peer_id, peer_usage);
        self.total_usage = total_usage;
        self.next_sequence = next_sequence;

        Ok(QueueReceipt {
            peer_id,
            envelope_id,
            sequence,
        })
    }

    fn make_room(&mut self, peer_id: PeerId, incoming_bytes: usize) -> Result<(), DropReason> {
        loop {
            let usage = self.peer_usage(peer_id);
            if !exceeds(usage.items, 1, self.limits.max_peer_items)
                && !exceeds(usage.bytes, incoming_bytes, self.limits.max_peer_bytes)
            {
                break;
            }
            let sequence = self
                .peer_sequences
                .get(&peer_id)
                .and_then(|sequences| sequences.iter().next().copied())
                .ok_or(DropReason::AccountingInvariantViolation)?;
            self.remove_sequence(sequence)?;
        }

        loop {
            if !exceeds(self.total_usage.items, 1, self.limits.max_total_items)
                && !exceeds(
                    self.total_usage.bytes,
                    incoming_bytes,
                    self.limits.max_total_bytes,
                )
            {
                break;
            }
            let sequence = self
                .entries
                .keys()
                .next()
                .copied()
                .ok_or(DropReason::AccountingInvariantViolation)?;
            self.remove_sequence(sequence)?;
        }
        Ok(())
    }

    fn remove_sequence(&mut self, sequence: u64) -> Result<CachedEnvelope, DropReason> {
        let entry = self
            .entries
            .get(&sequence)
            .ok_or(DropReason::AccountingInvariantViolation)?;
        let peer_id = entry.peer_id;
        let envelope_id = entry.metadata.envelope_id;
        let event_id = entry.metadata.event_id;
        let byte_count = entry.encrypted_opaque_bytes.len();

        let next_total_usage = Usage {
            items: self
                .total_usage
                .items
                .checked_sub(1)
                .ok_or(DropReason::AccountingInvariantViolation)?,
            bytes: self
                .total_usage
                .bytes
                .checked_sub(byte_count)
                .ok_or(DropReason::AccountingInvariantViolation)?,
        };
        let peer_usage = self
            .peer_usage
            .get(&peer_id)
            .copied()
            .ok_or(DropReason::AccountingInvariantViolation)?;
        let next_peer_usage = Usage {
            items: peer_usage
                .items
                .checked_sub(1)
                .ok_or(DropReason::AccountingInvariantViolation)?,
            bytes: peer_usage
                .bytes
                .checked_sub(byte_count)
                .ok_or(DropReason::AccountingInvariantViolation)?,
        };

        let entry = self
            .entries
            .remove(&sequence)
            .ok_or(DropReason::AccountingInvariantViolation)?;
        self.envelope_sequences.remove(&envelope_id);
        self.event_sequences.remove(&event_id);
        let remove_peer_set = if let Some(sequences) = self.peer_sequences.get_mut(&peer_id) {
            sequences.remove(&sequence);
            sequences.is_empty()
        } else {
            return Err(DropReason::AccountingInvariantViolation);
        };
        if remove_peer_set {
            self.peer_sequences.remove(&peer_id);
        }
        if next_peer_usage.items == 0 {
            self.peer_usage.remove(&peer_id);
        } else {
            self.peer_usage.insert(peer_id, next_peer_usage);
        }
        self.total_usage = next_total_usage;
        Ok(entry)
    }
}

fn exceeds(current: usize, incoming: usize, limit: usize) -> bool {
    match current.checked_add(incoming) {
        Some(total) => total > limit,
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW_MS: u64 = 1_000;

    fn id(value: u8) -> [u8; 16] {
        [value; 16]
    }

    fn event_id(value: u8) -> [u8; 32] {
        [value; 32]
    }

    fn metadata(envelope: u8, event: u8) -> CourierMetadata {
        CourierMetadata::new(
            EnvelopeId::new(id(envelope)),
            EventId::new(event_id(event)),
            NOW_MS + 100,
            8,
            4,
            TrafficClass::Interactive,
        )
    }

    fn cache(limits: CourierLimits) -> CourierCache {
        CourierCache::new(limits).expect("test limits stay beneath hard bounds")
    }

    fn limits() -> CourierLimits {
        CourierLimits::new(8, 16, 4, 32, 8)
    }

    #[test]
    fn rejects_caller_limits_above_each_hard_cache_ceiling() {
        let cases = [
            (
                CourierLimits::new(HARD_MAX_OBJECT_BYTES + 1, 1, 1, 1, 1),
                LimitError::ObjectBytesAboveHardLimit,
            ),
            (
                CourierLimits::new(1, HARD_MAX_PEER_BYTES + 1, 1, 1, 1),
                LimitError::PeerBytesAboveHardLimit,
            ),
            (
                CourierLimits::new(1, 1, HARD_MAX_PEER_ITEMS + 1, 1, 1),
                LimitError::PeerItemsAboveHardLimit,
            ),
            (
                CourierLimits::new(1, 1, 1, HARD_MAX_TOTAL_BYTES + 1, 1),
                LimitError::TotalBytesAboveHardLimit,
            ),
            (
                CourierLimits::new(1, 1, 1, 1, HARD_MAX_TOTAL_ITEMS + 1),
                LimitError::TotalItemsAboveHardLimit,
            ),
        ];

        for (limits, expected) in cases {
            assert_eq!(limits.validate(), Err(expected));
            assert_eq!(CourierCache::new(limits).err(), Some(expected));
        }
    }

    #[test]
    fn rejects_expired_envelopes_and_expiry_boundary() {
        let mut cache = cache(limits());
        let mut expired = metadata(1, 11);
        expired.expires_at_ms = NOW_MS;

        assert_eq!(
            cache.admit(PeerId::new(id(1)), expired, vec![1], NOW_MS),
            Err(DropReason::Expired)
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn rewrapped_event_is_deduplicated_by_event_identity_after_source_transfer() {
        let peer = PeerId::new(id(1));
        let mut source = cache(limits());
        let mut destination = cache(limits());
        source
            .admit(peer, metadata(1, 21), vec![0xaa], NOW_MS)
            .expect("source envelope queues");
        destination
            .admit(peer, metadata(3, 21), vec![0xcc], NOW_MS)
            .expect("already-seen event queues at destination");

        let (transferred_peer, rewrapped, bytes) = source
            .take_for_relay(EnvelopeId::new(id(1)), EnvelopeId::new(id(4)), NOW_MS)
            .expect("relay consumes source and reduces copy budget");
        assert_eq!(transferred_peer, peer);
        assert_eq!(rewrapped.envelope_id(), EnvelopeId::new(id(4)));
        assert_eq!(rewrapped.event_id(), EventId::new(event_id(21)));
        assert_eq!(rewrapped.remaining_copy_budget(), 3);
        assert_eq!(bytes.as_ref(), &[0xaa]);
        assert!(source.is_empty());
        assert_eq!(
            destination.admit(peer, rewrapped, bytes.into_vec(), NOW_MS),
            Err(DropReason::DuplicateEvent)
        );

        assert_eq!(
            destination.admit(peer, metadata(3, 22), vec![0xdd], NOW_MS),
            Err(DropReason::DuplicateEnvelope)
        );
        assert_eq!(destination.len(), 1);
    }

    #[test]
    fn enforces_nonempty_object_and_per_peer_and_global_byte_quotas() {
        let peer = PeerId::new(id(1));
        let mut object_limited = cache(CourierLimits::new(4, 8, 4, 16, 4));
        assert_eq!(
            object_limited.admit(peer, metadata(1, 31), Vec::new(), NOW_MS),
            Err(DropReason::EmptyOpaqueBytes)
        );
        assert_eq!(
            object_limited.admit(peer, metadata(2, 32), vec![1, 2, 3, 4, 5], NOW_MS),
            Err(DropReason::ObjectTooLarge)
        );

        let mut peer_limited = cache(CourierLimits::new(4, 2, 4, 8, 4));
        assert_eq!(
            peer_limited.admit(peer, metadata(3, 33), vec![1, 2, 3], NOW_MS),
            Err(DropReason::QuotaExceeded)
        );
        assert!(peer_limited.is_empty());

        let mut globally_limited = cache(CourierLimits::new(4, 8, 4, 2, 4));
        assert_eq!(
            globally_limited.admit(peer, metadata(4, 34), vec![1, 2, 3], NOW_MS),
            Err(DropReason::QuotaExceeded)
        );
        assert!(globally_limited.is_empty());

        globally_limited
            .admit(peer, metadata(5, 35), vec![1, 2], NOW_MS)
            .expect("item exactly at global byte bound queues");
        assert_eq!(globally_limited.total_usage(), Usage { items: 1, bytes: 2 });
        assert_eq!(
            globally_limited.peer_usage(peer),
            Usage { items: 1, bytes: 2 }
        );
    }

    #[test]
    fn global_byte_eviction_is_fifo() {
        let limits = CourierLimits::new(4, 8, 4, 5, 3);
        let mut cache = cache(limits);
        let peer_a = PeerId::new(id(1));
        let peer_b = PeerId::new(id(2));
        let first = cache
            .admit(peer_a, metadata(1, 41), vec![1, 1], NOW_MS)
            .expect("first entry queues");
        let second = cache
            .admit(peer_a, metadata(2, 42), vec![2, 2], NOW_MS)
            .expect("second entry queues");

        let third = cache
            .admit(peer_b, metadata(3, 43), vec![3, 3], NOW_MS)
            .expect("global byte quota evicts the oldest courier entry");
        assert!(cache.get(first.envelope_id()).is_none());
        assert_eq!(
            cache
                .get(second.envelope_id())
                .map(CachedEnvelope::sequence),
            Some(second.sequence())
        );
        assert_eq!(
            cache.get(third.envelope_id()).map(CachedEnvelope::sequence),
            Some(third.sequence())
        );
        assert_eq!(first.sequence(), 0);
        assert!(second.sequence() < third.sequence());
        assert_eq!(cache.total_usage(), Usage { items: 2, bytes: 4 });
        assert_eq!(cache.peer_usage(peer_a), Usage { items: 1, bytes: 2 });
        assert_eq!(cache.peer_usage(peer_b), Usage { items: 1, bytes: 2 });
    }

    #[test]
    fn peer_byte_quota_evicts_oldest_courier_entry() {
        let mut cache = cache(CourierLimits::new(4, 3, 4, 8, 4));
        let peer = PeerId::new(id(8));
        let first = cache
            .admit(peer, metadata(1, 47), vec![1, 1], NOW_MS)
            .expect("first peer entry queues");
        let second = cache
            .admit(peer, metadata(2, 48), vec![2, 2], NOW_MS)
            .expect("peer byte quota evicts its oldest entry");

        assert!(cache.get(first.envelope_id()).is_none());
        assert!(cache.get(second.envelope_id()).is_some());
        assert_eq!(cache.peer_usage(peer), Usage { items: 1, bytes: 2 });
    }

    #[test]
    fn global_item_quota_evicts_oldest_when_bytes_still_fit() {
        let mut cache = cache(CourierLimits::new(4, 8, 4, 12, 2));
        let first = cache
            .admit(PeerId::new(id(1)), metadata(1, 44), vec![1], NOW_MS)
            .expect("first item queues");
        let second = cache
            .admit(PeerId::new(id(2)), metadata(2, 45), vec![2], NOW_MS)
            .expect("second item queues");
        let third = cache
            .admit(PeerId::new(id(3)), metadata(3, 46), vec![3], NOW_MS)
            .expect("global item quota evicts oldest despite available byte capacity");

        assert!(cache.get(first.envelope_id()).is_none());
        assert!(cache.get(second.envelope_id()).is_some());
        assert!(cache.get(third.envelope_id()).is_some());
        assert_eq!(cache.total_usage(), Usage { items: 2, bytes: 2 });
    }

    #[test]
    fn peer_eviction_is_fifo_and_relay_transfer_checks_copy_budget() {
        let peer_limits = CourierLimits::new(4, 4, 1, 12, 4);
        let mut peer_cache = cache(peer_limits);
        let peer = PeerId::new(id(7));
        let first = peer_cache
            .admit(peer, metadata(1, 51), vec![1], NOW_MS)
            .expect("first entry queues");
        let second = peer_cache
            .admit(peer, metadata(2, 52), vec![2], NOW_MS)
            .expect("peer item quota evicts the oldest entry");
        assert!(peer_cache.get(first.envelope_id()).is_none());
        assert!(peer_cache.get(second.envelope_id()).is_some());

        let mut exhausted = metadata(3, 53);
        exhausted.remaining_copy_budget = 0;
        let mut relay_cache = cache(limits());
        relay_cache
            .admit(peer, exhausted, vec![3], NOW_MS)
            .expect("zero remaining copies may be queued but cannot relay");
        assert_eq!(
            relay_cache.take_for_relay(EnvelopeId::new(id(3)), EnvelopeId::new(id(4)), NOW_MS),
            Err(DropReason::HopBudgetExhausted)
        );
        assert_eq!(relay_cache.len(), 1);

        let mut expiry_cache = cache(limits());
        expiry_cache
            .admit(peer, metadata(5, 54), vec![5], NOW_MS)
            .expect("unexpired entry queues");
        assert_eq!(
            expiry_cache.take_for_relay(
                EnvelopeId::new(id(5)),
                EnvelopeId::new(id(6)),
                NOW_MS + 100
            ),
            Err(DropReason::Expired)
        );
        assert_eq!(expiry_cache.len(), 1);
    }
}
