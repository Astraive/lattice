//! Bounded scoped anti-entropy over authenticated direct transports.
//!
//! Noise identity binding and scope authorization are required before sync
//! frames or repository records are accessed. Bytes remain caller-validated
//! application input and are not committed by this transport layer.

use std::collections::BTreeSet;

use lattice_platform::{MAX_EVENT_BYTES, TransportError, TransportReceipt};
use lattice_sync::{
    AuthorId, AuthorSummary, EventId, GapReason, KnownEvent, MAX_AUTHORS, MAX_BATCH_EVENTS,
    MAX_DEPENDENCY_REQUESTS, MAX_EXPLICIT_GAPS, MAX_KNOWN_EVENTS, ScopeId, ScopeSummary,
    SequenceRange, SyncPlan, SyncRequestRange, UnavailableRange, UnresolvedHistory,
};
use sha2::{Digest, Sha256};

const WIRE_MAGIC: &[u8; 4] = b"LSYN";
const WIRE_VERSION: u8 = 1;
const WIRE_VERSION_V2: u8 = 2;
const REQUEST_KIND: u8 = 1;
const RESPONSE_KIND: u8 = 2;
const V2_INITIATOR_SUMMARY_KIND: u8 = 3;
const V2_RESPONDER_SUMMARY_KIND: u8 = 4;
const V2_REQUEST_KIND: u8 = 5;
const V2_RESPONSE_KIND: u8 = 6;
const WIRE_HEADER_BYTES: usize = 40;
const TARGET_BY_ID: u8 = 0;
const TARGET_BY_SEQUENCE: u8 = 1;

mod direct_session;
pub use direct_session::{
    AuthenticatedSyncError, AuthenticatedSyncExchange, AuthenticatedSyncServeResult,
    AuthenticatedSyncV2Exchange, AuthenticatedSyncV2ServeResult, execute_authenticated_sync_once,
    execute_authenticated_sync_v2_once, serve_authenticated_sync_request_once,
    serve_authenticated_sync_v2_once,
};
mod store_source;
pub use store_source::{StoreSyncEventSource, StoreSyncSummarySource};

/// Derives the opaque synchronization scope for one Space MLS generation.
///
/// Both direct peers must use this function for the same 16-byte Space ID and
/// 32-byte MLS group reference. The group reference keeps recovered generations
/// in separate sync scopes.
#[must_use]
pub fn space_generation_scope_id(space_id: &[u8; 16], group_reference: &[u8; 32]) -> ScopeId {
    let mut hasher = Sha256::new();
    hasher.update(b"lattice:direct-sync-scope:v1\0");
    hasher.update(space_id);
    hasher.update(group_reference);
    ScopeId::new(hasher.finalize().into())
}

/// Maximum requested event records in one exchange, inherited from sync's
/// bounded batch contract.
pub const MAX_SYNC_EXCHANGE_EVENTS: usize = MAX_BATCH_EVENTS as usize;

/// A locator in the peer's scoped event history.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SyncRequestTarget {
    /// Request one exact inner event ID, normally a known missing dependency.
    EventId(EventId),
    /// Request one event at an author's one-based sequence position.
    Sequence { author: AuthorId, sequence: u64 },
}

/// One event returned by a caller-owned repository, with opaque event bytes.
#[derive(Debug)]
pub struct SyncEventRecord {
    /// Event author supplied by the existing repository/validation layer.
    pub author: AuthorId,
    /// One-based author sequence.
    pub sequence: u64,
    /// Inner event identity, not any outer envelope identity.
    pub event_id: EventId,
    /// Exact event bytes; this crate does not parse or normalize them.
    pub bytes: Vec<u8>,
}

/// Resolves exact bounded requests against a local repository.
pub trait SyncEventSource {
    /// Returns the exact requested event, `None` if unavailable, or a source failure.
    ///
    /// # Errors
    ///
    /// Returns `SyncSourceError` when the repository cannot reliably resolve the
    /// target or its stored metadata is corrupt.
    fn load(
        &mut self,
        scope: ScopeId,
        target: SyncRequestTarget,
    ) -> Result<Option<SyncEventRecord>, SyncSourceError>;
}

impl<F> SyncEventSource for F
where
    F: FnMut(ScopeId, SyncRequestTarget) -> Result<Option<SyncEventRecord>, SyncSourceError>,
{
    fn load(
        &mut self,
        scope: ScopeId,
        target: SyncRequestTarget,
    ) -> Result<Option<SyncEventRecord>, SyncSourceError> {
        self(scope, target)
    }
}

/// Supplies one bounded per-scope summary after peer and scope authorization.
pub trait SyncSummarySource {
    /// Returns the summary for exactly the requested scope.
    ///
    /// # Errors
    ///
    /// Returns `SyncSourceError` if the summary cannot be read reliably.
    fn load_summary(&mut self, scope: ScopeId) -> Result<ScopeSummary, SyncSourceError>;
}

impl<F> SyncSummarySource for F
where
    F: FnMut(ScopeId) -> Result<ScopeSummary, SyncSourceError>,
{
    fn load_summary(&mut self, scope: ScopeId) -> Result<ScopeSummary, SyncSourceError> {
        self(scope)
    }
}

/// A source-level storage or decoding failure, separate from an unavailable record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncSourceError(String);

impl SyncSourceError {
    /// Wraps a safe source diagnostic for propagation to the sync caller.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for SyncSourceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for SyncSourceError {}

/// Existing application validation boundary for opaque sync event bytes.
pub trait SyncEventValidator {
    /// Validation diagnostics owned by the application boundary.
    type Error;

    /// Validates bytes in the supplied scope/author/sequence context and returns
    /// the verified inner event ID. Implementations should check all contextual
    /// fields and authorization required by their existing acceptance path.
    ///
    /// # Errors
    ///
    /// Returns the validator's error if the event bytes do not satisfy its
    /// existing identity, signature, scope, or authorization checks.
    fn validate(
        &mut self,
        scope: ScopeId,
        author: AuthorId,
        sequence: u64,
        expected_event_id: Option<EventId>,
        bytes: &[u8],
    ) -> Result<EventId, Self::Error>;
}

impl<F, E> SyncEventValidator for F
where
    F: FnMut(ScopeId, AuthorId, u64, Option<EventId>, &[u8]) -> Result<EventId, E>,
{
    type Error = E;

    fn validate(
        &mut self,
        scope: ScopeId,
        author: AuthorId,
        sequence: u64,
        expected_event_id: Option<EventId>,
        bytes: &[u8],
    ) -> Result<EventId, Self::Error> {
        self(scope, author, sequence, expected_event_id, bytes)
    }
}

/// Exact status of the one request send attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HopOutcome {
    /// No send was attempted (for example, the plan had no requests).
    NotAttempted,
    /// The exact transport adapter receipt; this is never recipient delivery.
    Accepted(TransportReceipt),
    /// The adapter rejected or failed the send.
    Failed(TransportError),
    /// Cancellation won before a send receipt was produced.
    Cancelled,
}

/// Exact status of receiving the single reply frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncReceiveOutcome {
    /// No reply was requested.
    NotAttempted,
    /// One syntactically valid, scope-matching reply was received.
    Received,
    /// The peer closed the transport before a reply arrived.
    Closed,
    /// The adapter failed while receiving.
    Failed(TransportError),
    /// The incoming frame failed the bounded sync wire checks.
    Rejected(SyncProtocolError),
    /// Cancellation won while waiting for the reply.
    Cancelled,
}

/// Bounded wire protocol failures; event bytes are never interpreted here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncProtocolError {
    Truncated,
    InvalidMagic,
    UnsupportedVersion,
    UnexpectedMessage,
    ScopeMismatch,
    InvalidCount,
    InvalidTarget,
    DuplicateTarget,
    UnrequestedTarget,
    InvalidEvent,
    InvalidLength,
    TrailingBytes,
}

/// Why one returned record did not resolve its request.
#[derive(Debug)]
pub enum SyncEventRejection<E> {
    Validation(E),
    AdvertisedIdMismatch,
    SummaryIdMismatch,
}

/// One event that passed the caller validator and was first-seen by the
/// bounded inner-event-ID deduplicator. This module does not commit it.
#[derive(Debug)]
pub struct ValidatedSyncEvent {
    pub author: AuthorId,
    pub sequence: u64,
    pub event_id: EventId,
    pub bytes: Vec<u8>,
}

/// Result of one bounded client-side sync exchange.
#[derive(Debug)]
pub struct SyncExchange<E> {
    /// The scoped anti-entropy plan, including retained-history gaps.
    pub plan: SyncPlan,
    /// Exact send outcome for the request frame.
    pub request_hop: HopOutcome,
    /// Whether and how the one reply was received.
    pub response: SyncReceiveOutcome,
    /// Exact requests placed on the wire (zero to 128).
    pub requested: Vec<SyncRequestTarget>,
    /// Events validated by the caller and accepted as first-seen inner IDs.
    pub events: Vec<ValidatedSyncEvent>,
    /// Requests answered by an already-seen inner event ID.
    pub duplicates: Vec<EventId>,
    /// Returned event records that failed caller or identity validation.
    pub rejected_events: Vec<(SyncRequestTarget, SyncEventRejection<E>)>,
    /// Exact dependency IDs still not resolved by this one exchange.
    pub unresolved_dependencies: Vec<EventId>,
    /// Exact sequence ranges still not resolved by this one exchange.
    pub unresolved_ranges: Vec<SyncRequestRange>,
    /// Historical gaps reported by the planner and not made requestable.
    pub unresolved_history: Vec<UnresolvedHistory>,
}

/// Receive-side status for one call to [`serve_authenticated_sync_request_once`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncServeReceiveOutcome {
    Received,
    Closed,
    Failed(TransportError),
    Cancelled,
}

/// Result of receiving one request and optionally sending one bounded response.
#[derive(Debug)]
pub struct SyncServeResult {
    pub receive: SyncServeReceiveOutcome,
    /// Exact send outcome for the reply frame.
    pub response_hop: HopOutcome,
    /// Number of records encoded in the response candidate; this does not
    /// imply that a reply was sent or that the peer received or accepted them.
    pub included_events: usize,
    /// Requests not answered because no matching event was available or the
    /// response frame byte cap did not leave room for them.
    pub omitted_targets: Vec<SyncRequestTarget>,
}

fn bounded_targets(
    plan: &SyncPlan,
    max_frame_bytes: usize,
) -> (Vec<SyncRequestTarget>, Vec<EventId>, Vec<SyncRequestRange>) {
    let mut targets = Vec::with_capacity(MAX_SYNC_EXCHANGE_EVENTS);
    let mut unresolved_dependencies = Vec::new();
    let mut unresolved_ranges = Vec::new();
    let mut remaining_bytes = max_frame_bytes.saturating_sub(WIRE_HEADER_BYTES);
    if !plan.dependency_requests.is_empty() {
        for (index, event_id) in plan.dependency_requests.iter().copied().enumerate() {
            if targets.len() == MAX_SYNC_EXCHANGE_EVENTS || remaining_bytes < 33 {
                unresolved_dependencies.extend(plan.dependency_requests[index..].iter().copied());
                break;
            }
            targets.push(SyncRequestTarget::EventId(event_id));
            remaining_bytes -= 33;
        }
        return (targets, unresolved_dependencies, unresolved_ranges);
    }

    for (range_index, request) in plan.request_ranges.iter().enumerate() {
        let mut sequence = request.range.start();
        loop {
            if targets.len() == MAX_SYNC_EXCHANGE_EVENTS || remaining_bytes < 41 {
                unresolved_ranges.push(SyncRequestRange {
                    author: request.author,
                    range: lattice_sync::SequenceRange::new(sequence, request.range.end())
                        .expect("remaining sequence range is non-empty"),
                });
                unresolved_ranges.extend_from_slice(&plan.request_ranges[range_index + 1..]);
                return (targets, unresolved_dependencies, unresolved_ranges);
            }
            targets.push(SyncRequestTarget::Sequence {
                author: request.author,
                sequence,
            });
            remaining_bytes -= 41;
            if sequence == request.range.end() {
                break;
            }
            sequence += 1;
        }
    }
    (targets, unresolved_dependencies, unresolved_ranges)
}

fn request_targets_are_planned(plan: &SyncPlan, targets: &[SyncRequestTarget]) -> bool {
    let (planned, _, _) = bounded_targets(plan, usize::MAX);
    targets.iter().all(|target| planned.contains(target))
}
fn encode_request(scope: ScopeId, targets: &[SyncRequestTarget]) -> Vec<u8> {
    let target_bytes = targets.iter().copied().map(target_wire_size).sum::<usize>();
    let mut bytes = Vec::with_capacity(WIRE_HEADER_BYTES + target_bytes);
    bytes.extend_from_slice(WIRE_MAGIC);
    bytes.push(WIRE_VERSION);
    bytes.push(REQUEST_KIND);
    bytes.extend_from_slice(scope.as_bytes());
    let count = u16::try_from(targets.len()).expect("request count is bounded");
    bytes.extend_from_slice(&count.to_be_bytes());
    for target in targets {
        encode_target(&mut bytes, *target);
    }
    bytes
}

fn response_header(scope: ScopeId) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(WIRE_HEADER_BYTES);
    bytes.extend_from_slice(WIRE_MAGIC);
    bytes.push(WIRE_VERSION);
    bytes.push(RESPONSE_KIND);
    bytes.extend_from_slice(scope.as_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes
}

fn encode_target(bytes: &mut Vec<u8>, target: SyncRequestTarget) {
    match target {
        SyncRequestTarget::EventId(event_id) => {
            bytes.push(TARGET_BY_ID);
            bytes.extend_from_slice(event_id.as_bytes());
        }
        SyncRequestTarget::Sequence { author, sequence } => {
            bytes.push(TARGET_BY_SEQUENCE);
            bytes.extend_from_slice(author.as_bytes());
            bytes.extend_from_slice(&sequence.to_be_bytes());
        }
    }
}

fn decode_request(
    bytes: &[u8],
    expected_scope: ScopeId,
) -> Result<Vec<SyncRequestTarget>, SyncProtocolError> {
    let mut reader = Reader::new(bytes);
    reader.header(REQUEST_KIND, expected_scope)?;
    let count = usize::from(reader.u16()?);
    if count > MAX_SYNC_EXCHANGE_EVENTS {
        return Err(SyncProtocolError::InvalidCount);
    }
    let mut targets = Vec::with_capacity(count);
    let mut unique = BTreeSet::new();
    for _ in 0..count {
        let target = reader.target()?;
        if !unique.insert(target) {
            return Err(SyncProtocolError::DuplicateTarget);
        }
        targets.push(target);
    }
    reader.finish()?;
    Ok(targets)
}

fn decode_response<'a>(
    bytes: &'a [u8],
    expected_scope: ScopeId,
    requested: &BTreeSet<SyncRequestTarget>,
) -> Result<Vec<WireEvent<'a>>, SyncProtocolError> {
    let mut reader = Reader::new(bytes);
    reader.header(RESPONSE_KIND, expected_scope)?;
    let count = usize::from(reader.u16()?);
    if count > MAX_SYNC_EXCHANGE_EVENTS {
        return Err(SyncProtocolError::InvalidCount);
    }
    let mut events = Vec::with_capacity(count);
    let mut unique = BTreeSet::new();
    for _ in 0..count {
        let target = reader.target()?;
        if !requested.contains(&target) {
            return Err(SyncProtocolError::UnrequestedTarget);
        }
        if !unique.insert(target) {
            return Err(SyncProtocolError::DuplicateTarget);
        }
        let author = AuthorId::new(reader.array32()?);
        let sequence = reader.u64()?;
        let event_id = EventId::new(reader.array32()?);
        let length =
            usize::try_from(reader.u32()?).map_err(|_| SyncProtocolError::InvalidLength)?;
        if sequence == 0 || length == 0 || length > MAX_EVENT_BYTES {
            return Err(SyncProtocolError::InvalidEvent);
        }
        if let SyncRequestTarget::Sequence {
            author: requested_author,
            sequence: requested_sequence,
        } = target
            && (author != requested_author || sequence != requested_sequence)
        {
            return Err(SyncProtocolError::InvalidEvent);
        }
        let event_bytes = reader.take(length)?;
        events.push(WireEvent {
            target,
            author,
            sequence,
            event_id,
            bytes: event_bytes,
        });
    }
    reader.finish()?;
    Ok(events)
}

fn v2_header(scope: ScopeId, kind: u8, count: usize) -> Result<Vec<u8>, SyncProtocolError> {
    let count = u16::try_from(count).map_err(|_| SyncProtocolError::InvalidCount)?;
    let mut bytes = Vec::with_capacity(WIRE_HEADER_BYTES);
    bytes.extend_from_slice(WIRE_MAGIC);
    bytes.push(WIRE_VERSION_V2);
    bytes.push(kind);
    bytes.extend_from_slice(scope.as_bytes());
    bytes.extend_from_slice(&count.to_be_bytes());
    Ok(bytes)
}

fn encode_v2_summary(
    summary: &ScopeSummary,
    kind: u8,
    max_frame_bytes: usize,
) -> Result<Vec<u8>, SyncProtocolError> {
    let author_count = summary.authors.len();
    let dependency_count = summary.missing_dependencies.len();
    if author_count > MAX_AUTHORS || dependency_count > MAX_DEPENDENCY_REQUESTS {
        return Err(SyncProtocolError::InvalidCount);
    }
    let mut known_count = 0_usize;
    let mut gap_count = 0_usize;
    let mut size = WIRE_HEADER_BYTES
        .checked_add(2)
        .and_then(|size| size.checked_add(dependency_count.checked_mul(32)?))
        .ok_or(SyncProtocolError::InvalidLength)?;
    for author in &summary.authors {
        known_count = known_count
            .checked_add(author.known_events.len())
            .ok_or(SyncProtocolError::InvalidCount)?;
        gap_count = gap_count
            .checked_add(author.unavailable.len())
            .ok_or(SyncProtocolError::InvalidCount)?;
        if author.known_events.iter().any(|known| known.sequence == 0) {
            return Err(SyncProtocolError::InvalidEvent);
        }
        let known_bytes = author
            .known_events
            .len()
            .checked_mul(40)
            .ok_or(SyncProtocolError::InvalidLength)?;
        let gap_bytes = author
            .unavailable
            .len()
            .checked_mul(17)
            .ok_or(SyncProtocolError::InvalidLength)?;
        size = size
            .checked_add(44)
            .and_then(|size| size.checked_add(known_bytes))
            .and_then(|size| size.checked_add(gap_bytes))
            .ok_or(SyncProtocolError::InvalidLength)?;
    }
    if known_count > MAX_KNOWN_EVENTS || gap_count > MAX_EXPLICIT_GAPS {
        return Err(SyncProtocolError::InvalidCount);
    }
    if size > max_frame_bytes {
        return Err(SyncProtocolError::InvalidLength);
    }
    let mut bytes = v2_header(summary.scope, kind, author_count)?;
    bytes.reserve(size - WIRE_HEADER_BYTES);
    let dependency_count =
        u16::try_from(dependency_count).map_err(|_| SyncProtocolError::InvalidCount)?;
    bytes.extend_from_slice(&dependency_count.to_be_bytes());
    for author in &summary.authors {
        bytes.extend_from_slice(author.author.as_bytes());
        bytes.extend_from_slice(&author.contiguous_sequence.to_be_bytes());
        let known_count = u16::try_from(author.known_events.len())
            .map_err(|_| SyncProtocolError::InvalidCount)?;
        bytes.extend_from_slice(&known_count.to_be_bytes());
        let gap_count =
            u16::try_from(author.unavailable.len()).map_err(|_| SyncProtocolError::InvalidCount)?;
        bytes.extend_from_slice(&gap_count.to_be_bytes());
        for known in &author.known_events {
            bytes.extend_from_slice(&known.sequence.to_be_bytes());
            bytes.extend_from_slice(known.event_id.as_bytes());
        }
        for unavailable in &author.unavailable {
            bytes.extend_from_slice(&unavailable.range.start().to_be_bytes());
            bytes.extend_from_slice(&unavailable.range.end().to_be_bytes());
            bytes.push(match unavailable.reason {
                GapReason::Unknown => 0,
                GapReason::Retention => 1,
            });
        }
    }
    for dependency in &summary.missing_dependencies {
        bytes.extend_from_slice(dependency.as_bytes());
    }
    Ok(bytes)
}

fn decode_v2_summary(
    bytes: &[u8],
    expected_scope: ScopeId,
    expected_kind: u8,
) -> Result<ScopeSummary, SyncProtocolError> {
    let mut reader = Reader::new(bytes);
    reader.header_version(WIRE_VERSION_V2, expected_kind, expected_scope)?;
    let author_count = usize::from(reader.u16()?);
    let dependency_count = usize::from(reader.u16()?);
    if author_count > MAX_AUTHORS || dependency_count > MAX_DEPENDENCY_REQUESTS {
        return Err(SyncProtocolError::InvalidCount);
    }
    let mut known_total = 0_usize;
    let mut gap_total = 0_usize;
    let mut authors = Vec::with_capacity(author_count);
    for _ in 0..author_count {
        let author = AuthorId::new(reader.array32()?);
        let contiguous_sequence = reader.u64()?;
        let known_count = usize::from(reader.u16()?);
        let gap_count = usize::from(reader.u16()?);
        known_total = known_total
            .checked_add(known_count)
            .ok_or(SyncProtocolError::InvalidCount)?;
        gap_total = gap_total
            .checked_add(gap_count)
            .ok_or(SyncProtocolError::InvalidCount)?;
        if known_total > MAX_KNOWN_EVENTS || gap_total > MAX_EXPLICIT_GAPS {
            return Err(SyncProtocolError::InvalidCount);
        }
        let mut known_events = Vec::with_capacity(known_count);
        for _ in 0..known_count {
            let sequence = reader.u64()?;
            if sequence == 0 {
                return Err(SyncProtocolError::InvalidEvent);
            }
            known_events.push(KnownEvent {
                sequence,
                event_id: EventId::new(reader.array32()?),
            });
        }
        let mut unavailable = Vec::with_capacity(gap_count);
        for _ in 0..gap_count {
            let start = reader.u64()?;
            let end = reader.u64()?;
            let range =
                SequenceRange::new(start, end).map_err(|_| SyncProtocolError::InvalidEvent)?;
            let reason = match reader.u8()? {
                0 => GapReason::Unknown,
                1 => GapReason::Retention,
                _ => return Err(SyncProtocolError::InvalidEvent),
            };
            unavailable.push(UnavailableRange { range, reason });
        }
        authors.push(AuthorSummary {
            author,
            contiguous_sequence,
            known_events,
            unavailable,
        });
    }
    let mut missing_dependencies = Vec::with_capacity(dependency_count);
    for _ in 0..dependency_count {
        missing_dependencies.push(EventId::new(reader.array32()?));
    }
    reader.finish()?;
    Ok(ScopeSummary {
        scope: expected_scope,
        authors,
        missing_dependencies,
    })
}

fn encode_v2_request(
    scope: ScopeId,
    targets: &[SyncRequestTarget],
) -> Result<Vec<u8>, SyncProtocolError> {
    let target_bytes = targets.iter().copied().map(target_wire_size).sum::<usize>();
    let mut bytes = v2_header(scope, V2_REQUEST_KIND, targets.len())?;
    bytes.reserve(target_bytes);
    for target in targets {
        encode_target(&mut bytes, *target);
    }
    Ok(bytes)
}

fn encode_v2_response_header(scope: ScopeId) -> Result<Vec<u8>, SyncProtocolError> {
    v2_header(scope, V2_RESPONSE_KIND, 0)
}

fn decode_v2_request(
    bytes: &[u8],
    expected_scope: ScopeId,
) -> Result<Vec<SyncRequestTarget>, SyncProtocolError> {
    let mut reader = Reader::new(bytes);
    reader.header_version(WIRE_VERSION_V2, V2_REQUEST_KIND, expected_scope)?;
    let count = usize::from(reader.u16()?);
    if count > MAX_SYNC_EXCHANGE_EVENTS {
        return Err(SyncProtocolError::InvalidCount);
    }
    let mut targets = Vec::with_capacity(count);
    let mut unique = BTreeSet::new();
    for _ in 0..count {
        let target = reader.target()?;
        if !unique.insert(target) {
            return Err(SyncProtocolError::DuplicateTarget);
        }
        targets.push(target);
    }
    reader.finish()?;
    Ok(targets)
}

fn decode_v2_response<'a>(
    bytes: &'a [u8],
    expected_scope: ScopeId,
    requested: &BTreeSet<SyncRequestTarget>,
) -> Result<Vec<WireEvent<'a>>, SyncProtocolError> {
    let mut reader = Reader::new(bytes);
    reader.header_version(WIRE_VERSION_V2, V2_RESPONSE_KIND, expected_scope)?;
    let count = usize::from(reader.u16()?);
    if count > MAX_SYNC_EXCHANGE_EVENTS {
        return Err(SyncProtocolError::InvalidCount);
    }
    let mut events = Vec::with_capacity(count);
    let mut unique = BTreeSet::new();
    for _ in 0..count {
        let target = reader.target()?;
        if !requested.contains(&target) {
            return Err(SyncProtocolError::UnrequestedTarget);
        }
        if !unique.insert(target) {
            return Err(SyncProtocolError::DuplicateTarget);
        }
        let author = AuthorId::new(reader.array32()?);
        let sequence = reader.u64()?;
        let event_id = EventId::new(reader.array32()?);
        let length =
            usize::try_from(reader.u32()?).map_err(|_| SyncProtocolError::InvalidLength)?;
        if sequence == 0 || length == 0 || length > MAX_EVENT_BYTES {
            return Err(SyncProtocolError::InvalidEvent);
        }
        if let SyncRequestTarget::Sequence {
            author: requested_author,
            sequence: requested_sequence,
        } = target
            && (author != requested_author || sequence != requested_sequence)
        {
            return Err(SyncProtocolError::InvalidEvent);
        }
        events.push(WireEvent {
            target,
            author,
            sequence,
            event_id,
            bytes: reader.take(length)?,
        });
    }
    reader.finish()?;
    Ok(events)
}

fn record_matches_target(target: SyncRequestTarget, record: &SyncEventRecord) -> bool {
    match target {
        SyncRequestTarget::EventId(event_id) => record.event_id == event_id,
        SyncRequestTarget::Sequence { author, sequence } => {
            record.author == author && record.sequence == sequence
        }
    }
}

fn target_wire_size(target: SyncRequestTarget) -> usize {
    match target {
        SyncRequestTarget::EventId(_) => 1 + 32,
        SyncRequestTarget::Sequence { .. } => 1 + 32 + 8,
    }
}

fn known_summary_event(peer: &ScopeSummary, author: AuthorId, sequence: u64) -> Option<EventId> {
    peer.authors
        .iter()
        .find(|summary| summary.author == author)?
        .known_events
        .iter()
        .find(|known| known.sequence == sequence)
        .map(|known| known.event_id)
}

fn add_unresolved_target(
    target: SyncRequestTarget,
    dependencies: &mut Vec<EventId>,
    ranges: &mut Vec<SyncRequestRange>,
) {
    match target {
        SyncRequestTarget::EventId(event_id) => dependencies.push(event_id),
        SyncRequestTarget::Sequence { author, sequence } => {
            ranges.push(SyncRequestRange {
                author,
                range: lattice_sync::SequenceRange::new(sequence, sequence)
                    .expect("event sequence is nonzero"),
            });
        }
    }
}

fn sort_dedup(mut event_ids: Vec<EventId>) -> Vec<EventId> {
    event_ids.sort_unstable();
    event_ids.dedup();
    event_ids
}

fn normalize_ranges(mut ranges: Vec<SyncRequestRange>) -> Vec<SyncRequestRange> {
    ranges.sort_unstable_by_key(|request| {
        (request.author, request.range.start(), request.range.end())
    });
    let mut normalized: Vec<SyncRequestRange> = Vec::with_capacity(ranges.len());
    for request in ranges {
        if let Some(previous) = normalized.last_mut()
            && previous.author == request.author
            && (request.range.start() <= previous.range.end()
                || previous.range.end().checked_add(1) == Some(request.range.start()))
        {
            let end = previous.range.end().max(request.range.end());
            previous.range = lattice_sync::SequenceRange::new(previous.range.start(), end)
                .expect("normalized sequence range is valid");
        } else {
            normalized.push(request);
        }
    }
    normalized
}

struct WireEvent<'a> {
    target: SyncRequestTarget,
    author: AuthorId,
    sequence: u64,
    event_id: EventId,
    bytes: &'a [u8],
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn header(
        &mut self,
        expected_kind: u8,
        expected_scope: ScopeId,
    ) -> Result<(), SyncProtocolError> {
        self.header_version(WIRE_VERSION, expected_kind, expected_scope)
    }

    fn header_version(
        &mut self,
        expected_version: u8,
        expected_kind: u8,
        expected_scope: ScopeId,
    ) -> Result<(), SyncProtocolError> {
        if self.take(4)? != &WIRE_MAGIC[..] {
            return Err(SyncProtocolError::InvalidMagic);
        }
        if self.u8()? != expected_version {
            return Err(SyncProtocolError::UnsupportedVersion);
        }
        if self.u8()? != expected_kind {
            return Err(SyncProtocolError::UnexpectedMessage);
        }
        if self.array32()? != *expected_scope.as_bytes() {
            return Err(SyncProtocolError::ScopeMismatch);
        }
        Ok(())
    }

    fn target(&mut self) -> Result<SyncRequestTarget, SyncProtocolError> {
        match self.u8()? {
            TARGET_BY_ID => Ok(SyncRequestTarget::EventId(EventId::new(self.array32()?))),
            TARGET_BY_SEQUENCE => {
                let author = AuthorId::new(self.array32()?);
                let sequence = self.u64()?;
                if sequence == 0 {
                    return Err(SyncProtocolError::InvalidTarget);
                }
                Ok(SyncRequestTarget::Sequence { author, sequence })
            }
            _ => Err(SyncProtocolError::InvalidTarget),
        }
    }

    fn u8(&mut self) -> Result<u8, SyncProtocolError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, SyncProtocolError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| SyncProtocolError::Truncated)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, SyncProtocolError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| SyncProtocolError::Truncated)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, SyncProtocolError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| SyncProtocolError::Truncated)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn array32(&mut self) -> Result<[u8; 32], SyncProtocolError> {
        self.take(32)?
            .try_into()
            .map_err(|_| SyncProtocolError::Truncated)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], SyncProtocolError> {
        let end = self
            .position
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(SyncProtocolError::Truncated)?;
        let result = &self.bytes[self.position..end];
        self.position = end;
        Ok(result)
    }

    fn finish(&self) -> Result<(), SyncProtocolError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(SyncProtocolError::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use lattice_identity::{DeviceIdentity, PinnedIdentity};
    use lattice_router::EventDeduplicator;
    use lattice_sync::{AuthorSummary, KnownEvent, ScopeId, ScopeSummary};
    use lattice_transport::{TcpPeerAdapter, TcpPeerListener};
    use tokio_util::sync::CancellationToken;

    use super::{
        AuthenticatedSyncError, AuthenticatedSyncV2Exchange, AuthenticatedSyncV2ServeResult,
        HopOutcome, SyncEventRecord, SyncReceiveOutcome, SyncRequestTarget,
        SyncServeReceiveOutcome, SyncSourceError, execute_authenticated_sync_once,
        execute_authenticated_sync_v2_once, serve_authenticated_sync_request_once,
        serve_authenticated_sync_v2_once, space_generation_scope_id,
    };

    #[test]
    fn space_generation_scope_id_is_stable_and_separates_generations() {
        let space_id = [0x11; 16];
        let first_generation = [0x22; 32];
        let next_generation = [0x23; 32];

        assert_eq!(
            space_generation_scope_id(&space_id, &first_generation),
            space_generation_scope_id(&space_id, &first_generation)
        );
        assert_ne!(
            space_generation_scope_id(&space_id, &first_generation),
            space_generation_scope_id(&space_id, &next_generation)
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // Keeps the TCP exchange's security and data assertions together.
    async fn authenticates_pinned_identities_before_one_sync_round_trip_over_tcp() {
        let scope = ScopeId::new([0x31; 32]);
        let author = lattice_sync::AuthorId::new([0x42; 32]);
        let event_id = lattice_sync::EventId::new([0x53; 32]);
        let event_bytes = b"event bytes behind the authenticated direct channel".to_vec();
        let alice = DeviceIdentity::generate().expect("generate initiator identity");
        let bob = DeviceIdentity::generate().expect("generate responder identity");
        let alice_fingerprint = alice.fingerprint();
        let bob_fingerprint = bob.fingerprint();
        let alice_pins_bob =
            PinnedIdentity::from_verified_fingerprint(bob.public_bundle(), bob_fingerprint)
                .expect("pin exact responder bundle");
        let bob_pins_alice =
            PinnedIdentity::from_verified_fingerprint(alice.public_bundle(), alice_fingerprint)
                .expect("pin exact initiator bundle");

        let listener = TcpPeerListener::bind("127.0.0.1:0", 4096)
            .await
            .expect("bind ephemeral local test listener");
        let endpoint = listener.local_addr().expect("read bound address");
        let (client_result, server_result) =
            tokio::join!(TcpPeerAdapter::connect(endpoint, 4096), listener.accept(),);
        let client_adapter = client_result.expect("connect direct TCP adapter");
        let (server_adapter, _) = server_result.expect("accept direct TCP adapter");

        let local = ScopeSummary {
            scope,
            authors: vec![AuthorSummary::new(author, 0)],
            missing_dependencies: Vec::new(),
        };
        let peer = ScopeSummary {
            scope,
            authors: vec![AuthorSummary {
                author,
                contiguous_sequence: 1,
                known_events: vec![KnownEvent {
                    sequence: 1,
                    event_id,
                }],
                unavailable: Vec::new(),
            }],
            missing_dependencies: Vec::new(),
        };
        let mut deduplicator = EventDeduplicator::new(64).expect("bounded deduplicator");
        let expected_bytes = event_bytes.clone();
        let mut validator = move |actual_scope: ScopeId,
                                  actual_author: lattice_sync::AuthorId,
                                  sequence: u64,
                                  expected_event_id: Option<lattice_sync::EventId>,
                                  bytes: &[u8]| {
            if actual_scope == scope
                && actual_author == author
                && sequence == 1
                && expected_event_id == Some(event_id)
                && bytes == expected_bytes.as_slice()
            {
                Ok(event_id)
            } else {
                Err("caller validation rejected sync event")
            }
        };
        let requested_target = SyncRequestTarget::Sequence {
            author,
            sequence: 1,
        };
        let mut source = move |requested_scope, target| {
            Ok(if requested_scope == scope && target == requested_target {
                Some(SyncEventRecord {
                    author,
                    sequence: 1,
                    event_id,
                    bytes: event_bytes.clone(),
                })
            } else {
                None
            })
        };
        let client_cancellation = CancellationToken::new();
        let server_cancellation = CancellationToken::new();
        let (client, server) = tokio::join!(
            execute_authenticated_sync_once(
                &client_adapter,
                &alice,
                alice_pins_bob,
                &local,
                &peer,
                &mut deduplicator,
                &mut validator,
                |pinned, requested_scope| {
                    pinned.fingerprint() == bob_fingerprint && requested_scope == scope
                },
                &client_cancellation,
            ),
            serve_authenticated_sync_request_once(
                &server_adapter,
                &bob,
                bob_pins_alice,
                &mut source,
                |pinned, requested_scope| {
                    pinned.fingerprint() == alice_fingerprint && requested_scope == scope
                },
                &server_cancellation,
            ),
        );
        let client = client.expect("complete authenticated sync request and response");
        let server = server.expect("authorize and serve authenticated sync request");

        assert_eq!(client.authenticated_peer.fingerprint(), bob_fingerprint);
        assert_eq!(server.authenticated_peer.fingerprint(), alice_fingerprint);
        assert_eq!(client.exchange.requested.len(), 1);
        assert_eq!(client.exchange.response, SyncReceiveOutcome::Received);
        assert_eq!(client.exchange.events.len(), 1);
        assert_eq!(client.exchange.events[0].event_id, event_id);
        assert_eq!(
            client.exchange.events[0].bytes,
            b"event bytes behind the authenticated direct channel"
        );
        assert_eq!(server.authorized_scope, scope);
        assert_eq!(server.exchange.receive, SyncServeReceiveOutcome::Received);
        assert_eq!(server.exchange.included_events, 1);
        assert!(matches!(
            client.exchange.request_hop,
            HopOutcome::Accepted(_)
        ));
        assert!(matches!(
            server.exchange.response_hop,
            HopOutcome::Accepted(_)
        ));
    }

    #[tokio::test]
    async fn authenticated_empty_sync_still_completes_one_round_trip() {
        let scope = ScopeId::new([0x59; 32]);
        let author = lattice_sync::AuthorId::new([0x6a; 32]);
        let alice = DeviceIdentity::generate().expect("generate initiator identity");
        let bob = DeviceIdentity::generate().expect("generate responder identity");
        let alice_pins_bob =
            PinnedIdentity::from_verified_fingerprint(bob.public_bundle(), bob.fingerprint())
                .expect("pin exact responder bundle");
        let bob_pins_alice =
            PinnedIdentity::from_verified_fingerprint(alice.public_bundle(), alice.fingerprint())
                .expect("pin exact initiator bundle");
        let listener = TcpPeerListener::bind("127.0.0.1:0", 4096)
            .await
            .expect("bind ephemeral local test listener");
        let endpoint = listener.local_addr().expect("read bound address");
        let (client_result, server_result) =
            tokio::join!(TcpPeerAdapter::connect(endpoint, 4096), listener.accept(),);
        let client_adapter = client_result.expect("connect direct TCP adapter");
        let (server_adapter, _) = server_result.expect("accept direct TCP adapter");
        let summary = ScopeSummary {
            scope,
            authors: vec![AuthorSummary::new(author, 0)],
            missing_dependencies: Vec::new(),
        };
        let mut deduplicator = EventDeduplicator::new(64).expect("bounded deduplicator");
        let mut validator =
            |_: ScopeId,
             _: lattice_sync::AuthorId,
             _: u64,
             _: Option<lattice_sync::EventId>,
             _: &[u8]| Ok::<_, ()>(lattice_sync::EventId::new([0x7b; 32]));
        let source_calls = Cell::new(0);
        let mut source = |_: ScopeId, _: SyncRequestTarget| {
            source_calls.set(source_calls.get() + 1);
            Ok(None::<SyncEventRecord>)
        };

        let client_cancellation = CancellationToken::new();
        let server_cancellation = CancellationToken::new();
        let (client_result, server_result) = tokio::join!(
            execute_authenticated_sync_once(
                &client_adapter,
                &alice,
                alice_pins_bob,
                &summary,
                &summary,
                &mut deduplicator,
                &mut validator,
                |_, requested_scope| requested_scope == scope,
                &client_cancellation,
            ),
            serve_authenticated_sync_request_once(
                &server_adapter,
                &bob,
                bob_pins_alice,
                &mut source,
                |_, requested_scope| requested_scope == scope,
                &server_cancellation,
            ),
        );
        let client = client_result.expect("complete empty authenticated request");
        let server = server_result.expect("complete empty authenticated response");

        assert!(client.exchange.requested.is_empty());
        assert_eq!(client.exchange.response, SyncReceiveOutcome::Received);
        assert!(client.exchange.events.is_empty());
        assert_eq!(source_calls.get(), 0);
        assert_eq!(server.exchange.included_events, 0);
        assert!(matches!(
            client.exchange.request_hop,
            HopOutcome::Accepted(_)
        ));
        assert!(matches!(
            server.exchange.response_hop,
            HopOutcome::Accepted(_)
        ));
    }

    #[tokio::test]
    async fn authenticated_sync_propagates_event_source_failure() {
        let scope = ScopeId::new([0x18; 32]);
        let author = lattice_sync::AuthorId::new([0x29; 32]);
        let event_id = lattice_sync::EventId::new([0x3a; 32]);
        let alice = DeviceIdentity::generate().expect("generate initiator identity");
        let bob = DeviceIdentity::generate().expect("generate responder identity");
        let alice_pins_bob =
            PinnedIdentity::from_verified_fingerprint(bob.public_bundle(), bob.fingerprint())
                .expect("pin responder");
        let bob_pins_alice =
            PinnedIdentity::from_verified_fingerprint(alice.public_bundle(), alice.fingerprint())
                .expect("pin initiator");

        let listener = TcpPeerListener::bind("127.0.0.1:0", 4096)
            .await
            .expect("bind ephemeral test listener");
        let endpoint = listener.local_addr().expect("read listener address");
        let (client_result, server_result) =
            tokio::join!(TcpPeerAdapter::connect(endpoint, 4096), listener.accept());
        let client_adapter = client_result.expect("connect test adapter");
        let (server_adapter, _) = server_result.expect("accept test adapter");

        let local = ScopeSummary::new(scope);
        let peer = ScopeSummary {
            scope,
            authors: vec![AuthorSummary {
                author,
                contiguous_sequence: 1,
                known_events: vec![KnownEvent {
                    sequence: 1,
                    event_id,
                }],
                unavailable: Vec::new(),
            }],
            missing_dependencies: Vec::new(),
        };
        let mut deduplicator = EventDeduplicator::new(64).expect("bounded deduplicator");
        let mut validator = |_: ScopeId,
                             _: lattice_sync::AuthorId,
                             _: u64,
                             _: Option<lattice_sync::EventId>,
                             _: &[u8]| Ok::<_, ()>(event_id);
        let mut source = |_: ScopeId, _: SyncRequestTarget| {
            Err(SyncSourceError::new("test storage read failure"))
        };
        let client_cancellation = CancellationToken::new();
        let server_cancellation = CancellationToken::new();
        let client_future = execute_authenticated_sync_once(
            &client_adapter,
            &alice,
            alice_pins_bob,
            &local,
            &peer,
            &mut deduplicator,
            &mut validator,
            |_, requested_scope| requested_scope == scope,
            &client_cancellation,
        );
        let server_future = serve_authenticated_sync_request_once(
            &server_adapter,
            &bob,
            bob_pins_alice,
            &mut source,
            |_, requested_scope| requested_scope == scope,
            &server_cancellation,
        );
        tokio::pin!(client_future);
        tokio::pin!(server_future);
        tokio::select! {
            result = &mut server_future => {
                assert!(matches!(
                    &result,
                    Err(AuthenticatedSyncError::EventSource(error))
                        if error.to_string() == "test storage read failure"
                ));
                client_cancellation.cancel();
                assert!(matches!(
                    client_future.await,
                    Err(AuthenticatedSyncError::Cancelled)
                ));
            }
            _ = &mut client_future => panic!("client must not receive a successful empty response"),
        }
    }

    #[tokio::test]
    async fn denied_authenticated_scope_never_reaches_the_event_source() {
        let scope = ScopeId::new([0x61; 32]);
        let author = lattice_sync::AuthorId::new([0x72; 32]);
        let event_id = lattice_sync::EventId::new([0x83; 32]);
        let alice = DeviceIdentity::generate().expect("generate initiator identity");
        let bob = DeviceIdentity::generate().expect("generate responder identity");
        let alice_fingerprint = alice.fingerprint();
        let bob_fingerprint = bob.fingerprint();
        let alice_pins_bob =
            PinnedIdentity::from_verified_fingerprint(bob.public_bundle(), bob_fingerprint)
                .expect("pin exact responder bundle");
        let bob_pins_alice =
            PinnedIdentity::from_verified_fingerprint(alice.public_bundle(), alice_fingerprint)
                .expect("pin exact initiator bundle");

        let listener = TcpPeerListener::bind("127.0.0.1:0", 4096)
            .await
            .expect("bind ephemeral local test listener");
        let endpoint = listener.local_addr().expect("read bound address");
        let (client_result, server_result) =
            tokio::join!(TcpPeerAdapter::connect(endpoint, 4096), listener.accept(),);
        let client_adapter = client_result.expect("connect direct TCP adapter");
        let (server_adapter, _) = server_result.expect("accept direct TCP adapter");

        let local = ScopeSummary {
            scope,
            authors: vec![AuthorSummary::new(author, 0)],
            missing_dependencies: Vec::new(),
        };
        let peer = ScopeSummary {
            scope,
            authors: vec![AuthorSummary {
                author,
                contiguous_sequence: 1,
                known_events: vec![KnownEvent {
                    sequence: 1,
                    event_id,
                }],
                unavailable: Vec::new(),
            }],
            missing_dependencies: Vec::new(),
        };
        let mut deduplicator = EventDeduplicator::new(64).expect("bounded deduplicator");
        let mut validator = |_: ScopeId,
                             _: lattice_sync::AuthorId,
                             _: u64,
                             _: Option<lattice_sync::EventId>,
                             _: &[u8]| Ok::<_, ()>(event_id);
        let source_calls = Cell::new(0);
        let mut source = |_: ScopeId, _: SyncRequestTarget| {
            source_calls.set(source_calls.get() + 1);
            Ok(None::<SyncEventRecord>)
        };
        let client_cancellation = CancellationToken::new();
        let server_cancellation = CancellationToken::new();
        let client_future = execute_authenticated_sync_once(
            &client_adapter,
            &alice,
            alice_pins_bob,
            &local,
            &peer,
            &mut deduplicator,
            &mut validator,
            |_, requested_scope| requested_scope == scope,
            &client_cancellation,
        );
        let server_future = serve_authenticated_sync_request_once(
            &server_adapter,
            &bob,
            bob_pins_alice,
            &mut source,
            |_, _| false,
            &server_cancellation,
        );
        tokio::pin!(client_future);
        tokio::pin!(server_future);
        tokio::select! {
            result = &mut server_future => {
                assert!(matches!(result, Err(AuthenticatedSyncError::ScopeUnauthorized)));
                assert_eq!(source_calls.get(), 0);
                client_cancellation.cancel();
                assert!(matches!(
                    client_future.await,
                    Err(AuthenticatedSyncError::Cancelled)
                ));
            }
            _ = &mut client_future => panic!("client should wait after server denies the scope"),
        }
    }
    #[tokio::test]
    async fn mismatched_peer_pin_fails_before_scope_data_is_sent_or_loaded() {
        let scope = ScopeId::new([0x91; 32]);
        let alice = DeviceIdentity::generate().expect("generate initiator identity");
        let bob = DeviceIdentity::generate().expect("generate responder identity");
        let mallory = DeviceIdentity::generate().expect("generate wrong pinned identity");
        let alice_pins_mallory = PinnedIdentity::from_verified_fingerprint(
            mallory.public_bundle(),
            mallory.fingerprint(),
        )
        .expect("create internally consistent but incorrect pin");
        let bob_pins_alice =
            PinnedIdentity::from_verified_fingerprint(alice.public_bundle(), alice.fingerprint())
                .expect("pin exact initiator bundle");

        let listener = TcpPeerListener::bind("127.0.0.1:0", 4096)
            .await
            .expect("bind ephemeral local test listener");
        let endpoint = listener.local_addr().expect("read bound address");
        let (client_result, server_result) =
            tokio::join!(TcpPeerAdapter::connect(endpoint, 4096), listener.accept(),);
        let client_adapter = client_result.expect("connect direct TCP adapter");
        let (server_adapter, _) = server_result.expect("accept direct TCP adapter");

        let summary = ScopeSummary::new(scope);
        let mut deduplicator = EventDeduplicator::new(64).expect("bounded deduplicator");
        let mut validator =
            |_: ScopeId,
             _: lattice_sync::AuthorId,
             _: u64,
             _: Option<lattice_sync::EventId>,
             _: &[u8]| { Ok::<_, ()>(lattice_sync::EventId::new([0xa2; 32])) };
        let source_calls = Cell::new(0);
        let mut source = |_: ScopeId, _: SyncRequestTarget| {
            source_calls.set(source_calls.get() + 1);
            Ok(None::<SyncEventRecord>)
        };
        let client_cancellation = CancellationToken::new();
        let server_cancellation = CancellationToken::new();
        let server_future = serve_authenticated_sync_request_once(
            &server_adapter,
            &bob,
            bob_pins_alice,
            &mut source,
            |_, requested_scope| requested_scope == scope,
            &server_cancellation,
        );
        tokio::pin!(server_future);

        let server_result = {
            let client_future = execute_authenticated_sync_once(
                &client_adapter,
                &alice,
                alice_pins_mallory,
                &summary,
                &summary,
                &mut deduplicator,
                &mut validator,
                |_, requested_scope| requested_scope == scope,
                &client_cancellation,
            );
            tokio::pin!(client_future);
            tokio::select! {
                result = &mut server_future => result,
                _ = &mut client_future => panic!("mismatched peer pin must not authenticate"),
            }
        };
        assert!(matches!(
            server_result,
            Err(AuthenticatedSyncError::IdentityBinding)
        ));
        assert_eq!(source_calls.get(), 0);
    }

    #[allow(clippy::too_many_lines)]
    async fn authenticated_v2_pair(
        local_summary: ScopeSummary,
        remote_summary: ScopeSummary,
        requested_target: SyncRequestTarget,
        record: SyncEventRecord,
    ) -> (
        AuthenticatedSyncV2Exchange<&'static str>,
        AuthenticatedSyncV2ServeResult,
        Option<SyncRequestTarget>,
        usize,
        usize,
    ) {
        let scope = local_summary.scope;
        let event_id = record.event_id;
        let event_author = record.author;
        let event_sequence = record.sequence;
        let expected_bytes = record.bytes.clone();
        let alice = DeviceIdentity::generate().expect("generate v2 initiator identity");
        let bob = DeviceIdentity::generate().expect("generate v2 responder identity");
        let alice_fingerprint = alice.fingerprint();
        let bob_fingerprint = bob.fingerprint();
        let alice_pins_bob =
            PinnedIdentity::from_verified_fingerprint(bob.public_bundle(), bob_fingerprint)
                .expect("pin v2 responder");
        let bob_pins_alice =
            PinnedIdentity::from_verified_fingerprint(alice.public_bundle(), alice_fingerprint)
                .expect("pin v2 initiator");
        let listener = TcpPeerListener::bind("127.0.0.1:0", 4096)
            .await
            .expect("bind v2 local test listener");
        let endpoint = listener.local_addr().expect("read v2 listener address");
        let (client_result, server_result) =
            tokio::join!(TcpPeerAdapter::connect(endpoint, 4096), listener.accept());
        let client_adapter = client_result.expect("connect v2 test adapter");
        let (server_adapter, _) = server_result.expect("accept v2 test adapter");

        let mut deduplicator = EventDeduplicator::new(64).expect("bounded deduplicator");
        let mut validator = move |actual_scope: ScopeId,
                                  actual_author: lattice_sync::AuthorId,
                                  sequence: u64,
                                  expected_event_id: Option<lattice_sync::EventId>,
                                  bytes: &[u8]| {
            if actual_scope == scope
                && actual_author == event_author
                && sequence == event_sequence
                && expected_event_id == Some(event_id)
                && bytes == expected_bytes.as_slice()
            {
                Ok(event_id)
            } else {
                Err("caller validation rejected v2 sync event")
            }
        };
        let summary_calls = Cell::new(0);
        let mut summary_source = {
            let summary_calls = &summary_calls;
            let remote_summary = remote_summary.clone();
            move |actual_scope| {
                summary_calls.set(summary_calls.get() + 1);
                if actual_scope == remote_summary.scope {
                    Ok(remote_summary.clone())
                } else {
                    Err(SyncSourceError::new("wrong v2 summary scope"))
                }
            }
        };
        let event_calls = Cell::new(0);
        let last_target = Cell::new(None);
        let mut event_source = {
            let event_calls = &event_calls;
            let last_target = &last_target;
            let event_bytes = record.bytes;
            move |actual_scope, actual_target| {
                event_calls.set(event_calls.get() + 1);
                last_target.set(Some(actual_target));
                if actual_scope == scope && actual_target == requested_target {
                    Ok(Some(SyncEventRecord {
                        author: event_author,
                        sequence: event_sequence,
                        event_id,
                        bytes: event_bytes.clone(),
                    }))
                } else {
                    Ok(None)
                }
            }
        };
        let client_cancellation = CancellationToken::new();
        let server_cancellation = CancellationToken::new();
        let (client_result, server_result) = tokio::join!(
            execute_authenticated_sync_v2_once(
                &client_adapter,
                &alice,
                alice_pins_bob,
                &local_summary,
                &mut deduplicator,
                &mut validator,
                |pinned, requested_scope| {
                    pinned.fingerprint() == bob_fingerprint && requested_scope == scope
                },
                &client_cancellation,
            ),
            serve_authenticated_sync_v2_once(
                &server_adapter,
                &bob,
                bob_pins_alice,
                &mut summary_source,
                &mut event_source,
                |pinned, requested_scope| {
                    pinned.fingerprint() == alice_fingerprint && requested_scope == scope
                },
                &server_cancellation,
            ),
        );
        let client = client_result.expect("complete authenticated v2 sync exchange");
        let server = server_result.expect("serve authenticated v2 sync exchange");
        (
            client,
            server,
            last_target.get(),
            summary_calls.get(),
            event_calls.get(),
        )
    }

    #[tokio::test]
    async fn authenticated_v2_sync_exchanges_summaries_and_repairs_missing_sequence() {
        let scope = ScopeId::new([0xb1; 32]);
        let author = lattice_sync::AuthorId::new([0xb2; 32]);
        let event_id = lattice_sync::EventId::new([0xb3; 32]);
        let event_bytes = b"validated v2 author sequence event".to_vec();
        let local_summary = ScopeSummary {
            scope,
            authors: vec![AuthorSummary::new(author, 0)],
            missing_dependencies: Vec::new(),
        };
        let remote_summary = ScopeSummary {
            scope,
            authors: vec![AuthorSummary {
                author,
                contiguous_sequence: 1,
                known_events: vec![KnownEvent {
                    sequence: 1,
                    event_id,
                }],
                unavailable: Vec::new(),
            }],
            missing_dependencies: Vec::new(),
        };
        let target = SyncRequestTarget::Sequence {
            author,
            sequence: 1,
        };
        let (client, server, last_target, summary_calls, event_calls) = authenticated_v2_pair(
            local_summary.clone(),
            remote_summary.clone(),
            target,
            SyncEventRecord {
                author,
                sequence: 1,
                event_id,
                bytes: event_bytes.clone(),
            },
        )
        .await;

        assert_eq!(client.peer_summary, remote_summary);
        assert_eq!(server.peer_summary, local_summary);
        assert_eq!(client.exchange.requested, vec![target]);
        assert_eq!(client.exchange.plan.request_ranges.len(), 1);
        assert_eq!(client.exchange.plan.request_ranges[0].author, author);
        assert_eq!(client.exchange.plan.request_ranges[0].range.start(), 1);
        assert_eq!(client.exchange.plan.request_ranges[0].range.end(), 1);
        assert_eq!(client.exchange.events.len(), 1);
        assert_eq!(client.exchange.events[0].author, author);
        assert_eq!(client.exchange.events[0].sequence, 1);
        assert_eq!(client.exchange.events[0].event_id, event_id);
        assert_eq!(client.exchange.events[0].bytes, event_bytes);
        assert_eq!(last_target, Some(target));
        assert_eq!(summary_calls, 1);
        assert_eq!(event_calls, 1);
        assert_eq!(server.exchange.included_events, 1);
        assert!(matches!(client.summary_hop, HopOutcome::Accepted(_)));
        assert!(matches!(server.summary_hop, HopOutcome::Accepted(_)));
        assert!(matches!(
            client.exchange.request_hop,
            HopOutcome::Accepted(_)
        ));
        assert!(matches!(
            server.exchange.response_hop,
            HopOutcome::Accepted(_)
        ));
    }

    #[tokio::test]
    async fn authenticated_v2_sync_requests_and_validates_missing_dependency() {
        let scope = ScopeId::new([0xc1; 32]);
        let author = lattice_sync::AuthorId::new([0xc2; 32]);
        let event_id = lattice_sync::EventId::new([0xc3; 32]);
        let event_bytes = b"validated v2 dependency event".to_vec();
        let local_summary = ScopeSummary {
            scope,
            authors: Vec::new(),
            missing_dependencies: vec![event_id],
        };
        let remote_summary = ScopeSummary {
            scope,
            authors: vec![AuthorSummary {
                author,
                contiguous_sequence: 1,
                known_events: vec![KnownEvent {
                    sequence: 1,
                    event_id,
                }],
                unavailable: Vec::new(),
            }],
            missing_dependencies: Vec::new(),
        };
        let target = SyncRequestTarget::EventId(event_id);
        let (client, server, last_target, summary_calls, event_calls) = authenticated_v2_pair(
            local_summary.clone(),
            remote_summary.clone(),
            target,
            SyncEventRecord {
                author,
                sequence: 1,
                event_id,
                bytes: event_bytes.clone(),
            },
        )
        .await;

        assert_eq!(client.peer_summary, remote_summary);
        assert_eq!(server.peer_summary, local_summary);
        assert_eq!(client.exchange.plan.dependency_requests, vec![event_id]);
        assert_eq!(client.exchange.requested, vec![target]);
        assert_eq!(client.exchange.events.len(), 1);
        assert_eq!(client.exchange.events[0].event_id, event_id);
        assert_eq!(client.exchange.events[0].bytes, event_bytes);
        assert_eq!(last_target, Some(target));
        assert_eq!(summary_calls, 1);
        assert_eq!(event_calls, 1);
        assert_eq!(server.exchange.included_events, 1);
        assert!(matches!(client.summary_hop, HopOutcome::Accepted(_)));
        assert!(matches!(server.summary_hop, HopOutcome::Accepted(_)));
    }

    #[tokio::test]
    async fn wrong_v2_scope_does_not_disclose_responder_summary_or_access_events() {
        let scope = ScopeId::new([0xd1; 32]);
        let allowed_scope = ScopeId::new([0xd5; 32]);
        let local_summary = ScopeSummary::new(scope);
        let alice = DeviceIdentity::generate().expect("generate v2 initiator identity");
        let bob = DeviceIdentity::generate().expect("generate v2 responder identity");
        let alice_fingerprint = alice.fingerprint();
        let bob_fingerprint = bob.fingerprint();
        let alice_pins_bob =
            PinnedIdentity::from_verified_fingerprint(bob.public_bundle(), bob_fingerprint)
                .expect("pin v2 responder");
        let bob_pins_alice =
            PinnedIdentity::from_verified_fingerprint(alice.public_bundle(), alice_fingerprint)
                .expect("pin v2 initiator");
        let listener = TcpPeerListener::bind("127.0.0.1:0", 4096)
            .await
            .expect("bind v2 local test listener");
        let endpoint = listener.local_addr().expect("read v2 listener address");
        let (client_result, server_result) =
            tokio::join!(TcpPeerAdapter::connect(endpoint, 4096), listener.accept());
        let client_adapter = client_result.expect("connect v2 test adapter");
        let (server_adapter, _) = server_result.expect("accept v2 test adapter");
        let summary_calls = Cell::new(0);
        let event_calls = Cell::new(0);
        let mut summary_source = |_: ScopeId| {
            summary_calls.set(summary_calls.get() + 1);
            Ok(ScopeSummary::new(scope))
        };
        let mut event_source = |_: ScopeId, _: SyncRequestTarget| {
            event_calls.set(event_calls.get() + 1);
            Ok(None::<SyncEventRecord>)
        };
        let mut deduplicator = EventDeduplicator::new(64).expect("bounded deduplicator");
        let mut validator =
            |_: ScopeId,
             _: lattice_sync::AuthorId,
             _: u64,
             _: Option<lattice_sync::EventId>,
             _: &[u8]| Ok::<_, ()>(lattice_sync::EventId::new([0xd2; 32]));
        let client_cancellation = CancellationToken::new();
        let server_cancellation = CancellationToken::new();
        let client_future = execute_authenticated_sync_v2_once(
            &client_adapter,
            &alice,
            alice_pins_bob,
            &local_summary,
            &mut deduplicator,
            &mut validator,
            |_, requested_scope| requested_scope == scope,
            &client_cancellation,
        );
        let server_future = serve_authenticated_sync_v2_once(
            &server_adapter,
            &bob,
            bob_pins_alice,
            &mut summary_source,
            &mut event_source,
            |pinned, requested_scope| {
                pinned.fingerprint() == alice_fingerprint && requested_scope == allowed_scope
            },
            &server_cancellation,
        );
        tokio::pin!(client_future);
        tokio::pin!(server_future);
        tokio::select! {
            result = &mut server_future => {
                assert!(matches!(result, Err(AuthenticatedSyncError::ScopeUnauthorized)));
                assert_eq!(summary_calls.get(), 0);
                assert_eq!(event_calls.get(), 0);
                client_cancellation.cancel();
                assert!(matches!(client_future.await, Err(AuthenticatedSyncError::Cancelled)));
            }
            _ = &mut client_future => panic!("denied v2 scope must not receive a summary"),
        }
    }

    #[tokio::test]
    async fn denied_v2_local_scope_sends_no_summary_to_peer() {
        let scope = ScopeId::new([0xd3; 32]);
        let local_summary = ScopeSummary::new(scope);
        let alice = DeviceIdentity::generate().expect("generate v2 initiator identity");
        let bob = DeviceIdentity::generate().expect("generate v2 responder identity");
        let alice_pins_bob =
            PinnedIdentity::from_verified_fingerprint(bob.public_bundle(), bob.fingerprint())
                .expect("pin v2 responder");
        let bob_pins_alice =
            PinnedIdentity::from_verified_fingerprint(alice.public_bundle(), alice.fingerprint())
                .expect("pin v2 initiator");
        let listener = TcpPeerListener::bind("127.0.0.1:0", 4096)
            .await
            .expect("bind v2 local test listener");
        let endpoint = listener.local_addr().expect("read v2 listener address");
        let (client_result, server_result) =
            tokio::join!(TcpPeerAdapter::connect(endpoint, 4096), listener.accept());
        let client_adapter = client_result.expect("connect v2 test adapter");
        let (server_adapter, _) = server_result.expect("accept v2 test adapter");
        let summary_calls = Cell::new(0);
        let event_calls = Cell::new(0);
        let mut summary_source = |_: ScopeId| {
            summary_calls.set(summary_calls.get() + 1);
            Ok::<_, SyncSourceError>(ScopeSummary::new(scope))
        };
        let mut event_source = |_: ScopeId, _: SyncRequestTarget| {
            event_calls.set(event_calls.get() + 1);
            Ok(None::<SyncEventRecord>)
        };
        let mut deduplicator = EventDeduplicator::new(64).expect("bounded deduplicator");
        let mut validator =
            |_: ScopeId,
             _: lattice_sync::AuthorId,
             _: u64,
             _: Option<lattice_sync::EventId>,
             _: &[u8]| Ok::<_, ()>(lattice_sync::EventId::new([0xd4; 32]));
        let client_cancellation = CancellationToken::new();
        let server_cancellation = CancellationToken::new();
        let client_future = execute_authenticated_sync_v2_once(
            &client_adapter,
            &alice,
            alice_pins_bob,
            &local_summary,
            &mut deduplicator,
            &mut validator,
            |_, _| false,
            &client_cancellation,
        );
        let server_future = serve_authenticated_sync_v2_once(
            &server_adapter,
            &bob,
            bob_pins_alice,
            &mut summary_source,
            &mut event_source,
            |_, requested_scope| requested_scope == scope,
            &server_cancellation,
        );
        tokio::pin!(client_future);
        tokio::pin!(server_future);
        tokio::select! {
            result = &mut client_future => {
                assert!(matches!(result, Err(AuthenticatedSyncError::ScopeUnauthorized)));
                assert_eq!(summary_calls.get(), 0);
                assert_eq!(event_calls.get(), 0);
                server_cancellation.cancel();
                assert!(matches!(server_future.await, Err(AuthenticatedSyncError::Cancelled)));
            }
            _ = &mut server_future => panic!("server cannot receive a denied scope summary"),
        }
    }

    #[test]
    fn v2_summary_codec_bounds_oversize_and_malformed_frames_without_changing_v1() {
        let scope = ScopeId::new([0xe1; 32]);
        let empty = ScopeSummary::new(scope);
        assert_eq!(
            super::encode_v2_summary(&empty, super::V2_INITIATOR_SUMMARY_KIND, 41),
            Err(super::SyncProtocolError::InvalidLength)
        );

        let summary_author = lattice_sync::AuthorId::new([0xe3; 32]);
        let summary_event = lattice_sync::EventId::new([0xe4; 32]);
        let rich_summary = ScopeSummary {
            scope,
            authors: vec![AuthorSummary {
                author: summary_author,
                contiguous_sequence: 3,
                known_events: vec![KnownEvent {
                    sequence: 4,
                    event_id: summary_event,
                }],
                unavailable: vec![
                    lattice_sync::UnavailableRange {
                        range: lattice_sync::SequenceRange::new(1, 2).expect("valid retained gap"),
                        reason: lattice_sync::GapReason::Retention,
                    },
                    lattice_sync::UnavailableRange {
                        range: lattice_sync::SequenceRange::new(3, 3).expect("valid unknown gap"),
                        reason: lattice_sync::GapReason::Unknown,
                    },
                ],
            }],
            missing_dependencies: vec![lattice_sync::EventId::new([0xe5; 32])],
        };
        let encoded =
            super::encode_v2_summary(&rich_summary, super::V2_INITIATOR_SUMMARY_KIND, 4096)
                .expect("encode bounded rich summary");
        assert_eq!(
            super::decode_v2_summary(&encoded, scope, super::V2_INITIATOR_SUMMARY_KIND,)
                .expect("decode bounded rich summary"),
            rich_summary
        );

        let mut too_many_authors = super::v2_header(
            scope,
            super::V2_INITIATOR_SUMMARY_KIND,
            super::MAX_AUTHORS + 1,
        )
        .expect("encode bounded count field");
        too_many_authors.extend_from_slice(&0_u16.to_be_bytes());
        assert_eq!(
            super::decode_v2_summary(&too_many_authors, scope, super::V2_INITIATOR_SUMMARY_KIND,),
            Err(super::SyncProtocolError::InvalidCount)
        );

        let mut invalid_gap = super::v2_header(scope, super::V2_INITIATOR_SUMMARY_KIND, 1)
            .expect("encode one-author count");
        invalid_gap.extend_from_slice(&0_u16.to_be_bytes());
        invalid_gap.extend_from_slice(lattice_sync::AuthorId::new([0xe2; 32]).as_bytes());
        invalid_gap.extend_from_slice(&0_u64.to_be_bytes());
        invalid_gap.extend_from_slice(&0_u16.to_be_bytes());
        invalid_gap.extend_from_slice(&1_u16.to_be_bytes());
        invalid_gap.extend_from_slice(&1_u64.to_be_bytes());
        invalid_gap.extend_from_slice(&1_u64.to_be_bytes());
        invalid_gap.push(2);
        assert_eq!(
            super::decode_v2_summary(&invalid_gap, scope, super::V2_INITIATOR_SUMMARY_KIND,),
            Err(super::SyncProtocolError::InvalidEvent)
        );

        let v1_empty_request = super::encode_request(scope, &[]);
        assert_eq!(v1_empty_request[4], super::WIRE_VERSION);
        assert_eq!(v1_empty_request[5], super::REQUEST_KIND);
    }
}
