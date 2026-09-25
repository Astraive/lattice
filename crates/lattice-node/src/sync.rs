//! One-shot scoped anti-entropy exchanges over an already-running transport.
//!
//! This module joins `lattice-sync` planning to the opaque `TransportAdapter`
//! port. It sends one bounded request and consumes at most one bounded reply;
//! it does not authenticate peers, authorize scopes, persist history, or treat a
//! transport receipt as remote delivery. Callers must serialize exchanges on a
//! shared adapter and validate returned event bytes at their existing trust
//! boundary before accepting them.

use std::collections::BTreeSet;

use lattice_platform::{
    EnvelopeBytes, MAX_ENVELOPE_BYTES, MAX_EVENT_BYTES, TransportAdapter, TransportError,
    TransportReceipt,
};
use lattice_router::{DeduplicationOutcome, EventDeduplicator, EventId as RouterEventId};
use lattice_sync::{
    AuthorId, EventId, MAX_BATCH_EVENTS, PlanError, ScopeId, ScopeSummary, SyncPlan,
    SyncRequestRange, UnresolvedHistory, plan_sync,
};
use lattice_transport::{receive_bounded, send_bounded};
use tokio_util::sync::CancellationToken;

const WIRE_MAGIC: &[u8; 4] = b"LSYN";
const WIRE_VERSION: u8 = 1;
const REQUEST_KIND: u8 = 1;
const RESPONSE_KIND: u8 = 2;
const WIRE_HEADER_BYTES: usize = 40;
const TARGET_BY_ID: u8 = 0;
const TARGET_BY_SEQUENCE: u8 = 1;

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
    /// Returns the exact requested event, or `None` if it is unavailable.
    fn load(&mut self, scope: ScopeId, target: SyncRequestTarget) -> Option<SyncEventRecord>;
}

impl<F> SyncEventSource for F
where
    F: FnMut(ScopeId, SyncRequestTarget) -> Option<SyncEventRecord>,
{
    fn load(&mut self, scope: ScopeId, target: SyncRequestTarget) -> Option<SyncEventRecord> {
        self(scope, target)
    }
}

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

/// Receive-side status for one call to [`serve_sync_request_once`].
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

/// Plans and executes one bounded anti-entropy request over an existing
/// transport. The `peer` summary is used only for planning; the peer must run
/// [`serve_sync_request_once`] on its matching adapter to answer.
///
/// The caller controls scope authorization, peer authentication, validator
/// policy, cancellation, and serialization of concurrent exchanges. The
/// adapter stays caller-owned and is not stopped on return. Each operation sends
/// at most one request and receives at most one response; no retries or history
/// subscriptions are started.
///
/// # Errors
///
/// Returns `PlanError` if the summaries are malformed, exceed planner limits,
/// or conflict about an event identity at a shared author sequence.
#[allow(clippy::too_many_lines)] // Keeps one exchange's outcome transitions auditable.
pub async fn execute_sync_once<A, V>(
    adapter: &A,
    local: &ScopeSummary,
    peer: &ScopeSummary,
    deduplicator: &mut EventDeduplicator,
    validator: &mut V,
    cancellation: &CancellationToken,
) -> Result<SyncExchange<V::Error>, PlanError>
where
    A: TransportAdapter + ?Sized,
    V: SyncEventValidator,
{
    let plan = plan_sync(local, peer)?;
    let request_frame_limit = adapter
        .capabilities()
        .max_envelope_bytes()
        .min(MAX_ENVELOPE_BYTES);
    let (requested, mut unresolved_dependencies, mut unresolved_ranges) =
        bounded_targets(&plan, request_frame_limit);
    let mut exchange = SyncExchange {
        unresolved_history: plan.unresolved_history.clone(),
        plan,
        request_hop: HopOutcome::NotAttempted,
        response: SyncReceiveOutcome::NotAttempted,
        requested: requested.clone(),
        events: Vec::with_capacity(requested.len()),
        duplicates: Vec::new(),
        rejected_events: Vec::new(),
        unresolved_dependencies: Vec::new(),
        unresolved_ranges: Vec::new(),
    };

    if requested.is_empty() {
        exchange.unresolved_dependencies = unresolved_dependencies;
        exchange.unresolved_ranges = normalize_ranges(unresolved_ranges);
        return Ok(exchange);
    }

    let request = encode_request(local.scope, &requested);
    if cancellation.is_cancelled() {
        exchange.request_hop = HopOutcome::Cancelled;
        exchange.unresolved_dependencies = unresolved_dependencies;
        exchange.unresolved_ranges = normalize_ranges(unresolved_ranges);
        return Ok(exchange);
    }

    let Ok(request_bytes) = EnvelopeBytes::try_from(request) else {
        exchange.request_hop = HopOutcome::Failed(TransportError::EnvelopeTooLarge);
        exchange.unresolved_dependencies = unresolved_dependencies;
        exchange.unresolved_ranges = normalize_ranges(unresolved_ranges);
        return Ok(exchange);
    };
    let send_result = tokio::select! {
        biased;
        () = cancellation.cancelled() => None,
        result = send_bounded(adapter, request_bytes) => Some(result),
    };
    let Some(send_result) = send_result else {
        exchange.request_hop = HopOutcome::Cancelled;
        exchange.unresolved_dependencies = unresolved_dependencies;
        exchange.unresolved_ranges = normalize_ranges(unresolved_ranges);
        return Ok(exchange);
    };
    match send_result {
        Ok(receipt) => exchange.request_hop = HopOutcome::Accepted(receipt),
        Err(error) => {
            exchange.request_hop = HopOutcome::Failed(error);
            exchange.unresolved_dependencies = unresolved_dependencies;
            exchange.unresolved_ranges = normalize_ranges(unresolved_ranges);
            return Ok(exchange);
        }
    }

    let incoming = tokio::select! {
        biased;
        () = cancellation.cancelled() => None,
        result = receive_bounded(adapter) => Some(result),
    };
    let Some(incoming) = incoming else {
        exchange.response = SyncReceiveOutcome::Cancelled;
        exchange.unresolved_dependencies = unresolved_dependencies;
        exchange.unresolved_ranges = normalize_ranges(unresolved_ranges);
        return Ok(exchange);
    };
    let frame = match incoming {
        Ok(Some(frame)) => frame,
        Ok(None) => {
            exchange.response = SyncReceiveOutcome::Closed;
            exchange.unresolved_dependencies = unresolved_dependencies;
            exchange.unresolved_ranges = normalize_ranges(unresolved_ranges);
            return Ok(exchange);
        }
        Err(error) => {
            exchange.response = SyncReceiveOutcome::Failed(error);
            exchange.unresolved_dependencies = unresolved_dependencies;
            exchange.unresolved_ranges = normalize_ranges(unresolved_ranges);
            return Ok(exchange);
        }
    };

    let expected = requested.iter().copied().collect::<BTreeSet<_>>();
    let records = match decode_response(frame.as_bytes(), local.scope, &expected) {
        Ok(records) => records,
        Err(error) => {
            exchange.response = SyncReceiveOutcome::Rejected(error);
            exchange.unresolved_dependencies = unresolved_dependencies;
            exchange.unresolved_ranges = normalize_ranges(unresolved_ranges);
            return Ok(exchange);
        }
    };
    exchange.response = SyncReceiveOutcome::Received;
    let mut pending = expected;
    for record in records {
        let expected_id = match record.target {
            SyncRequestTarget::EventId(event_id) => Some(event_id),
            SyncRequestTarget::Sequence { author, sequence } => {
                known_summary_event(peer, author, sequence)
            }
        };
        let validation = validator.validate(
            local.scope,
            record.author,
            record.sequence,
            expected_id,
            record.bytes,
        );
        let validated_id = match validation {
            Ok(event_id) => event_id,
            Err(error) => {
                exchange
                    .rejected_events
                    .push((record.target, SyncEventRejection::Validation(error)));
                continue;
            }
        };
        if validated_id != record.event_id {
            exchange
                .rejected_events
                .push((record.target, SyncEventRejection::AdvertisedIdMismatch));
            continue;
        }
        if expected_id.is_some_and(|expected| expected != validated_id) {
            exchange
                .rejected_events
                .push((record.target, SyncEventRejection::SummaryIdMismatch));
            continue;
        }

        match deduplicator.observe(RouterEventId(*validated_id.as_bytes())) {
            DeduplicationOutcome::Duplicate => {
                exchange.duplicates.push(validated_id);
                pending.remove(&record.target);
            }
            DeduplicationOutcome::FirstSeen { .. } => {
                exchange.events.push(ValidatedSyncEvent {
                    author: record.author,
                    sequence: record.sequence,
                    event_id: validated_id,
                    bytes: record.bytes.to_vec(),
                });
                pending.remove(&record.target);
            }
        }
    }
    for target in pending {
        add_unresolved_target(target, &mut unresolved_dependencies, &mut unresolved_ranges);
    }
    exchange.unresolved_dependencies = sort_dedup(unresolved_dependencies);
    exchange.unresolved_ranges = normalize_ranges(unresolved_ranges);
    Ok(exchange)
}

/// Receives one scoped sync request, resolves at most 128 exact records, and
/// sends at most one response frame. `authorized_scope` is a caller-selected
/// scope boundary, not an authentication mechanism. The caller owns adapter
/// lifecycle and must serialize this call with other reads on that adapter.
///
/// # Errors
///
/// Returns `SyncProtocolError` when the single incoming frame is malformed,
/// requests an invalid count, or uses an unexpected scope or target encoding.
#[allow(clippy::too_many_lines)] // Keeps bounded resolution and receipt reporting together.
pub async fn serve_sync_request_once<A, S>(
    adapter: &A,
    authorized_scope: ScopeId,
    source: &mut S,
    cancellation: &CancellationToken,
) -> Result<SyncServeResult, SyncProtocolError>
where
    A: TransportAdapter + ?Sized,
    S: SyncEventSource + ?Sized,
{
    let incoming = tokio::select! {
        biased;
        () = cancellation.cancelled() => {
            return Ok(SyncServeResult {
                receive: SyncServeReceiveOutcome::Cancelled,
                response_hop: HopOutcome::NotAttempted,
                included_events: 0,
                omitted_targets: Vec::new(),
            });
        }
        result = receive_bounded(adapter) => result,
    };
    let frame = match incoming {
        Ok(Some(frame)) => frame,
        Ok(None) => {
            return Ok(SyncServeResult {
                receive: SyncServeReceiveOutcome::Closed,
                response_hop: HopOutcome::NotAttempted,
                included_events: 0,
                omitted_targets: Vec::new(),
            });
        }
        Err(error) => {
            return Ok(SyncServeResult {
                receive: SyncServeReceiveOutcome::Failed(error),
                response_hop: HopOutcome::NotAttempted,
                included_events: 0,
                omitted_targets: Vec::new(),
            });
        }
    };
    let targets = decode_request(frame.as_bytes(), authorized_scope)?;
    if targets.is_empty() {
        return Err(SyncProtocolError::InvalidCount);
    }

    let max_bytes = adapter
        .capabilities()
        .max_envelope_bytes()
        .min(MAX_ENVELOPE_BYTES);
    let mut response = response_header(authorized_scope);
    let mut omitted_targets = Vec::with_capacity(targets.len());
    let mut included_events = 0_usize;
    for target in targets {
        let Some(record) = source.load(authorized_scope, target) else {
            omitted_targets.push(target);
            continue;
        };
        if record.sequence == 0
            || record.bytes.is_empty()
            || record.bytes.len() > MAX_EVENT_BYTES
            || !record_matches_target(target, &record)
        {
            omitted_targets.push(target);
            continue;
        }
        let Some(record_size) = target_wire_size(target)
            .checked_add(32 + 8 + 32 + 4)
            .and_then(|size| size.checked_add(record.bytes.len()))
        else {
            omitted_targets.push(target);
            continue;
        };
        if response
            .len()
            .checked_add(record_size)
            .is_none_or(|size| size > max_bytes)
        {
            omitted_targets.push(target);
            continue;
        }
        encode_target(&mut response, target);
        response.extend_from_slice(record.author.as_bytes());
        response.extend_from_slice(&record.sequence.to_be_bytes());
        response.extend_from_slice(record.event_id.as_bytes());
        let Ok(event_len) = u32::try_from(record.bytes.len()) else {
            omitted_targets.push(target);
            continue;
        };
        response.extend_from_slice(&event_len.to_be_bytes());
        response.extend_from_slice(&record.bytes);
        included_events += 1;
    }
    let count = u16::try_from(included_events).map_err(|_| SyncProtocolError::InvalidCount)?;
    response[38..40].copy_from_slice(&count.to_be_bytes());

    let response_hop = if cancellation.is_cancelled() {
        HopOutcome::Cancelled
    } else {
        match EnvelopeBytes::try_from(response) {
            Ok(response_bytes) => {
                let send = tokio::select! {
                    biased;
                    () = cancellation.cancelled() => None,
                    result = send_bounded(adapter, response_bytes) => Some(result),
                };
                match send {
                    None => HopOutcome::Cancelled,
                    Some(Ok(receipt)) => HopOutcome::Accepted(receipt),
                    Some(Err(error)) => HopOutcome::Failed(error),
                }
            }
            Err(_) => HopOutcome::Failed(TransportError::EnvelopeTooLarge),
        }
    };
    Ok(SyncServeResult {
        receive: SyncServeReceiveOutcome::Received,
        response_hop,
        included_events,
        omitted_targets,
    })
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
        if self.take(4)? != &WIRE_MAGIC[..] {
            return Err(SyncProtocolError::InvalidMagic);
        }
        if self.u8()? != WIRE_VERSION {
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
    use lattice_router::EventDeduplicator;
    use lattice_sync::{AuthorSummary, KnownEvent, ScopeId, ScopeSummary};
    use lattice_transport::{TcpPeerAdapter, TcpPeerListener};
    use tokio_util::sync::CancellationToken;

    use super::{
        HopOutcome, SyncEventRecord, SyncReceiveOutcome, SyncRequestTarget,
        SyncServeReceiveOutcome, execute_sync_once, serve_sync_request_once,
    };

    #[tokio::test]
    async fn exchanges_one_missing_sequence_over_bounded_tcp_adapters() {
        let scope = ScopeId::new([0x11; 32]);
        let author = lattice_sync::AuthorId::new([0x22; 32]);
        let event_id = lattice_sync::EventId::new([0x33; 32]);
        let event_bytes = b"opaque event bytes validated by the caller".to_vec();
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
            if requested_scope == scope && target == requested_target {
                Some(SyncEventRecord {
                    author,
                    sequence: 1,
                    event_id,
                    bytes: event_bytes.clone(),
                })
            } else {
                None
            }
        };
        let client_cancellation = CancellationToken::new();
        let server_cancellation = CancellationToken::new();
        let (client, server) = tokio::join!(
            execute_sync_once(
                &client_adapter,
                &local,
                &peer,
                &mut deduplicator,
                &mut validator,
                &client_cancellation,
            ),
            serve_sync_request_once(&server_adapter, scope, &mut source, &server_cancellation,),
        );
        let client = client.expect("plan and execute one sync exchange");
        let server = server.expect("receive request and send one response");

        assert_eq!(client.requested.len(), 1);
        assert_eq!(
            client.requested[0],
            SyncRequestTarget::Sequence {
                author,
                sequence: 1
            }
        );
        assert_eq!(client.response, SyncReceiveOutcome::Received);
        assert_eq!(client.events.len(), 1);
        assert_eq!(client.events[0].event_id, event_id);
        assert_eq!(
            client.events[0].bytes,
            b"opaque event bytes validated by the caller"
        );
        assert!(client.unresolved_ranges.is_empty());
        assert_eq!(server.receive, SyncServeReceiveOutcome::Received);
        assert_eq!(server.included_events, 1);
        assert!(matches!(client.request_hop, HopOutcome::Accepted(_)));
        assert!(matches!(server.response_hop, HopOutcome::Accepted(_)));
    }
}
