//! Lattice anti-entropy and repair planning.
//!
//! This crate compares bounded summaries for one scope at a time. A plan is
//! advisory metadata: it does not validate, accept, or authorize events.

use std::collections::{BTreeMap, BTreeSet};

pub const CRATE_NAME: &str = "lattice-sync";

/// Maximum number of author records in either input summary or its author union.
pub const MAX_AUTHORS: usize = 256;
/// Maximum number of sparse event positions in one summary.
pub const MAX_KNOWN_EVENTS: usize = 4_096;
/// Maximum number of explicit historical gaps in one summary.
pub const MAX_EXPLICIT_GAPS: usize = 2_048;
/// Maximum number of unresolved history ranges returned in a plan.
pub const MAX_HISTORY_RANGES: usize = 256;
/// Maximum number of sequence ranges returned in a plan.
pub const MAX_REQUEST_RANGES: usize = 256;
/// Maximum number of missing dependencies returned in a plan.
pub const MAX_DEPENDENCY_REQUESTS: usize = 256;
/// Maximum number of events a peer may return for one request batch.
pub const MAX_BATCH_EVENTS: u16 = 128;

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Creates an opaque identifier. This crate does not derive or verify IDs.
            #[must_use]
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Returns the identifier bytes without interpreting them.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

id_type!(ScopeId);
id_type!(AuthorId);
id_type!(EventId);

/// An inclusive, one-based interval of author sequence numbers.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SequenceRange {
    start: u64,
    end: u64,
}

impl SequenceRange {
    /// Creates a non-empty inclusive sequence range.
    ///
    /// Event sequences are one-based; zero is not a valid sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`RangeError::ZeroStart`] when `start` is zero, or
    /// [`RangeError::EndBeforeStart`] when `end` is less than `start`.
    pub fn new(start: u64, end: u64) -> Result<Self, RangeError> {
        if start == 0 {
            return Err(RangeError::ZeroStart);
        }
        if end < start {
            return Err(RangeError::EndBeforeStart);
        }
        Ok(Self { start, end })
    }

    #[must_use]
    pub const fn start(self) -> u64 {
        self.start
    }

    #[must_use]
    pub const fn end(self) -> u64 {
        self.end
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RangeError {
    ZeroStart,
    EndBeforeStart,
}

/// Why the event payloads for a sequence interval are unavailable locally.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GapReason {
    /// The summary cannot establish whether these sequence positions existed.
    Unknown,
    /// The events existed but are no longer retained by that replica.
    Retention,
}

/// A reported interval that a replica cannot currently provide.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnavailableRange {
    pub range: SequenceRange,
    pub reason: GapReason,
}

/// A sparse event identity associated with an author's sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KnownEvent {
    pub sequence: u64,
    pub event_id: EventId,
}

/// Summary for one event author within a single scope.
///
/// `contiguous_sequence` is the greatest contiguous sequence observed. Explicit
/// unavailable ranges override that prefix where the payload is no longer
/// available. Sparse positions can extend beyond the contiguous prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorSummary {
    pub author: AuthorId,
    pub contiguous_sequence: u64,
    pub known_events: Vec<KnownEvent>,
    pub unavailable: Vec<UnavailableRange>,
}

impl AuthorSummary {
    #[must_use]
    pub fn new(author: AuthorId, contiguous_sequence: u64) -> Self {
        Self {
            author,
            contiguous_sequence,
            known_events: Vec::new(),
            unavailable: Vec::new(),
        }
    }
}

/// Summary for exactly one common scope; no global Space enumeration is used.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeSummary {
    pub scope: ScopeId,
    pub authors: Vec<AuthorSummary>,
    /// Dependencies this replica still needs in order to process its events.
    pub missing_dependencies: Vec<EventId>,
}

impl ScopeSummary {
    #[must_use]
    pub fn new(scope: ScopeId) -> Self {
        Self {
            scope,
            authors: Vec::new(),
            missing_dependencies: Vec::new(),
        }
    }
}

/// A request for an inclusive range of one author's sequence stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncRequestRange {
    pub author: AuthorId,
    pub range: SequenceRange,
}

/// Reason a summary comparison could not establish complete history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnresolvedHistory {
    pub author: AuthorId,
    pub range: SequenceRange,
    pub reason: GapReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncStatus {
    /// There are no known missing events, dependencies, or unresolved gaps.
    UpToDate,
    /// One or more exact event or dependency requests can be made.
    RequestsPending,
    /// Known historical gaps prevent a complete comparison.
    HistoryIncomplete,
    /// Requests can be made, but known historical gaps also remain.
    RequestsPendingWithHistoryGaps,
}

/// Deterministic, bounded requests derived from two summaries of the same scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncPlan {
    /// Ranges to request from the peer, in author and sequence order.
    pub request_ranges: Vec<SyncRequestRange>,
    /// Event IDs of dependencies this replica is missing.
    pub dependency_requests: Vec<EventId>,
    /// Explicit gaps that neither replica can currently fill.
    pub unresolved_history: Vec<UnresolvedHistory>,
    /// Maximum events a requester should permit in one response batch.
    pub max_events_per_batch: u16,
    pub status: SyncStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanLimit {
    Authors,
    KnownEvents,
    ExplicitGaps,
    DependencyRequests,
    RequestRanges,
    HistoryRanges,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlanError {
    ScopeMismatch,
    LimitExceeded { resource: PlanLimit, limit: usize },
    ZeroEventSequence { author: AuthorId },
    ConflictingEventAtSequence { author: AuthorId, sequence: u64 },
}

#[derive(Default)]
struct NormalizedAuthor {
    contiguous_sequence: u64,
    known_events: BTreeMap<u64, EventId>,
    unknown_gaps: Vec<SequenceRange>,
    retention_gaps: Vec<SequenceRange>,
}

struct NormalizedSummary {
    authors: BTreeMap<AuthorId, NormalizedAuthor>,
    missing_dependencies: Vec<EventId>,
}

/// Compares two summaries and plans exact requests from `peer` to `local`.
///
/// Summaries are sorted and deduplicated during comparison. Conflicting event
/// IDs assigned to one author sequence are rejected. A retained-history gap is
/// reported rather than silently treating the replicas as up to date.
///
/// # Errors
///
/// Returns an error if the summaries refer to different scopes, contain
/// conflicting event IDs for an author sequence, contain an event with sequence
/// zero, or exceed a configured author, event, gap, request, or dependency
/// limit.
pub fn plan_sync(local: &ScopeSummary, peer: &ScopeSummary) -> Result<SyncPlan, PlanError> {
    if local.scope != peer.scope {
        return Err(PlanError::ScopeMismatch);
    }

    let local = normalize(local)?;
    let peer = normalize(peer)?;

    let mut authors = BTreeSet::new();
    for author in local.authors.keys().chain(peer.authors.keys()) {
        authors.insert(*author);
        if authors.len() > MAX_AUTHORS {
            return Err(limit_error(PlanLimit::Authors, MAX_AUTHORS));
        }
    }

    let mut request_ranges = Vec::new();
    let mut unresolved_history = Vec::new();
    for author in authors {
        let local_author = local.authors.get(&author);
        let peer_author = peer.authors.get(&author);
        let local_available = available_ranges(local_author);
        let peer_available = available_ranges(peer_author);

        let missing = subtract_ranges(&peer_available, &local_available);
        for range in missing {
            request_ranges.push(SyncRequestRange { author, range });
            if request_ranges.len() > MAX_REQUEST_RANGES {
                return Err(limit_error(PlanLimit::RequestRanges, MAX_REQUEST_RANGES));
            }
        }

        append_unresolved_gaps(
            author,
            local_author,
            peer_author,
            &local_available,
            &peer_available,
            &mut unresolved_history,
        )?;
    }

    unresolved_history
        .sort_unstable_by_key(|gap| (gap.author, gap.range.start, gap.range.end, gap.reason));
    let dependency_requests = local.missing_dependencies;
    let status = match (
        request_ranges.is_empty() && dependency_requests.is_empty(),
        unresolved_history.is_empty(),
    ) {
        (true, true) => SyncStatus::UpToDate,
        (false, true) => SyncStatus::RequestsPending,
        (true, false) => SyncStatus::HistoryIncomplete,
        (false, false) => SyncStatus::RequestsPendingWithHistoryGaps,
    };

    Ok(SyncPlan {
        request_ranges,
        dependency_requests,
        unresolved_history,
        max_events_per_batch: MAX_BATCH_EVENTS,
        status,
    })
}

fn normalize(summary: &ScopeSummary) -> Result<NormalizedSummary, PlanError> {
    if summary.authors.len() > MAX_AUTHORS {
        return Err(limit_error(PlanLimit::Authors, MAX_AUTHORS));
    }
    if summary.missing_dependencies.len() > MAX_DEPENDENCY_REQUESTS {
        return Err(limit_error(
            PlanLimit::DependencyRequests,
            MAX_DEPENDENCY_REQUESTS,
        ));
    }

    let mut known_event_count = 0;
    let mut gap_count = 0;
    let mut authors = BTreeMap::<AuthorId, NormalizedAuthor>::new();

    for author in &summary.authors {
        add_bounded(
            &mut known_event_count,
            author.known_events.len(),
            MAX_KNOWN_EVENTS,
            PlanLimit::KnownEvents,
        )?;
        add_bounded(
            &mut gap_count,
            author.unavailable.len(),
            MAX_EXPLICIT_GAPS,
            PlanLimit::ExplicitGaps,
        )?;

        let normalized = authors.entry(author.author).or_default();
        normalized.contiguous_sequence = normalized
            .contiguous_sequence
            .max(author.contiguous_sequence);

        for known in &author.known_events {
            if known.sequence == 0 {
                return Err(PlanError::ZeroEventSequence {
                    author: author.author,
                });
            }
            if let Some(existing) = normalized.known_events.get(&known.sequence) {
                if existing != &known.event_id {
                    return Err(PlanError::ConflictingEventAtSequence {
                        author: author.author,
                        sequence: known.sequence,
                    });
                }
            } else {
                normalized
                    .known_events
                    .insert(known.sequence, known.event_id);
            }
        }

        for gap in &author.unavailable {
            match gap.reason {
                GapReason::Unknown => normalized.unknown_gaps.push(gap.range),
                GapReason::Retention => normalized.retention_gaps.push(gap.range),
            }
        }
    }

    for author in authors.values_mut() {
        let retention = merge_ranges(std::mem::take(&mut author.retention_gaps));
        let unknown = merge_ranges(std::mem::take(&mut author.unknown_gaps));
        author.unknown_gaps = subtract_ranges(&unknown, &retention);
        author.retention_gaps = retention;
    }

    let mut missing_dependencies = summary.missing_dependencies.clone();
    missing_dependencies.sort_unstable();
    missing_dependencies.dedup();

    Ok(NormalizedSummary {
        authors,
        missing_dependencies,
    })
}

fn add_bounded(
    total: &mut usize,
    count: usize,
    limit: usize,
    resource: PlanLimit,
) -> Result<(), PlanError> {
    *total = total
        .checked_add(count)
        .filter(|updated| *updated <= limit)
        .ok_or_else(|| limit_error(resource, limit))?;
    Ok(())
}

fn limit_error(resource: PlanLimit, limit: usize) -> PlanError {
    PlanError::LimitExceeded { resource, limit }
}

fn available_ranges(author: Option<&NormalizedAuthor>) -> Vec<SequenceRange> {
    let Some(author) = author else {
        return Vec::new();
    };

    let mut ranges = Vec::with_capacity(author.known_events.len());
    if author.contiguous_sequence > 0 {
        ranges.push(SequenceRange {
            start: 1,
            end: author.contiguous_sequence,
        });
    }
    ranges.extend(author.known_events.keys().map(|sequence| SequenceRange {
        start: *sequence,
        end: *sequence,
    }));
    let available = merge_ranges(ranges);
    let mut unavailable = author.unknown_gaps.clone();
    unavailable.extend_from_slice(&author.retention_gaps);
    subtract_ranges(&available, &merge_ranges(unavailable))
}

fn append_unresolved_gaps(
    author: AuthorId,
    local: Option<&NormalizedAuthor>,
    peer: Option<&NormalizedAuthor>,
    local_available: &[SequenceRange],
    peer_available: &[SequenceRange],
    output: &mut Vec<UnresolvedHistory>,
) -> Result<(), PlanError> {
    let mut unknown = Vec::new();
    let mut retention = Vec::new();
    for summary in [local, peer].into_iter().flatten() {
        unknown.extend_from_slice(&summary.unknown_gaps);
        retention.extend_from_slice(&summary.retention_gaps);
    }

    let retention = merge_ranges(retention);
    let unknown = subtract_ranges(&merge_ranges(unknown), &retention);
    let mut jointly_available = local_available.to_vec();
    jointly_available.extend_from_slice(peer_available);
    let jointly_available = merge_ranges(jointly_available);

    let unresolved_retention = subtract_ranges(&retention, &jointly_available);
    let unresolved_unknown = subtract_ranges(&unknown, &jointly_available);
    for (reason, ranges) in [
        (GapReason::Unknown, unresolved_unknown),
        (GapReason::Retention, unresolved_retention),
    ] {
        for range in ranges {
            output.push(UnresolvedHistory {
                author,
                range,
                reason,
            });
            if output.len() > MAX_HISTORY_RANGES {
                return Err(limit_error(PlanLimit::HistoryRanges, MAX_HISTORY_RANGES));
            }
        }
    }
    Ok(())
}

fn merge_ranges(mut ranges: Vec<SequenceRange>) -> Vec<SequenceRange> {
    ranges.sort_unstable_by_key(|range| (range.start, range.end));
    let mut merged: Vec<SequenceRange> = Vec::with_capacity(ranges.len());
    for range in ranges {
        if let Some(previous) = merged.last_mut() {
            let adjacent = previous.end.checked_add(1) == Some(range.start);
            if range.start <= previous.end || adjacent {
                previous.end = previous.end.max(range.end);
                continue;
            }
        }
        merged.push(range);
    }
    merged
}

/// Returns the intervals in `source` that are not covered by `cuts`.
fn subtract_ranges(source: &[SequenceRange], cuts: &[SequenceRange]) -> Vec<SequenceRange> {
    let mut output = Vec::new();
    let mut first_relevant_cut = 0;

    for source_range in source {
        while first_relevant_cut < cuts.len() && cuts[first_relevant_cut].end < source_range.start {
            first_relevant_cut += 1;
        }

        let mut next_sequence = Some(source_range.start);
        let mut cut_index = first_relevant_cut;
        while cut_index < cuts.len() {
            let cut = cuts[cut_index];
            if cut.start > source_range.end {
                break;
            }

            if let Some(start) = next_sequence {
                if cut.start > start {
                    output.push(SequenceRange {
                        start,
                        end: cut.start - 1,
                    });
                }
                if cut.end >= source_range.end {
                    next_sequence = None;
                    break;
                }
                next_sequence = cut.end.checked_add(1);
            }
            cut_index += 1;
        }

        if let Some(start) = next_sequence
            && start <= source_range.end
        {
            output.push(SequenceRange {
                start,
                end: source_range.end,
            });
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> ScopeId {
        ScopeId::new([1; 32])
    }

    fn author(value: u8) -> AuthorId {
        AuthorId::new([value; 32])
    }

    fn event(value: u8) -> EventId {
        EventId::new([value; 32])
    }

    fn range(start: u64, end: u64) -> SequenceRange {
        SequenceRange::new(start, end).expect("test range is valid")
    }

    #[test]
    fn requests_exact_sequence_gaps_and_respects_batch_limit() {
        let mut local = ScopeSummary::new(scope());
        let mut local_author = AuthorSummary::new(author(7), 2);
        local_author.known_events.push(KnownEvent {
            sequence: 5,
            event_id: event(5),
        });
        local.authors.push(local_author);

        let mut peer = ScopeSummary::new(scope());
        peer.authors.push(AuthorSummary::new(author(7), 8));

        let plan = plan_sync(&local, &peer).expect("summaries are within bounds");
        assert_eq!(
            plan.request_ranges,
            vec![
                SyncRequestRange {
                    author: author(7),
                    range: range(3, 4),
                },
                SyncRequestRange {
                    author: author(7),
                    range: range(6, 8),
                },
            ]
        );
        assert_eq!(plan.max_events_per_batch, MAX_BATCH_EVENTS);
        assert_eq!(plan.status, SyncStatus::RequestsPending);
    }

    #[test]
    fn duplicate_and_reordered_summaries_produce_identical_plans() {
        let mut duplicate_local = ScopeSummary::new(scope());
        duplicate_local.missing_dependencies = vec![event(9), event(3), event(9)];
        duplicate_local.authors = vec![
            AuthorSummary {
                author: author(2),
                contiguous_sequence: 4,
                known_events: vec![
                    KnownEvent {
                        sequence: 7,
                        event_id: event(7),
                    },
                    KnownEvent {
                        sequence: 5,
                        event_id: event(5),
                    },
                ],
                unavailable: vec![
                    UnavailableRange {
                        range: range(3, 3),
                        reason: GapReason::Unknown,
                    },
                    UnavailableRange {
                        range: range(4, 4),
                        reason: GapReason::Unknown,
                    },
                ],
            },
            AuthorSummary {
                author: author(1),
                contiguous_sequence: 1,
                known_events: Vec::new(),
                unavailable: Vec::new(),
            },
            AuthorSummary {
                author: author(2),
                contiguous_sequence: 2,
                known_events: vec![KnownEvent {
                    sequence: 5,
                    event_id: event(5),
                }],
                unavailable: vec![UnavailableRange {
                    range: range(3, 4),
                    reason: GapReason::Unknown,
                }],
            },
        ];

        let mut canonical_local = ScopeSummary::new(scope());
        canonical_local.missing_dependencies = vec![event(3), event(9)];
        canonical_local.authors = vec![
            AuthorSummary {
                author: author(1),
                contiguous_sequence: 1,
                known_events: Vec::new(),
                unavailable: Vec::new(),
            },
            AuthorSummary {
                author: author(2),
                contiguous_sequence: 4,
                known_events: vec![
                    KnownEvent {
                        sequence: 5,
                        event_id: event(5),
                    },
                    KnownEvent {
                        sequence: 7,
                        event_id: event(7),
                    },
                ],
                unavailable: vec![UnavailableRange {
                    range: range(3, 4),
                    reason: GapReason::Unknown,
                }],
            },
        ];

        let mut duplicate_peer = ScopeSummary::new(scope());
        duplicate_peer.authors = vec![
            AuthorSummary::new(author(2), 9),
            AuthorSummary::new(author(1), 3),
            AuthorSummary::new(author(2), 6),
        ];
        let mut canonical_peer = ScopeSummary::new(scope());
        canonical_peer.authors = vec![
            AuthorSummary::new(author(1), 3),
            AuthorSummary::new(author(2), 9),
        ];

        assert_eq!(
            plan_sync(&duplicate_local, &duplicate_peer),
            plan_sync(&canonical_local, &canonical_peer)
        );
    }

    #[test]
    fn rejects_author_and_output_range_overflow() {
        let mut too_many_authors = ScopeSummary::new(scope());
        for _ in 0..=MAX_AUTHORS {
            too_many_authors
                .authors
                .push(AuthorSummary::new(author(1), 0));
        }
        let empty = ScopeSummary::new(scope());
        assert_eq!(
            plan_sync(&too_many_authors, &empty),
            Err(PlanError::LimitExceeded {
                resource: PlanLimit::Authors,
                limit: MAX_AUTHORS,
            })
        );

        let mut peer = ScopeSummary::new(scope());
        let mut sparse_author = AuthorSummary::new(author(8), 0);
        for index in 0..=MAX_REQUEST_RANGES {
            let sequence = (index as u64 + 1) * 2;
            sparse_author.known_events.push(KnownEvent {
                sequence,
                event_id: EventId::new(
                    [u8::try_from(index).expect("fixture index fits in u8"); 32],
                ),
            });
        }
        peer.authors.push(sparse_author);
        assert_eq!(
            plan_sync(&empty, &peer),
            Err(PlanError::LimitExceeded {
                resource: PlanLimit::RequestRanges,
                limit: MAX_REQUEST_RANGES,
            })
        );
    }

    #[test]
    fn reports_explicit_retention_gaps_instead_of_claiming_up_to_date() {
        let local = ScopeSummary::new(scope());
        let mut peer = ScopeSummary::new(scope());
        let mut peer_author = AuthorSummary::new(author(4), 10);
        peer_author.unavailable.push(UnavailableRange {
            range: range(4, 6),
            reason: GapReason::Retention,
        });
        peer_author.unavailable.push(UnavailableRange {
            range: range(12, 14),
            reason: GapReason::Unknown,
        });
        peer.authors.push(peer_author);

        let plan = plan_sync(&local, &peer).expect("summaries are within bounds");
        assert_eq!(
            plan.request_ranges,
            vec![
                SyncRequestRange {
                    author: author(4),
                    range: range(1, 3),
                },
                SyncRequestRange {
                    author: author(4),
                    range: range(7, 10),
                },
            ]
        );
        assert_eq!(
            plan.unresolved_history,
            vec![
                UnresolvedHistory {
                    author: author(4),
                    range: range(4, 6),
                    reason: GapReason::Retention,
                },
                UnresolvedHistory {
                    author: author(4),
                    range: range(12, 14),
                    reason: GapReason::Unknown,
                },
            ]
        );
        assert_eq!(plan.status, SyncStatus::RequestsPendingWithHistoryGaps);
    }

    #[test]
    fn requests_missing_dependencies_in_stable_deduplicated_order() {
        let mut local = ScopeSummary::new(scope());
        local.missing_dependencies = vec![event(8), event(2), event(8)];
        let peer = ScopeSummary::new(scope());

        let plan = plan_sync(&local, &peer).expect("summaries are within bounds");
        assert_eq!(plan.dependency_requests, vec![event(2), event(8)]);
        assert_eq!(plan.status, SyncStatus::RequestsPending);
    }

    #[test]
    fn interval_operations_do_not_overflow_at_u64_max() {
        let mut local = ScopeSummary::new(scope());
        local
            .authors
            .push(AuthorSummary::new(author(3), u64::MAX - 1));
        let mut peer = ScopeSummary::new(scope());
        peer.authors.push(AuthorSummary::new(author(3), u64::MAX));

        let plan = plan_sync(&local, &peer).expect("maximum sequence is supported");
        assert_eq!(
            plan.request_ranges,
            vec![SyncRequestRange {
                author: author(3),
                range: range(u64::MAX, u64::MAX),
            }]
        );
    }
}
