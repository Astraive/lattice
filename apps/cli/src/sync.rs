use std::{error::Error, io, net::SocketAddr, path::Path, time::Duration};

use clap::Subcommand;
use lattice_core::{Client, CoreError};
use lattice_events::VerifiedSignatureOnlyEvent;
use lattice_node::sync::{
    AuthenticatedSyncV2Exchange, AuthenticatedSyncV2ServeResult, StoreSyncEventSource,
    StoreSyncSummarySource, SyncExchange, SyncServeResult, SyncSummarySource,
    execute_authenticated_sync_v2_once, serve_authenticated_sync_v2_once,
    space_generation_scope_id,
};
use lattice_platform::{MAX_EVENT_BYTES, OsKeyringProtector};
use lattice_router::EventDeduplicator;
use lattice_storage::{MAX_EVENT_PAGE_SIZE, MAX_OUTBOX_PAGE_SIZE, OutboxState, Store};
use lattice_sync::{
    AuthorId, EventId, GapReason, ScopeId, SequenceRange, SyncStatus, UnresolvedHistory, plan_sync,
};
use lattice_transport::{TcpPeerAdapter, TcpPeerListener};
use tokio_util::sync::CancellationToken;

const MAX_RECONCILIATION_ROUNDS: usize = 8;
const MAX_RECONCILIATION_CONNECTION_ATTEMPTS: usize = 4;
const RECONCILIATION_STAGE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Subcommand)]
pub(super) enum SyncCommand {
    /// Inspect local event, dependency, and outbox state without networking.
    Status,
    /// Exchange scoped history with a pinned v2 peer and apply one bounded batch.
    FetchOnce {
        /// TCP endpoint to connect, for example `127.0.0.1:7000`.
        #[arg(long)]
        connect: SocketAddr,
        /// Space ID as 32 hexadecimal characters.
        #[arg(long)]
        space_id: String,
        /// MLS group reference as 64 hexadecimal characters.
        #[arg(long)]
        group_reference: String,
        /// Previously pinned peer fingerprint as 64 hexadecimal characters.
        #[arg(long)]
        peer_fingerprint: String,
        /// Optional exact event ID; absent uses scoped summary repair planning.
        #[arg(long)]
        event_id: Option<String>,
    },
    /// Accept one pinned peer and serve a v2 summary-derived request batch.
    ServeOnce {
        /// TCP endpoint to bind, for example `127.0.0.1:7000`.
        #[arg(long)]
        listen: SocketAddr,
        /// Space ID as 32 hexadecimal characters.
        #[arg(long)]
        space_id: String,
        /// MLS group reference as 64 hexadecimal characters.
        #[arg(long)]
        group_reference: String,
        /// Previously pinned peer fingerprint as 64 hexadecimal characters.
        #[arg(long)]
        peer_fingerprint: String,
    },
    /// Reconcile scoped history in bounded authenticated v2 sessions.
    ///
    /// Both peers must run this command concurrently, each with its own
    /// listener, outbound connection, and exact pin for the other peer.
    Reconcile {
        /// TCP endpoint of the peer's listener, for example `127.0.0.1:7000`.
        #[arg(long)]
        connect: SocketAddr,
        /// TCP endpoint to bind for the peer's outbound connection.
        #[arg(long)]
        listen: SocketAddr,
        /// Space ID as 32 hexadecimal characters.
        #[arg(long)]
        space_id: String,
        /// MLS group reference as 64 hexadecimal characters.
        #[arg(long)]
        group_reference: String,
        /// Exact previously pinned peer fingerprint as 64 hexadecimal characters.
        #[arg(long)]
        peer_fingerprint: String,
    },
}

pub(super) fn validate_command(command: &SyncCommand) -> Result<(), String> {
    match command {
        SyncCommand::Status => Ok(()),
        SyncCommand::FetchOnce {
            space_id,
            group_reference,
            peer_fingerprint,
            event_id,
            ..
        } => {
            super::parse_fixed_hex::<16>(space_id, "space ID")?;
            super::parse_fixed_hex::<32>(group_reference, "group reference")?;
            super::parse_fixed_hex::<32>(peer_fingerprint, "peer fingerprint")?;
            if let Some(event_id) = event_id {
                super::parse_fixed_hex::<32>(event_id, "event ID")?;
            }
            Ok(())
        }
        SyncCommand::ServeOnce {
            space_id,
            group_reference,
            peer_fingerprint,
            ..
        }
        | SyncCommand::Reconcile {
            space_id,
            group_reference,
            peer_fingerprint,
            ..
        } => {
            super::parse_fixed_hex::<16>(space_id, "space ID")?;
            super::parse_fixed_hex::<32>(group_reference, "group reference")?;
            super::parse_fixed_hex::<32>(peer_fingerprint, "peer fingerprint")?;
            Ok(())
        }
    }
}
pub(super) fn execute(
    command: &SyncCommand,
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    match command {
        SyncCommand::Status => print_status(database_path, protector, json),
        SyncCommand::FetchOnce {
            connect,
            space_id,
            group_reference,
            peer_fingerprint,
            event_id,
        } => fetch_once(
            FetchOnceRequest {
                connect: *connect,
                space_id,
                group_reference,
                peer_fingerprint,
                event_id: event_id.as_deref(),
            },
            database_path,
            protector,
            json,
        ),
        SyncCommand::ServeOnce {
            listen,
            space_id,
            group_reference,
            peer_fingerprint,
        } => serve_once(
            *listen,
            space_id,
            group_reference,
            peer_fingerprint,
            database_path,
            protector,
            json,
        ),
        SyncCommand::Reconcile {
            connect,
            listen,
            space_id,
            group_reference,
            peer_fingerprint,
        } => reconcile(
            ReconcileRequest {
                connect: *connect,
                listen: *listen,
                space_id,
                group_reference,
                peer_fingerprint,
            },
            database_path,
            protector,
            json,
        ),
    }
}

#[derive(Clone, Copy)]
struct FetchOnceRequest<'a> {
    connect: SocketAddr,
    space_id: &'a str,
    group_reference: &'a str,
    peer_fingerprint: &'a str,
    event_id: Option<&'a str>,
}
#[derive(Clone, Copy)]
struct ReconcileRequest<'a> {
    connect: SocketAddr,
    listen: SocketAddr,
    space_id: &'a str,
    group_reference: &'a str,
    peer_fingerprint: &'a str,
}

#[derive(Clone, Copy)]
struct FetchOnceTarget {
    connect: SocketAddr,
    space_id: [u8; 16],
    group_reference: [u8; 32],
    peer_fingerprint: [u8; 32],
    event_id: Option<[u8; 32]>,
    scope: ScopeId,
}

#[derive(Default)]
struct FetchEventCounts {
    accepted: usize,
    accepted_event_ids: Vec<String>,
    pending: usize,
    pending_dependency_ids: Vec<String>,
    duplicates: usize,
    retried_accepted: usize,
    retried_pending: usize,
    retried_duplicates: usize,
}

fn fetch_once(
    request: FetchOnceRequest<'_>,
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    let space_id = super::parse_fixed_hex::<16>(request.space_id, "space ID")
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let group_reference = super::parse_fixed_hex::<32>(request.group_reference, "group reference")
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let peer_fingerprint =
        super::parse_fixed_hex::<32>(request.peer_fingerprint, "peer fingerprint")
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let event_id = request
        .event_id
        .map(|event_id| super::parse_fixed_hex::<32>(event_id, "event ID"))
        .transpose()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let target = FetchOnceTarget {
        connect: request.connect,
        space_id,
        group_reference,
        peer_fingerprint,
        event_id,
        scope: space_generation_scope_id(&space_id, &group_reference),
    };
    let mut client = Client::open_existing(database_path, protector)?;
    let mut created = client.restore_space(&target.space_id, &target.group_reference)?;
    if client.pinned_identity(&target.peer_fingerprint)?.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "requested peer fingerprint is not pinned in this profile",
        )
        .into());
    }
    let store = Store::open(database_path)?;
    let mut summary_source = StoreSyncSummarySource::new(
        &store,
        target.scope,
        target.space_id,
        target.group_reference,
    );
    let authenticated = fetch_from_peer(&client, &mut summary_source, target)?;
    let counts = accept_fetched_events(&mut client, &mut created, &authenticated.exchange.events)?;
    print_fetch_result(target, &counts, &authenticated.exchange, json);
    Ok(())
}

fn fetch_from_peer(
    client: &Client,
    summary_source: &mut StoreSyncSummarySource<'_>,
    target: FetchOnceTarget,
) -> Result<AuthenticatedSyncV2Exchange<&'static str>, Box<dyn Error>> {
    let mut local_summary = summary_source
        .load_summary(target.scope)
        .map_err(|error| io::Error::other(error.to_string()))?;
    if let Some(event_id) = target.event_id {
        local_summary.missing_dependencies.clear();
        local_summary
            .missing_dependencies
            .push(EventId::new(event_id));
    }
    let mut deduplicator =
        EventDeduplicator::new(128).map_err(|error| io::Error::other(format!("{error:?}")))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let adapter = runtime
        .block_on(TcpPeerAdapter::connect(target.connect, MAX_EVENT_BYTES))
        .map_err(|error| io::Error::other(format!("{error:?}")))?;
    let cancellation = CancellationToken::new();
    let pinned = runtime.block_on(client.with_pinned_identity(
        &target.peer_fingerprint,
        |identity, pinned_peer| async move {
            execute_authenticated_sync_v2_once(
                &adapter,
                identity,
                pinned_peer,
                &local_summary,
                &mut deduplicator,
                &mut |requested_scope: ScopeId,
                      author: lattice_sync::AuthorId,
                      sequence: u64,
                      expected_id: Option<EventId>,
                      bytes: &[u8]|
                 -> Result<EventId, &'static str> {
                    validate_fetch_event(
                        target,
                        requested_scope,
                        author,
                        sequence,
                        expected_id,
                        bytes,
                    )
                },
                |peer, requested_scope| {
                    peer.fingerprint() == target.peer_fingerprint && requested_scope == target.scope
                },
                &cancellation,
            )
            .await
        },
    ))?;
    pinned
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "requested peer fingerprint is no longer pinned",
            )
        })?
        .map_err(|error| io::Error::other(error.to_string()).into())
}

fn validate_fetch_event(
    target: FetchOnceTarget,
    requested_scope: ScopeId,
    author: lattice_sync::AuthorId,
    sequence: u64,
    expected_id: Option<EventId>,
    bytes: &[u8],
) -> Result<EventId, &'static str> {
    let event = VerifiedSignatureOnlyEvent::decode_verify(bytes)
        .map_err(|_| "invalid signed event bytes")?;
    if requested_scope != target.scope
        || event.space_id() != &target.space_id
        || event.mls_group_reference() != &target.group_reference
        || event.author_fingerprint() != author.as_bytes()
        || event.author_sequence() != sequence
        || expected_id.is_some_and(|expected| event.event_id().as_bytes() != expected.as_bytes())
    {
        return Err("event identity, sequence, or generation mismatch");
    }
    Ok(EventId::new(*event.event_id().as_bytes()))
}

fn accept_fetched_events(
    client: &mut Client,
    created: &mut lattice_core::CreatedSpace,
    events: &[lattice_node::sync::ValidatedSyncEvent],
) -> Result<FetchEventCounts, CoreError> {
    let mut counts = FetchEventCounts::default();
    for event in events {
        match client.accept_synced_application_event(created, &event.bytes)? {
            lattice_core::SyncedApplicationOutcome::Accepted { event_id } => {
                counts.accepted += 1;
                counts.accepted_event_ids.push(super::hex(&event_id));
            }
            lattice_core::SyncedApplicationOutcome::Pending {
                missing_dependencies,
                ..
            } => {
                counts.pending += 1;
                counts.pending_dependency_ids.extend(
                    missing_dependencies
                        .iter()
                        .map(|dependency| super::hex(dependency)),
                );
            }
            lattice_core::SyncedApplicationOutcome::Duplicate { .. } => counts.duplicates += 1,
        }
    }
    Ok(counts)
}

fn accept_reconciliation_events(
    client: &mut Client,
    created: &mut lattice_core::CreatedSpace,
    events: &[lattice_node::sync::ValidatedSyncEvent],
) -> Result<FetchEventCounts, CoreError> {
    let mut counts = accept_fetched_events(client, created, events)?;
    for outcome in client.retry_ready_synced_application_events(created)? {
        match outcome {
            lattice_core::SyncedApplicationOutcome::Accepted { event_id } => {
                counts.accepted += 1;
                counts.retried_accepted += 1;
                counts.accepted_event_ids.push(super::hex(&event_id));
            }
            lattice_core::SyncedApplicationOutcome::Pending {
                missing_dependencies,
                ..
            } => {
                counts.pending += 1;
                counts.retried_pending += 1;
                counts.pending_dependency_ids.extend(
                    missing_dependencies
                        .iter()
                        .map(|dependency| super::hex(dependency)),
                );
            }
            lattice_core::SyncedApplicationOutcome::Duplicate { .. } => {
                counts.duplicates += 1;
                counts.retried_duplicates += 1;
            }
        }
    }
    Ok(counts)
}

fn print_fetch_result(
    target: FetchOnceTarget,
    counts: &FetchEventCounts,
    exchange: &SyncExchange<&'static str>,
    json: bool,
) {
    let rejected_events = exchange.rejected_events.len();
    let planned_ranges = exchange
        .plan
        .request_ranges
        .iter()
        .map(|requested| sequence_range_json(requested.author, requested.range))
        .collect::<Vec<_>>();
    let unresolved_ranges = exchange
        .unresolved_ranges
        .iter()
        .map(|unresolved| sequence_range_json(unresolved.author, unresolved.range))
        .collect::<Vec<_>>();
    let unresolved_history = exchange
        .unresolved_history
        .iter()
        .map(unresolved_history_json)
        .collect::<Vec<_>>();
    let unresolved_dependencies = exchange
        .unresolved_dependencies
        .iter()
        .map(|dependency| super::hex(dependency.as_bytes()))
        .collect::<Vec<_>>();
    if json {
        let state = if rejected_events > 0 {
            "event_rejected"
        } else if counts.pending > 0 {
            "pending_dependencies"
        } else if counts.accepted + counts.duplicates > 0 {
            "event_received"
        } else {
            "unresolved"
        };
        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "command": "sync_fetch_once",
                "state": state,
                "peer_fingerprint": super::hex(&target.peer_fingerprint),
                "space_id": super::hex(&target.space_id),
                "group_reference": super::hex(&target.group_reference),
                "scope_id": super::hex(target.scope.as_bytes()),
                "requested_event_id": target.event_id.map(|id| super::hex(&id)),
                "plan_status": sync_status_name(exchange.plan.status),
                "planned_sequence_ranges": planned_ranges,
                "unresolved_sequence_ranges": unresolved_ranges,
                "unresolved_history_ranges": unresolved_history,
                "unresolved_dependency_ids": unresolved_dependencies,
                "accepted_events": counts.accepted,
                "accepted_event_ids": counts.accepted_event_ids,
                "pending_dependency_ids": counts.pending_dependency_ids,
                "pending_events": counts.pending,
                "duplicate_events": counts.duplicates,
                "rejected_events": rejected_events,
                "recipient_delivery_claimed": false,
            })
        );
    } else {
        println!(
            "Scoped sync plan for Space {} group {}: {}; received {} event(s), retained {} pending, recognized {} duplicates, rejected {rejected_events}.",
            super::hex(&target.space_id),
            super::hex(&target.group_reference),
            sync_status_name(exchange.plan.status),
            counts.accepted,
            counts.pending,
            counts.duplicates,
        );
        for requested in &exchange.plan.request_ranges {
            println!(
                "Planned range for author {}: {}–{}.",
                super::hex(requested.author.as_bytes()),
                requested.range.start(),
                requested.range.end(),
            );
        }
        for unresolved in &exchange.unresolved_ranges {
            println!(
                "Unresolved range for author {}: {}–{}.",
                super::hex(unresolved.author.as_bytes()),
                unresolved.range.start(),
                unresolved.range.end(),
            );
        }
        for dependency in &exchange.unresolved_dependencies {
            println!(
                "Unresolved dependency event {}.",
                super::hex(dependency.as_bytes()),
            );
        }
        for unresolved in &exchange.unresolved_history {
            println!(
                "Unfillable history gap for author {}: {}–{} ({})",
                super::hex(unresolved.author.as_bytes()),
                unresolved.range.start(),
                unresolved.range.end(),
                gap_reason_name(unresolved.reason),
            );
        }
        println!("No recipient-delivery claim is made.");
    }
}

fn sequence_range_json(author: AuthorId, range: SequenceRange) -> serde_json::Value {
    serde_json::json!({
        "author_id": super::hex(author.as_bytes()),
        "start": range.start(),
        "end": range.end(),
    })
}

fn unresolved_history_json(unresolved: &UnresolvedHistory) -> serde_json::Value {
    serde_json::json!({
        "author_id": super::hex(unresolved.author.as_bytes()),
        "start": unresolved.range.start(),
        "end": unresolved.range.end(),
        "reason": gap_reason_name(unresolved.reason),
    })
}

fn sync_status_name(status: SyncStatus) -> &'static str {
    match status {
        SyncStatus::UpToDate => "up_to_date",
        SyncStatus::RequestsPending => "requests_pending",
        SyncStatus::HistoryIncomplete => "history_incomplete",
        SyncStatus::RequestsPendingWithHistoryGaps => "requests_pending_with_history_gaps",
    }
}

fn gap_reason_name(reason: GapReason) -> &'static str {
    match reason {
        GapReason::Unknown => "unknown",
        GapReason::Retention => "retention",
    }
}

fn serve_once(
    listen: SocketAddr,
    space_id: &str,
    group_reference: &str,
    peer_fingerprint: &str,
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    let space_id = super::parse_fixed_hex::<16>(space_id, "space ID")
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let group_reference = super::parse_fixed_hex::<32>(group_reference, "group reference")
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let peer_fingerprint = super::parse_fixed_hex::<32>(peer_fingerprint, "peer fingerprint")
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let scope = space_generation_scope_id(&space_id, &group_reference);

    let client = Client::open_existing(database_path, protector)?;
    if client.pinned_identity(&peer_fingerprint)?.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "requested peer fingerprint is not pinned in this profile",
        )
        .into());
    }
    let store = Store::open(database_path)?;
    let mut source = StoreSyncEventSource::new(&store, scope, space_id, group_reference);
    let mut summary_source = StoreSyncSummarySource::new(&store, scope, space_id, group_reference);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let listener = runtime
        .block_on(TcpPeerListener::bind(listen, MAX_EVENT_BYTES))
        .map_err(|error| io::Error::other(format!("{error:?}")))?;
    let bound = listener
        .local_addr()
        .map_err(|error| io::Error::other(format!("{error:?}")))?;
    if !json {
        println!(
            "Waiting for one authenticated sync request on {bound} with scope {}",
            super::hex(scope.as_bytes())
        );
    }
    let (adapter, remote_address) = runtime
        .block_on(listener.accept())
        .map_err(|error| io::Error::other(format!("{error:?}")))?;
    let cancellation = CancellationToken::new();
    let authenticated = runtime.block_on(client.with_pinned_identity(
        &peer_fingerprint,
        |identity, pinned_peer| async move {
            serve_authenticated_sync_v2_once(
                &adapter,
                identity,
                pinned_peer,
                &mut summary_source,
                &mut source,
                |peer, requested_scope| {
                    peer.fingerprint() == peer_fingerprint && requested_scope == scope
                },
                &cancellation,
            )
            .await
        },
    ))?;
    let result = authenticated.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "requested peer fingerprint is no longer pinned",
        )
    })?;
    let result = result.map_err(|error| io::Error::other(error.to_string()))?;
    print_serve_result(
        json,
        bound,
        remote_address,
        &peer_fingerprint,
        scope,
        result.exchange,
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReconciliationState {
    Stable,
    BoundedIncomplete,
    HistoryGap,
    PendingDependencies,
    TransportFailure,
}

impl ReconciliationState {
    fn name(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::BoundedIncomplete => "bounded_incomplete",
            Self::HistoryGap => "history_gap",
            Self::PendingDependencies => "pending_dependencies",
            Self::TransportFailure => "transport_failure",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::BoundedIncomplete => "bounded/incomplete",
            Self::HistoryGap => "history gap",
            Self::PendingDependencies => "pending dependencies",
            Self::TransportFailure => "transport failure",
        }
    }
}

#[derive(Clone, Copy)]
struct ReconciliationRoundAssessment {
    initial_local_status: SyncStatus,
    local_status: SyncStatus,
    peer_status: SyncStatus,
    accepted_events: usize,
    pending_events: usize,
    retried_pending_events: usize,
    retried_duplicate_events: usize,
    duplicate_events: usize,
    rejected_events: usize,
    served_events: usize,
    unresolved_ranges: usize,
    unresolved_dependencies: usize,
    unresolved_history: usize,
    omitted_requests: usize,
    local_summary_changed: bool,
}

enum ReconciliationDecision {
    Stable,
    Continue,
    Stop(ReconciliationState, &'static str),
}

fn decide_reconciliation_round(
    round: usize,
    max_rounds: usize,
    assessment: ReconciliationRoundAssessment,
) -> ReconciliationDecision {
    let unresolved = assessment.unresolved_ranges > 0
        || assessment.unresolved_dependencies > 0
        || assessment.unresolved_history > 0
        || assessment.omitted_requests > 0
        || assessment.retried_pending_events > 0;
    let worked = assessment.accepted_events > 0
        || assessment.pending_events > 0
        || assessment.retried_pending_events > 0
        || assessment.duplicate_events > 0
        || assessment.retried_duplicate_events > 0
        || assessment.rejected_events > 0
        || assessment.served_events > 0;
    if assessment.initial_local_status == SyncStatus::UpToDate
        && assessment.local_status == SyncStatus::UpToDate
        && assessment.peer_status == SyncStatus::UpToDate
        && !worked
        && !unresolved
    {
        return ReconciliationDecision::Stable;
    }

    let made_progress = assessment.local_summary_changed
        || assessment.accepted_events > 0
        || assessment.served_events > 0
        || assessment.retried_duplicate_events > 0;
    if round < max_rounds && made_progress {
        return ReconciliationDecision::Continue;
    }

    let state = if assessment.unresolved_history > 0 {
        ReconciliationState::HistoryGap
    } else if assessment.unresolved_dependencies > 0 || assessment.retried_pending_events > 0 {
        ReconciliationState::PendingDependencies
    } else {
        ReconciliationState::BoundedIncomplete
    };
    let reason = if round >= max_rounds {
        "maximum_rounds_reached"
    } else {
        "no_progress"
    };
    ReconciliationDecision::Stop(state, reason)
}

struct ReconciliationReport {
    target: FetchOnceTarget,
    listen_address: SocketAddr,
    max_rounds: usize,
    rounds_completed: usize,
    state: ReconciliationState,
    reason: &'static str,
    initial_local_plan_status: Option<SyncStatus>,
    local_plan_status: Option<SyncStatus>,
    peer_plan_status: Option<SyncStatus>,
    accepted_events: usize,
    retried_accepted_events: usize,
    retried_pending_events: usize,
    retried_duplicate_events: usize,
    pending_events: usize,
    duplicate_events: usize,
    rejected_events: usize,
    served_events: usize,
    unresolved_ranges: Vec<serde_json::Value>,
    unresolved_dependencies: Vec<String>,
    unresolved_history: Vec<serde_json::Value>,
    unserved_requests: usize,
    transport_error: Option<String>,
}

impl ReconciliationReport {
    fn new(target: FetchOnceTarget, listen_address: SocketAddr) -> Self {
        Self {
            target,
            listen_address,
            max_rounds: MAX_RECONCILIATION_ROUNDS,
            rounds_completed: 0,
            state: ReconciliationState::BoundedIncomplete,
            reason: "maximum_rounds_reached",
            initial_local_plan_status: None,
            local_plan_status: None,
            peer_plan_status: None,
            accepted_events: 0,
            retried_accepted_events: 0,
            retried_pending_events: 0,
            retried_duplicate_events: 0,
            pending_events: 0,
            duplicate_events: 0,
            rejected_events: 0,
            served_events: 0,
            unresolved_ranges: Vec::new(),
            unresolved_dependencies: Vec::new(),
            unresolved_history: Vec::new(),
            unserved_requests: 0,
            transport_error: None,
        }
    }
}

enum ReconciliationRoundFailure {
    Transport(String),
    Local(Box<dyn Error>),
}

fn run_reconciliation_round(
    runtime: &tokio::runtime::Runtime,
    listener: &TcpPeerListener,
    client: &Client,
    summary_source: &mut StoreSyncSummarySource<'_>,
    event_source: &mut StoreSyncEventSource<'_>,
    target: FetchOnceTarget,
    local_summary: &lattice_sync::ScopeSummary,
) -> Result<
    (
        AuthenticatedSyncV2Exchange<&'static str>,
        AuthenticatedSyncV2ServeResult,
    ),
    ReconciliationRoundFailure,
> {
    retry_reconciliation_attempts(|| {
        run_reconciliation_round_attempt(
            runtime,
            listener,
            client,
            summary_source,
            event_source,
            target,
            local_summary,
        )
    })
}

fn retry_reconciliation_attempts<T>(
    mut run_attempt: impl FnMut() -> Result<T, ReconciliationRoundFailure>,
) -> Result<T, ReconciliationRoundFailure> {
    let mut last_transport_error = None;
    for attempt in 0..MAX_RECONCILIATION_CONNECTION_ATTEMPTS {
        match run_attempt() {
            Ok(result) => return Ok(result),
            Err(ReconciliationRoundFailure::Local(error)) => {
                return Err(ReconciliationRoundFailure::Local(error));
            }
            Err(ReconciliationRoundFailure::Transport(error)) => {
                last_transport_error = Some(error);
                if attempt + 1 == MAX_RECONCILIATION_CONNECTION_ATTEMPTS {
                    break;
                }
            }
        }
    }
    Err(ReconciliationRoundFailure::Transport(
        last_transport_error
            .unwrap_or_else(|| "sync retry loop exhausted without a result".to_owned()),
    ))
}

fn run_reconciliation_round_attempt(
    runtime: &tokio::runtime::Runtime,
    listener: &TcpPeerListener,
    client: &Client,
    summary_source: &mut StoreSyncSummarySource<'_>,
    event_source: &mut StoreSyncEventSource<'_>,
    target: FetchOnceTarget,
    local_summary: &lattice_sync::ScopeSummary,
) -> Result<
    (
        AuthenticatedSyncV2Exchange<&'static str>,
        AuthenticatedSyncV2ServeResult,
    ),
    ReconciliationRoundFailure,
> {
    let (outbound_adapter, (inbound_adapter, _remote_address)) = runtime
        .block_on(tokio::time::timeout(RECONCILIATION_STAGE_TIMEOUT, async {
            tokio::try_join!(
                TcpPeerAdapter::connect(target.connect, MAX_EVENT_BYTES),
                listener.accept()
            )
        }))
        .map_err(|_| {
            ReconciliationRoundFailure::Transport(
                "TCP connect/accept stage timed out after 30 seconds".to_owned(),
            )
        })?
        .map_err(|error| ReconciliationRoundFailure::Transport(format!("{error:?}")))?;
    let mut deduplicator = EventDeduplicator::new(128).map_err(|error| {
        ReconciliationRoundFailure::Local(Box::new(io::Error::other(format!("{error:?}"))))
    })?;
    let cancellation = CancellationToken::new();
    let mut validator = |requested_scope: ScopeId,
                         author: AuthorId,
                         sequence: u64,
                         expected_id: Option<EventId>,
                         bytes: &[u8]|
     -> Result<EventId, &'static str> {
        validate_fetch_event(
            target,
            requested_scope,
            author,
            sequence,
            expected_id,
            bytes,
        )
    };

    let pinned_session = runtime
        .block_on(tokio::time::timeout(
            RECONCILIATION_STAGE_TIMEOUT,
            client.with_pinned_identity(
                &target.peer_fingerprint,
                |identity, pinned_peer| async move {
                    let outbound = execute_authenticated_sync_v2_once(
                        &outbound_adapter,
                        identity,
                        pinned_peer,
                        local_summary,
                        &mut deduplicator,
                        &mut validator,
                        |peer, requested_scope| {
                            peer.fingerprint() == target.peer_fingerprint
                                && requested_scope == target.scope
                        },
                        &cancellation,
                    );
                    let inbound = serve_authenticated_sync_v2_once(
                        &inbound_adapter,
                        identity,
                        pinned_peer,
                        summary_source,
                        event_source,
                        |peer, requested_scope| {
                            peer.fingerprint() == target.peer_fingerprint
                                && requested_scope == target.scope
                        },
                        &cancellation,
                    );
                    tokio::try_join!(outbound, inbound)
                },
            ),
        ))
        .map_err(|_| {
            ReconciliationRoundFailure::Transport(
                "authenticated sync stage timed out after 30 seconds".to_owned(),
            )
        })?
        .map_err(|error| ReconciliationRoundFailure::Local(Box::new(error)))?;
    let session = pinned_session.ok_or_else(|| {
        ReconciliationRoundFailure::Local(Box::new(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "requested peer fingerprint is no longer pinned",
        )))
    })?;
    let (outbound, inbound) = match session {
        Ok(session) => session,
        Err(error @ lattice_node::sync::AuthenticatedSyncError::EventSource(_)) => {
            return Err(ReconciliationRoundFailure::Local(Box::new(error)));
        }
        Err(error) => {
            return Err(ReconciliationRoundFailure::Transport(error.to_string()));
        }
    };
    Ok((outbound, inbound))
}

struct ReconciliationContext<'a> {
    runtime: &'a tokio::runtime::Runtime,
    listener: &'a TcpPeerListener,
    client: &'a mut Client,
    created: &'a mut lattice_core::CreatedSpace,
    event_source: &'a mut StoreSyncEventSource<'a>,
    summary_source: &'a mut StoreSyncSummarySource<'a>,
    target: FetchOnceTarget,
}

fn reconcile(
    request: ReconcileRequest<'_>,
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    let space_id = super::parse_fixed_hex::<16>(request.space_id, "space ID")
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let group_reference = super::parse_fixed_hex::<32>(request.group_reference, "group reference")
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let peer_fingerprint =
        super::parse_fixed_hex::<32>(request.peer_fingerprint, "peer fingerprint")
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let target = FetchOnceTarget {
        connect: request.connect,
        space_id,
        group_reference,
        peer_fingerprint,
        event_id: None,
        scope: space_generation_scope_id(&space_id, &group_reference),
    };
    let mut client = Client::open_existing(database_path, protector)?;
    let mut created = client.restore_space(&target.space_id, &target.group_reference)?;
    if client.pinned_identity(&target.peer_fingerprint)?.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "requested peer fingerprint is not pinned in this profile",
        )
        .into());
    }
    let store = Store::open(database_path)?;
    let mut event_source = StoreSyncEventSource::new(
        &store,
        target.scope,
        target.space_id,
        target.group_reference,
    );
    let mut summary_source = StoreSyncSummarySource::new(
        &store,
        target.scope,
        target.space_id,
        target.group_reference,
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let listener = runtime
        .block_on(TcpPeerListener::bind(request.listen, MAX_EVENT_BYTES))
        .map_err(|error| io::Error::other(format!("{error:?}")))?;
    let bound = listener
        .local_addr()
        .map_err(|error| io::Error::other(format!("{error:?}")))?;
    if !json {
        println!(
            "Bidirectional direct sync listening on {bound}; connecting to {}. Both peers must run this command concurrently.",
            request.connect
        );
    }

    let mut report = ReconciliationReport::new(target, bound);
    run_reconciliation_rounds(
        ReconciliationContext {
            runtime: &runtime,
            listener: &listener,
            client: &mut client,
            created: &mut created,
            event_source: &mut event_source,
            summary_source: &mut summary_source,
            target,
        },
        &mut report,
    )?;
    print_reconciliation_result(&report, json);
    Ok(())
}

fn run_reconciliation_rounds(
    context: ReconciliationContext<'_>,
    report: &mut ReconciliationReport,
) -> Result<(), Box<dyn Error>> {
    let ReconciliationContext {
        runtime,
        listener,
        client,
        created,
        event_source,
        summary_source,
        target,
    } = context;
    for round_number in 1..=MAX_RECONCILIATION_ROUNDS {
        let before_summary = summary_source
            .load_summary(target.scope)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let (outbound, inbound) = match run_reconciliation_round(
            runtime,
            listener,
            client,
            summary_source,
            event_source,
            target,
            &before_summary,
        ) {
            Ok(round) => round,
            Err(ReconciliationRoundFailure::Transport(error)) => {
                report.state = ReconciliationState::TransportFailure;
                report.reason = "transport_or_authenticated_session_failure";
                report.transport_error = Some(error);
                break;
            }
            Err(ReconciliationRoundFailure::Local(error)) => return Err(error),
        };
        let counts = accept_reconciliation_events(client, created, &outbound.exchange.events)?;
        let after_summary = summary_source
            .load_summary(target.scope)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let local_plan = plan_sync(&after_summary, &outbound.peer_summary)
            .map_err(|error| io::Error::other(format!("{error:?}")))?;
        let peer_plan = plan_sync(&inbound.peer_summary, &after_summary)
            .map_err(|error| io::Error::other(format!("{error:?}")))?;

        if report.initial_local_plan_status.is_none() {
            report.initial_local_plan_status = Some(outbound.exchange.plan.status);
        }
        report.local_plan_status = Some(local_plan.status);
        report.peer_plan_status = Some(peer_plan.status);
        report.rounds_completed = round_number;
        report.accepted_events += counts.accepted;
        report.retried_accepted_events += counts.retried_accepted;
        report.retried_pending_events += counts.retried_pending;
        report.retried_duplicate_events += counts.retried_duplicates;
        report.pending_events += counts.pending;
        report.duplicate_events += counts.duplicates;
        report.rejected_events += outbound.exchange.rejected_events.len();
        report.served_events += inbound.exchange.included_events;
        report.unserved_requests = inbound.exchange.omitted_targets.len();
        report.unresolved_ranges =
            reconciliation_ranges(&outbound.exchange, &local_plan, &peer_plan);
        report.unresolved_dependencies =
            reconciliation_dependencies(&outbound.exchange, &local_plan, &peer_plan);
        report.unresolved_history =
            reconciliation_history(&outbound.exchange, &local_plan, &peer_plan);
        let assessment = ReconciliationRoundAssessment {
            initial_local_status: outbound.exchange.plan.status,
            local_status: local_plan.status,
            peer_status: peer_plan.status,
            accepted_events: counts.accepted,
            retried_pending_events: counts.retried_pending,
            retried_duplicate_events: counts.retried_duplicates,
            pending_events: counts.pending,
            duplicate_events: counts.duplicates,
            rejected_events: outbound.exchange.rejected_events.len(),
            served_events: inbound.exchange.included_events,
            unresolved_ranges: report.unresolved_ranges.len(),
            unresolved_dependencies: report.unresolved_dependencies.len(),
            unresolved_history: report.unresolved_history.len(),
            omitted_requests: report.unserved_requests,
            local_summary_changed: before_summary != after_summary,
        };
        match decide_reconciliation_round(round_number, MAX_RECONCILIATION_ROUNDS, assessment) {
            ReconciliationDecision::Stable => {
                report.state = ReconciliationState::Stable;
                report.reason = "both_directions_up_to_date_without_round_work";
                break;
            }
            ReconciliationDecision::Continue => {}
            ReconciliationDecision::Stop(state, reason) => {
                report.state = state;
                report.reason = reason;
                break;
            }
        }
    }
    Ok(())
}

fn reconciliation_ranges(
    exchange: &SyncExchange<&'static str>,
    local_plan: &lattice_sync::SyncPlan,
    peer_plan: &lattice_sync::SyncPlan,
) -> Vec<serde_json::Value> {
    let mut ranges = Vec::new();
    let mut add = |side: &str, requested: &lattice_sync::SyncRequestRange| {
        let value = serde_json::json!({
            "side": side,
            "author_id": super::hex(requested.author.as_bytes()),
            "start": requested.range.start(),
            "end": requested.range.end(),
        });
        if !ranges.contains(&value) {
            ranges.push(value);
        }
    };
    for requested in &local_plan.request_ranges {
        add("local", requested);
    }
    for requested in &peer_plan.request_ranges {
        add("peer", requested);
    }
    for requested in &exchange.unresolved_ranges {
        add("local_unresolved", requested);
    }
    ranges
}

fn reconciliation_dependencies(
    exchange: &SyncExchange<&'static str>,
    local_plan: &lattice_sync::SyncPlan,
    peer_plan: &lattice_sync::SyncPlan,
) -> Vec<String> {
    let mut dependencies = Vec::new();
    for dependency in local_plan
        .dependency_requests
        .iter()
        .chain(&peer_plan.dependency_requests)
        .chain(&exchange.unresolved_dependencies)
    {
        let id = super::hex(dependency.as_bytes());
        if !dependencies.contains(&id) {
            dependencies.push(id);
        }
    }
    dependencies
}

fn reconciliation_history(
    exchange: &SyncExchange<&'static str>,
    local_plan: &lattice_sync::SyncPlan,
    peer_plan: &lattice_sync::SyncPlan,
) -> Vec<serde_json::Value> {
    let mut history = Vec::new();
    for unresolved in exchange
        .plan
        .unresolved_history
        .iter()
        .chain(&local_plan.unresolved_history)
        .chain(&peer_plan.unresolved_history)
    {
        let value = unresolved_history_json(unresolved);
        if !history.contains(&value) {
            history.push(value);
        }
    }
    history
}

fn reconciliation_result_json(report: &ReconciliationReport) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "command": "sync_reconcile",
        "state": report.state.name(),
        "reason": report.reason,
        "connect_address": report.target.connect.to_string(),
        "listen_address": report.listen_address.to_string(),
        "peer_fingerprint": super::hex(&report.target.peer_fingerprint),
        "space_id": super::hex(&report.target.space_id),
        "group_reference": super::hex(&report.target.group_reference),
        "scope_id": super::hex(report.target.scope.as_bytes()),
        "rounds_completed": report.rounds_completed,
        "maximum_rounds": report.max_rounds,
        "initial_local_plan_status": report.initial_local_plan_status.map(sync_status_name),
        "local_plan_status": report.local_plan_status.map(sync_status_name),
        "peer_plan_status": report.peer_plan_status.map(sync_status_name),
        "accepted_events": report.accepted_events,
        "retried_accepted_events": report.retried_accepted_events,
        "retried_pending_events": report.retried_pending_events,
        "retried_duplicate_events": report.retried_duplicate_events,
        "pending_events": report.pending_events,
        "duplicate_events": report.duplicate_events,
        "rejected_events": report.rejected_events,
        "served_events": report.served_events,
        "unresolved_ranges": report.unresolved_ranges,
        "unresolved_dependency_ids": report.unresolved_dependencies,
        "unresolved_history_ranges": report.unresolved_history,
        "last_round_unserved_requests": report.unserved_requests,
        "transport_error": report.transport_error,
        "convergence_claimed": report.state == ReconciliationState::Stable,
        "recipient_delivery_claimed": false,
    })
}

fn reconciliation_result_text(report: &ReconciliationReport) -> String {
    let mut lines = vec![format!(
        "Bidirectional direct sync: {} after {} of {} round(s) ({}).",
        report.state.label(),
        report.rounds_completed,
        report.max_rounds,
        report.reason,
    )];
    lines.push(format!(
        "Peer {}; scope {}; listener {}; outbound {}.",
        super::hex(&report.target.peer_fingerprint),
        super::hex(report.target.scope.as_bytes()),
        report.listen_address,
        report.target.connect,
    ));
    if let (Some(local), Some(peer)) = (report.local_plan_status, report.peer_plan_status) {
        lines.push(format!(
            "Latest plan status: local {}, peer {}.",
            sync_status_name(local),
            sync_status_name(peer),
        ));
    }
    lines.push(format!(
        "Applied {} event(s); {} pending, {} duplicate, {} rejected; retried {} accepted, {} pending, {} duplicate; served {} event(s); last round left {} request(s) unserved.",
        report.accepted_events,
        report.pending_events,
        report.duplicate_events,
        report.rejected_events,
        report.retried_accepted_events,
        report.retried_pending_events,
        report.retried_duplicate_events,
        report.served_events,
        report.unserved_requests,
    ));
    if !report.unresolved_dependencies.is_empty() {
        lines.push(format!(
            "Unresolved dependencies: {}.",
            report.unresolved_dependencies.join(", "),
        ));
    }
    for range in &report.unresolved_ranges {
        lines.push(format!(
            "Unresolved {} range for author {}: {}–{}.",
            range["side"].as_str().unwrap_or("unknown-side"),
            range["author_id"].as_str().unwrap_or("unknown-author"),
            range["start"],
            range["end"],
        ));
    }
    for history in &report.unresolved_history {
        lines.push(format!(
            "Unfillable history gap for author {}: {}–{} ({}).",
            history["author_id"].as_str().unwrap_or("unknown-author"),
            history["start"],
            history["end"],
            history["reason"].as_str().unwrap_or("unknown"),
        ));
    }
    if let Some(error) = &report.transport_error {
        lines.push(format!("Transport/session failure: {error}."));
    }
    if report.state == ReconciliationState::Stable {
        lines.push("Both directions were up to date in a work-free round.".to_owned());
    } else {
        lines.push("Synchronization is incomplete; convergence is not claimed.".to_owned());
    }
    lines.push("No recipient-delivery claim is made.".to_owned());
    lines.join("\n")
}

fn print_reconciliation_result(report: &ReconciliationReport, json: bool) {
    if json {
        println!("{}", reconciliation_result_json(report));
    } else {
        println!("{}", reconciliation_result_text(report));
    }
}

fn print_serve_result(
    json: bool,
    bound: SocketAddr,
    remote_address: SocketAddr,
    peer_fingerprint: &[u8; 32],
    scope: ScopeId,
    result: SyncServeResult,
) {
    let exchange = result;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "command": "sync_serve_once",
                "state": "authenticated_request_served",
                "listen_address": bound.to_string(),
                "remote_address": remote_address.to_string(),
                "peer_fingerprint": super::hex(peer_fingerprint),
                "scope_id": super::hex(scope.as_bytes()),
                "included_events": exchange.included_events,
                "omitted_requests": exchange.omitted_targets.len(),
                "response_hop": format!("{:?}", exchange.response_hop),
                "recipient_delivery_claimed": false,
                "events_applied_locally": false,
            })
        );
    } else {
        println!(
            "Authenticated direct-sync request from {remote_address}; served {} event(s), {} unresolved request(s), response {:?}.",
            exchange.included_events,
            exchange.omitted_targets.len(),
            exchange.response_hop
        );
        println!("No recipient-delivery or local-application claim is made.");
    }
}

fn print_status(
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    let client = match Client::open_existing(database_path, protector) {
        Ok(client) => client,
        Err(CoreError::MissingIdentity) => {
            return Err(Box::new(CoreError::MissingIdentity));
        }
        Err(error) => return Err(Box::new(error)),
    };
    let next_local_event_sequence = client.next_author_sequence()?;
    drop(client);

    let store = Store::open(database_path)?;
    let pending_event_details = pending_event_summaries(&store)?;
    let pending_event_count = pending_event_details.len();
    let pending_mls_epochs = pending_event_details
        .iter()
        .map(|pending| {
            serde_json::json!({
                "space_id": pending["space_id"],
                "group_reference": pending["group_reference"],
                "event_id": pending["event_id"],
                "epoch": pending["mls_epoch"],
            })
        })
        .collect::<Vec<_>>();
    let committed_event_count = committed_event_count(&store)?;
    let outbox = outbox_counts(&store)?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "command": "sync_status",
                "identity": "initialized",
                "next_local_event_sequence": next_local_event_sequence,
                "committed_events": committed_event_count,
                "pending_events": pending_event_count,
                "outbox": {
                    "total": outbox.total,
                    "queued": outbox.queued,
                    "forwarded": outbox.forwarded,
                    "destination_receipt_recorded": outbox.destination_receipt_recorded,
                    "failed": outbox.failed,
                },
                "missing_ranges": null,
                "missing_ranges_available": false,
                "pending_events_by_space": pending_event_details,
                "pending_mls_epochs": pending_mls_epochs,
                "pending_mls_epochs_available": true,
                "destination_receipt_state_source": "local_outbox_record",
                "network_exchange_available": false,
                "recipient_delivery_claimed": false,
            })
        );
    } else {
        println!("Local event sequence ready: {next_local_event_sequence}");
        println!("Committed events: {committed_event_count}");
        println!("Pending dependency events: {pending_event_count}");
        for pending in &pending_event_details {
            println!(
                "Pending event {} in Space {} group {}: author sequence {}, MLS epoch {}, missing dependencies {}.",
                pending["event_id"].as_str().unwrap_or_default(),
                pending["space_id"].as_str().unwrap_or_default(),
                pending["group_reference"].as_str().unwrap_or_default(),
                pending["author_sequence"],
                pending["mls_epoch"],
                pending["missing_dependencies"],
            );
        }
        println!(
            "Outbox: {} total ({} queued, {} forwarded, {} destination receipts recorded, {} failed).",
            outbox.total,
            outbox.queued,
            outbox.forwarded,
            outbox.destination_receipt_recorded,
            outbox.failed
        );
        println!(
            "Peer-relative history ranges remain unavailable until a scoped summary exchange."
        );
        println!("No synchronization scheduler or network exchange is running.");
        println!(
            "Destination-receipt counts reflect local outbox state and are not independently verified here."
        );
        println!("Forwarding or relay acceptance is not recipient delivery.");
    }
    Ok(())
}

fn committed_event_count(store: &Store) -> Result<usize, Box<dyn Error>> {
    let mut count = 0;
    let mut after = None;
    loop {
        let page = store.list_event_page(after, MAX_EVENT_PAGE_SIZE)?;
        count += page.len();
        after = page.last().map(|event| event.event_id);
        if page.len() < MAX_EVENT_PAGE_SIZE {
            return Ok(count);
        }
    }
}

fn outbox_counts(store: &Store) -> Result<OutboxCounts, Box<dyn Error>> {
    let mut counts = OutboxCounts::default();
    let mut after = None;
    loop {
        let page = store.list_outbox_page(after, MAX_OUTBOX_PAGE_SIZE)?;
        if page.is_empty() {
            return Ok(counts);
        }
        for entry in &page {
            counts.total += 1;
            match entry.state {
                OutboxState::Queued => counts.queued += 1,
                OutboxState::Forwarded => counts.forwarded += 1,
                OutboxState::Delivered => counts.destination_receipt_recorded += 1,
                OutboxState::Failed => counts.failed += 1,
            }
        }
        after = page.last().map(|entry| entry.event_id);
        if page.len() < MAX_OUTBOX_PAGE_SIZE {
            return Ok(counts);
        }
    }
}

fn pending_event_summaries(store: &Store) -> Result<Vec<serde_json::Value>, Box<dyn Error>> {
    let mut summaries = Vec::new();
    for pending in store.list_pending()? {
        let event = VerifiedSignatureOnlyEvent::decode_verify(&pending.canonical_bytes)?;
        if event.event_id().as_bytes() != &pending.event_id {
            return Err(Box::new(io::Error::other(
                "pending event signed ID does not match its storage key",
            )));
        }
        summaries.push(serde_json::json!({
            "state": "pending_dependencies",
            "space_id": super::hex(event.space_id()),
            "group_reference": super::hex(event.mls_group_reference()),
            "event_id": super::hex(&pending.event_id),
            "author_id": super::hex(event.author_fingerprint()),
            "author_sequence": event.author_sequence(),
            "mls_epoch": event.mls_epoch(),
            "missing_dependencies": pending
                .missing_dependencies
                .iter()
                .map(|dependency| super::hex(dependency))
                .collect::<Vec<_>>(),
        }));
    }
    Ok(summaries)
}

#[derive(Default)]
struct OutboxCounts {
    total: usize,
    queued: usize,
    forwarded: usize,
    destination_receipt_recorded: usize,
    failed: usize,
}

#[cfg(test)]
mod tests {
    use super::{
        ReconciliationRoundFailure, pending_event_summaries, retry_reconciliation_attempts,
    };
    use lattice_events::{EventDraft, EventKind, VerifiedSignatureOnlyEvent};
    use lattice_identity::DeviceIdentity;
    use lattice_storage::Store;
    use lattice_sync::SyncStatus;

    #[test]
    fn reconciliation_retries_transport_failure_before_success() {
        let attempts = std::cell::Cell::new(0);
        let result = retry_reconciliation_attempts(|| {
            let attempt = attempts.get() + 1;
            attempts.set(attempt);
            if attempt == 1 {
                Err(ReconciliationRoundFailure::Transport(
                    "unauthenticated peer disconnected".to_owned(),
                ))
            } else {
                Ok("authenticated round")
            }
        });

        assert!(matches!(result, Ok("authenticated round")));
        assert_eq!(attempts.get(), 2);
    }

    #[test]
    fn reconciliation_does_not_retry_local_failures() {
        let attempts = std::cell::Cell::new(0);
        let result: Result<(), _> = retry_reconciliation_attempts(|| {
            attempts.set(attempts.get() + 1);
            Err(ReconciliationRoundFailure::Local(Box::new(
                std::io::Error::other("local event source failed"),
            )))
        });

        assert!(matches!(result, Err(ReconciliationRoundFailure::Local(_))));
        assert_eq!(attempts.get(), 1);
    }

    #[test]
    fn reconciliation_bounds_transport_retries() {
        let attempts = std::cell::Cell::new(0);
        let result: Result<(), _> = retry_reconciliation_attempts(|| {
            attempts.set(attempts.get() + 1);
            Err(ReconciliationRoundFailure::Transport(
                "peer disconnected".to_owned(),
            ))
        });

        assert!(matches!(
            result,
            Err(ReconciliationRoundFailure::Transport(_))
        ));
        assert_eq!(
            attempts.get(),
            super::MAX_RECONCILIATION_CONNECTION_ATTEMPTS
        );
    }
    #[test]
    fn pending_status_reports_only_verified_space_epoch_and_dependency_metadata() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock follows epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "lattice-cli-pending-status-{}-{nonce}.sqlite",
            std::process::id(),
        ));
        let identity = DeviceIdentity::generate().expect("generate event signer");
        let space_id = [0x31; 16];
        let group_reference = [0x42; 32];
        let channel_id = [0x53; 16];
        let parent = VerifiedSignatureOnlyEvent::create(
            &identity,
            EventDraft {
                space_id,
                channel_id: Some(channel_id),
                author_sequence: 1,
                lamport: 1,
                wall_time_hint: 0,
                parents: Vec::new(),
                kind: EventKind::Message,
                protected_body: vec![0x80],
                mls_group_reference: group_reference,
                mls_epoch: 6,
            },
        )
        .expect("create missing parent event");
        let missing_dependency = *parent.event_id().as_bytes();
        let pending = VerifiedSignatureOnlyEvent::create(
            &identity,
            EventDraft {
                space_id,
                channel_id: Some(channel_id),
                author_sequence: 2,
                lamport: 2,
                wall_time_hint: 0,
                parents: vec![parent.event_id()],
                kind: EventKind::Message,
                protected_body: vec![0x81],
                mls_group_reference: group_reference,
                mls_epoch: 7,
            },
        )
        .expect("create event waiting on a parent");
        let pending_id = *pending.event_id().as_bytes();
        let mut store = Store::open(&path).expect("open temporary store");
        store
            .store_pending(pending_id, pending.encoded_bytes(), &[missing_dependency])
            .expect("store pending event");

        let summaries = pending_event_summaries(&store).expect("summarize pending status");
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0]["state"], "pending_dependencies");
        assert_eq!(summaries[0]["space_id"], super::super::hex(&space_id));
        assert_eq!(
            summaries[0]["group_reference"],
            super::super::hex(&group_reference)
        );
        assert_eq!(summaries[0]["event_id"], super::super::hex(&pending_id));
        assert_eq!(
            summaries[0]["author_id"],
            super::super::hex(&identity.fingerprint())
        );
        assert_eq!(summaries[0]["author_sequence"], 2);
        assert_eq!(summaries[0]["mls_epoch"], 7);
        assert_eq!(
            summaries[0]["missing_dependencies"][0],
            super::super::hex(&missing_dependency)
        );
        assert!(summaries[0].get("canonical_bytes").is_none());

        drop(store);
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn scoped_sync_range_report_preserves_author_endpoints_and_gap_reason() {
        let author = lattice_sync::AuthorId::new([0x91; 32]);
        let range = lattice_sync::SequenceRange::new(4, 9).expect("valid inclusive range");
        assert_eq!(
            super::sequence_range_json(author, range),
            serde_json::json!({
                "author_id": super::super::hex(author.as_bytes()),
                "start": 4,
                "end": 9,
            })
        );

        let unresolved = lattice_sync::UnresolvedHistory {
            author,
            range,
            reason: lattice_sync::GapReason::Retention,
        };
        assert_eq!(
            super::unresolved_history_json(&unresolved),
            serde_json::json!({
                "author_id": super::super::hex(author.as_bytes()),
                "start": 4,
                "end": 9,
                "reason": "retention",
            })
        );
        assert_eq!(
            super::sync_status_name(lattice_sync::SyncStatus::RequestsPendingWithHistoryGaps),
            "requests_pending_with_history_gaps"
        );
    }
    #[test]
    fn reconciliation_requires_a_work_free_up_to_date_round_for_stability() {
        let stable = super::ReconciliationRoundAssessment {
            initial_local_status: SyncStatus::UpToDate,
            local_status: SyncStatus::UpToDate,
            peer_status: SyncStatus::UpToDate,
            accepted_events: 0,
            pending_events: 0,
            retried_pending_events: 0,
            retried_duplicate_events: 0,
            duplicate_events: 0,
            rejected_events: 0,
            served_events: 0,
            unresolved_ranges: 0,
            unresolved_dependencies: 0,
            unresolved_history: 0,
            omitted_requests: 0,
            local_summary_changed: false,
        };
        assert!(matches!(
            super::decide_reconciliation_round(2, 8, stable),
            super::ReconciliationDecision::Stable
        ));

        let history_gap = super::ReconciliationRoundAssessment {
            unresolved_history: 1,
            ..stable
        };
        assert!(matches!(
            super::decide_reconciliation_round(2, 8, history_gap),
            super::ReconciliationDecision::Stop(
                super::ReconciliationState::HistoryGap,
                "no_progress"
            )
        ));

        let making_progress = super::ReconciliationRoundAssessment {
            local_summary_changed: true,
            unresolved_history: 1,
            ..stable
        };
        assert!(matches!(
            super::decide_reconciliation_round(2, 8, making_progress),
            super::ReconciliationDecision::Continue
        ));
        assert!(matches!(
            super::decide_reconciliation_round(8, 8, making_progress),
            super::ReconciliationDecision::Stop(
                super::ReconciliationState::HistoryGap,
                "maximum_rounds_reached"
            )
        ));

        let unavailable_range = super::ReconciliationRoundAssessment {
            unresolved_ranges: 1,
            ..stable
        };
        assert!(matches!(
            super::decide_reconciliation_round(1, 8, unavailable_range),
            super::ReconciliationDecision::Stop(
                super::ReconciliationState::BoundedIncomplete,
                "no_progress"
            )
        ));

        let pending = super::ReconciliationRoundAssessment {
            unresolved_dependencies: 1,
            ..stable
        };
        assert!(matches!(
            super::decide_reconciliation_round(1, 8, pending),
            super::ReconciliationDecision::Stop(
                super::ReconciliationState::PendingDependencies,
                "no_progress"
            )
        ));
        let retry_cleared_pending = super::ReconciliationRoundAssessment {
            pending_events: 1,
            retried_duplicate_events: 1,
            ..stable
        };
        assert!(matches!(
            super::decide_reconciliation_round(1, 8, retry_cleared_pending),
            super::ReconciliationDecision::Continue
        ));

        let unresolved_retry = super::ReconciliationRoundAssessment {
            retried_pending_events: 1,
            ..stable
        };
        assert!(matches!(
            super::decide_reconciliation_round(1, 8, unresolved_retry),
            super::ReconciliationDecision::Stop(
                super::ReconciliationState::PendingDependencies,
                "no_progress"
            )
        ));
    }

    #[test]
    fn reconciliation_json_and_text_report_incomplete_history_without_claiming_convergence() {
        let target = super::FetchOnceTarget {
            connect: "127.0.0.1:7000".parse().expect("valid test address"),
            space_id: [0x31; 16],
            group_reference: [0x42; 32],
            peer_fingerprint: [0x53; 32],
            event_id: None,
            scope: super::space_generation_scope_id(&[0x31; 16], &[0x42; 32]),
        };
        let mut report = super::ReconciliationReport::new(
            target,
            "127.0.0.1:7001".parse().expect("valid test address"),
        );
        report.state = super::ReconciliationState::HistoryGap;
        report.reason = "no_progress";
        report.rounds_completed = 2;
        report.local_plan_status = Some(SyncStatus::HistoryIncomplete);
        report.peer_plan_status = Some(SyncStatus::HistoryIncomplete);
        report.unresolved_history.push(serde_json::json!({
            "author_id": super::super::hex(&[0x64; 32]),
            "start": 3,
            "end": 5,
            "reason": "retention",
        }));

        let json = super::reconciliation_result_json(&report);
        assert_eq!(json["state"], "history_gap");
        assert_eq!(json["convergence_claimed"], false);
        assert_eq!(json["recipient_delivery_claimed"], false);
        assert_eq!(json["unresolved_history_ranges"][0]["start"], 3);
        assert_eq!(json["rounds_completed"], 2);

        let text = super::reconciliation_result_text(&report);
        assert!(text.contains("history gap"));
        assert!(text.contains("Unfillable history gap"));
        assert!(text.contains("convergence is not claimed"));
        assert!(text.contains("No recipient-delivery claim is made."));
    }

    #[test]
    fn reconciliation_output_distinguishes_transport_and_dependency_states() {
        let target = super::FetchOnceTarget {
            connect: "127.0.0.1:7000".parse().expect("valid test address"),
            space_id: [0x31; 16],
            group_reference: [0x42; 32],
            peer_fingerprint: [0x53; 32],
            event_id: None,
            scope: super::space_generation_scope_id(&[0x31; 16], &[0x42; 32]),
        };
        let mut report = super::ReconciliationReport::new(
            target,
            "127.0.0.1:7001".parse().expect("valid test address"),
        );
        report.accepted_events = 2;
        report.duplicate_events = 1;
        report.retried_accepted_events = 2;
        report.retried_duplicate_events = 1;
        let bounded = super::reconciliation_result_json(&report);
        assert_eq!(bounded["state"], "bounded_incomplete");
        assert_eq!(bounded["retried_accepted_events"], 2);
        assert_eq!(bounded["retried_duplicate_events"], 1);
        assert!(
            super::reconciliation_result_text(&report)
                .contains("retried 2 accepted, 0 pending, 1 duplicate")
        );
        assert!(super::reconciliation_result_text(&report).contains("bounded/incomplete"));

        report.state = super::ReconciliationState::PendingDependencies;
        report.reason = "no_progress";
        report
            .unresolved_dependencies
            .push(super::super::hex(&[0x75; 32]));
        let pending = super::reconciliation_result_json(&report);
        assert_eq!(pending["state"], "pending_dependencies");
        assert_eq!(
            pending["unresolved_dependency_ids"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(super::reconciliation_result_text(&report).contains("pending dependencies"));

        report.state = super::ReconciliationState::TransportFailure;
        report.reason = "transport_or_authenticated_session_failure";
        report.transport_error = Some("peer closed the session".to_owned());
        let failed = super::reconciliation_result_json(&report);
        assert_eq!(failed["state"], "transport_failure");
        assert_eq!(failed["convergence_claimed"], false);
        assert_eq!(failed["transport_error"], "peer closed the session");
        assert!(super::reconciliation_result_text(&report).contains("Transport/session failure"));

        report.state = super::ReconciliationState::Stable;
        report.reason = "both_directions_up_to_date_without_round_work";
        report.unresolved_dependencies.clear();
        report.accepted_events = 0;
        report.duplicate_events = 0;
        report.retried_accepted_events = 0;
        report.retried_duplicate_events = 0;
        report.transport_error = None;
        let stable = super::reconciliation_result_json(&report);
        assert_eq!(stable["state"], "stable");
        assert_eq!(stable["convergence_claimed"], true);
        assert!(super::reconciliation_result_text(&report).contains("work-free round"));
    }
}
