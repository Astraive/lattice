use lattice_crypto::{
    EstablishedNoiseTransportSession, MAX_NOISE_TRANSPORT_MESSAGE_SIZE, NoiseRole, NoiseSession,
    NoiseSessionError, NoiseTransportError,
};
use lattice_identity::{DeviceIdentity, PinnedIdentity, verify};
use lattice_platform::{EnvelopeBytes, TransportAdapter, TransportError, TransportReceipt};
use lattice_protocol::{NegotiatedPathUpgrades, PathUpgradeCapabilities, PathUpgradeError};
use lattice_router::{DeduplicationOutcome, EventDeduplicator, EventId as RouterEventId};
use lattice_sync::{PlanError, ScopeId, ScopeSummary, plan_sync};
use lattice_transport::{receive_bounded, send_bounded};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use super::{
    HopOutcome, REQUEST_KIND, SyncEventRejection, SyncEventSource, SyncEventValidator,
    SyncExchange, SyncProtocolError, SyncReceiveOutcome, SyncRequestTarget,
    SyncServeReceiveOutcome, SyncServeResult, SyncSourceError, SyncSummarySource,
    V2_INITIATOR_SUMMARY_KIND, V2_RESPONDER_SUMMARY_KIND, ValidatedSyncEvent, WIRE_HEADER_BYTES,
    WIRE_MAGIC, WIRE_VERSION, WIRE_VERSION_V2, bounded_targets, decode_request, decode_response,
    decode_v2_request, decode_v2_response, decode_v2_summary, encode_request, encode_v2_request,
    encode_v2_response_header, encode_v2_summary, known_summary_event, normalize_ranges,
    record_matches_target, response_header, sort_dedup,
};

const DIRECT_SYNC_PROLOGUE: &[u8] = b"lattice:direct-sync:noise-xx:v1\0";
const DIRECT_SYNC_V2_PROLOGUE: &[u8] = b"lattice:direct-sync:noise-xx:v2\0";
const IDENTITY_PROOF_MAGIC: &[u8; 4] = b"LIDP";
const IDENTITY_PROOF_VERSION: u8 = 1;
const IDENTITY_PROOF_BYTES: usize = 4 + 1 + 1 + 64;
const IDENTITY_PROOF_DOMAIN: &[u8] = b"lattice:direct-sync-identity-proof:v1\0";
const IDENTITY_PROOF_V2_DOMAIN: &[u8] = b"lattice:direct-sync-identity-proof:v2\0";
const PATH_UPGRADE_PROLOGUE: &[u8] = b"lattice:path-upgrade:noise-xx:v1\0";
const PATH_UPGRADE_PROOF_DOMAIN: &[u8] = b"lattice:path-upgrade-identity-proof:v1\0";

/// Failure while establishing or using one authenticated direct-sync session.
#[derive(Debug, Error)]
pub enum AuthenticatedSyncError {
    /// The peer closed its transport before the expected frame.
    #[error("direct-sync peer closed the transport")]
    PeerClosed,
    /// Cancellation won before the current one-shot operation completed.
    #[error("direct-sync operation was cancelled")]
    Cancelled,
    /// A Noise handshake or bounded transport operation failed.
    #[error(transparent)]
    NoiseHandshake(#[from] NoiseSessionError),
    /// Noise transport encryption or authentication failed.
    #[error(transparent)]
    NoiseTransport(#[from] NoiseTransportError),
    /// The transport adapter failed or rejected a bounded frame.
    #[error("transport failed: {0:?}")]
    Transport(TransportError),
    /// A handshake payload or identity proof had an unexpected encoding.
    #[error("direct-sync identity binding failed")]
    IdentityBinding,
    /// The caller rejected the authenticated peer for the requested scope.
    #[error("caller authorization denied this peer and scope")]
    ScopeUnauthorized,
    /// Sync request or response bytes failed strict protocol parsing.
    #[error("malformed direct-sync frame: {0:?}")]
    Protocol(SyncProtocolError),
    /// The local event source failed while resolving an authenticated request.
    #[error("sync event source failed: {0}")]
    EventSource(#[from] SyncSourceError),

    /// The local and peer summaries cannot be planned together.
    #[error("sync planning failed: {0:?}")]
    Plan(PlanError),
}

/// One completed direct-sync exchange whose peer is bound to an exact caller pin.
///
/// Construction is private to the authenticated path and occurs only after
/// transcript-bound Ed25519 proof verification and caller scope authorization.
/// `authenticated_peer` is the pin used for verification, not a trust decision
/// about how that pin was obtained.
#[derive(Debug)]
pub struct AuthenticatedSyncExchange<E> {
    /// Exact identity bundle/fingerprint selected by the caller and verified
    /// against a signature over this Noise transcript.
    pub authenticated_peer: PinnedIdentity,
    /// Result of the bounded one-shot anti-entropy exchange.
    pub exchange: SyncExchange<E>,
}

/// One authenticated receive-side direct-sync result.
#[derive(Debug)]
pub struct AuthenticatedSyncServeResult {
    /// Exact identity bundle/fingerprint selected by the caller and verified
    /// against a signature over this Noise transcript.
    pub authenticated_peer: PinnedIdentity,
    /// Scope accepted by the caller's authorization callback.
    pub authorized_scope: ScopeId,
    /// Exact-hop response result; it never means destination delivery.
    pub exchange: SyncServeResult,
}

/// One authenticated v2 exchange with a summary received from the pinned peer.
#[derive(Debug)]
pub struct AuthenticatedSyncV2Exchange<E> {
    /// Exact identity bundle/fingerprint verified over the v2 Noise transcript.
    pub authenticated_peer: PinnedIdentity,
    /// Exact-hop acceptance of the initiator's scoped summary frame.
    pub summary_hop: HopOutcome,
    /// The bounded summary advertised by the responder.
    pub peer_summary: ScopeSummary,
    /// Planned exact requests and their one-batch results.
    pub exchange: SyncExchange<E>,
}

/// One authenticated v2 serving result after exchanging scoped summaries.
#[derive(Debug)]
pub struct AuthenticatedSyncV2ServeResult {
    /// Exact identity bundle/fingerprint verified over the v2 Noise transcript.
    pub authenticated_peer: PinnedIdentity,
    /// Scope accepted by the caller's authorization callback.
    pub authorized_scope: ScopeId,
    /// Exact-hop acceptance of the responder's scoped summary frame.
    pub summary_hop: HopOutcome,
    /// The bounded summary advertised by the initiator.
    pub peer_summary: ScopeSummary,
    /// Exact-hop response result; it never means destination delivery.
    pub exchange: SyncServeResult,
}

/// Failure during pinned-peer path-capability negotiation.
#[derive(Debug, Error)]
pub enum AuthenticatedPathUpgradeError {
    /// Authenticated transport setup or use failed.
    #[error(transparent)]
    Session(#[from] AuthenticatedSyncError),
    /// The caller's local policy rejected the authenticated peer.
    #[error("caller authorization denied path-capability exchange")]
    PeerUnauthorized,
    /// The peer's bounded versioned offer was malformed or unsupported.
    #[error(transparent)]
    Capability(#[from] PathUpgradeError),
}

/// Supported direct-path frame limits shared by one authenticated peer pair.
#[derive(Debug)]
pub struct AuthenticatedPathUpgradeNegotiation {
    /// Exact identity pin used to verify the remote transcript proof.
    pub authenticated_peer: PinnedIdentity,
    /// Capability intersection. A limit is not evidence of current reachability.
    pub negotiated: NegotiatedPathUpgrades,
}

/// Exchanges bounded path capability offers over an authenticated pinned-peer
/// session. `role` must be initiator on one side and responder on the other.
/// The caller's peer policy runs after identity proof and before any offer.
///
/// This function does not discover or open a path. Use live reachability,
/// consent, routing class, and health before switching traffic from the
/// currently authenticated adapter.
///
/// # Errors
///
/// Returns an error for transport/Noise/authentication failure, local peer
/// policy rejection, or an invalid/unsupported capability offer.
pub async fn negotiate_authenticated_path_upgrades_once<A, Z>(
    adapter: &A,
    local_identity: &DeviceIdentity,
    pinned_peer: PinnedIdentity,
    role: NoiseRole,
    local_capabilities: PathUpgradeCapabilities,
    mut authorize_peer: Z,
    cancellation: &CancellationToken,
) -> Result<AuthenticatedPathUpgradeNegotiation, AuthenticatedPathUpgradeError>
where
    A: TransportAdapter + ?Sized,
    Z: FnMut(&PinnedIdentity) -> bool,
{
    let mut channel = establish_authenticated_channel_with_protocol(
        adapter,
        local_identity,
        pinned_peer,
        role,
        cancellation,
        PATH_UPGRADE_PROLOGUE,
        PATH_UPGRADE_PROOF_DOMAIN,
    )
    .await?;
    if !authorize_peer(&pinned_peer) {
        return Err(AuthenticatedPathUpgradeError::PeerUnauthorized);
    }
    let local_offer = local_capabilities.encode()?;
    let peer_offer = match role {
        NoiseRole::Initiator => {
            send_encrypted(adapter, &mut channel, &local_offer, cancellation).await?;
            receive_decrypted(adapter, &mut channel, cancellation).await?
        }
        NoiseRole::Responder => {
            let peer_offer = receive_decrypted(adapter, &mut channel, cancellation).await?;
            send_encrypted(adapter, &mut channel, &local_offer, cancellation).await?;
            peer_offer
        }
    };
    let peer_capabilities = PathUpgradeCapabilities::decode(&peer_offer)?;
    Ok(AuthenticatedPathUpgradeNegotiation {
        authenticated_peer: pinned_peer,
        negotiated: local_capabilities.negotiate(peer_capabilities),
    })
}

/// Plans and executes one encrypted, authenticated, scope-authorized sync request.
///
/// Noise XX uses a fresh per-session transport key. Both peers then sign the
/// final Noise handshake hash together with the initiator/responder role and the
/// exact pair of public identity bundles. The remote signature is verified
/// against `pinned_peer`; the Noise-generated static key is never treated as a
/// Lattice identity. The caller's authorization callback runs only after that
/// verification and before planning or sending scope data.
///
/// At most one request and one reply are sent. Each encrypted frame is limited
/// to one Noise transport message; event bytes remain opaque and must pass the
/// supplied validator before appearing in `exchange.events`. Receipts are exact
/// hop only. The transport and identity remain caller-owned. Serialize calls on
/// each adapter and discard it after any failed session, which may leave a
/// partial Noise exchange on the stream.
///
/// The `pinned_peer` must be loaded from a durable, previously verified pin by
/// the caller. This method neither persists sync history nor provides MLS
/// membership or application-event authorization.
///
/// # Errors
///
/// Returns an error for cancellation, transport or Noise failure, a failed
/// identity proof, a scope denied by the callback, invalid sync frames, or a
/// malformed/conflicting summary.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // Keeps the authenticated exchange's gates and outcomes together.
pub async fn execute_authenticated_sync_once<A, V, Z>(
    adapter: &A,
    local_identity: &DeviceIdentity,
    pinned_peer: PinnedIdentity,
    local: &ScopeSummary,
    peer: &ScopeSummary,
    deduplicator: &mut EventDeduplicator,
    validator: &mut V,
    mut authorize_scope: Z,
    cancellation: &CancellationToken,
) -> Result<AuthenticatedSyncExchange<V::Error>, AuthenticatedSyncError>
where
    A: TransportAdapter + ?Sized,
    V: SyncEventValidator,
    Z: FnMut(&PinnedIdentity, ScopeId) -> bool,
{
    let mut channel = establish_authenticated_channel(
        adapter,
        local_identity,
        pinned_peer,
        NoiseRole::Initiator,
        cancellation,
    )
    .await?;

    if !authorize_scope(&pinned_peer, local.scope) {
        return Err(AuthenticatedSyncError::ScopeUnauthorized);
    }
    let plan = plan_sync(local, peer).map_err(AuthenticatedSyncError::Plan)?;
    let max_plaintext = max_plaintext_frame(adapter);
    let (requested, mut unresolved_dependencies, mut unresolved_ranges) =
        bounded_targets(&plan, max_plaintext);
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

    let request = encode_request(local.scope, &requested);
    let request_hop = send_encrypted(adapter, &mut channel, &request, cancellation).await?;
    exchange.request_hop = HopOutcome::Accepted(request_hop);
    let response = receive_decrypted(adapter, &mut channel, cancellation).await?;
    let expected = requested
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    let records = decode_response(&response, local.scope, &expected)
        .map_err(AuthenticatedSyncError::Protocol)?;
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
        if expected_id.is_some_and(|expected_id| expected_id != validated_id) {
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
        super::add_unresolved_target(target, &mut unresolved_dependencies, &mut unresolved_ranges);
    }
    exchange.unresolved_dependencies = sort_dedup(unresolved_dependencies);
    exchange.unresolved_ranges = normalize_ranges(unresolved_ranges);
    Ok(AuthenticatedSyncExchange {
        authenticated_peer: pinned_peer,
        exchange,
    })
}

/// Exchanges bounded v2 summaries, plans exact repairs, and validates one batch.
///
/// The v2 Noise prologue/proof domain and application frame version are distinct
/// from v1. Scope authorization precedes sending the caller's summary.
///
/// # Errors
///
/// Returns an error for cancellation, failed Noise or pinned-identity
/// authentication, denied scope, malformed/oversize summaries or frames, or
/// invalid/conflicting summaries.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn execute_authenticated_sync_v2_once<A, V, Z>(
    adapter: &A,
    local_identity: &DeviceIdentity,
    pinned_peer: PinnedIdentity,
    local: &ScopeSummary,
    deduplicator: &mut EventDeduplicator,
    validator: &mut V,
    mut authorize_scope: Z,
    cancellation: &CancellationToken,
) -> Result<AuthenticatedSyncV2Exchange<V::Error>, AuthenticatedSyncError>
where
    A: TransportAdapter + ?Sized,
    V: SyncEventValidator,
    Z: FnMut(&PinnedIdentity, ScopeId) -> bool,
{
    let mut channel = establish_authenticated_channel_v2(
        adapter,
        local_identity,
        pinned_peer,
        NoiseRole::Initiator,
        cancellation,
    )
    .await?;
    if !authorize_scope(&pinned_peer, local.scope) {
        return Err(AuthenticatedSyncError::ScopeUnauthorized);
    }
    plan_sync(local, local).map_err(AuthenticatedSyncError::Plan)?;

    let max_plaintext = max_v2_plaintext_frame(adapter);
    let local_summary = encode_v2_summary(local, V2_INITIATOR_SUMMARY_KIND, max_plaintext)
        .map_err(AuthenticatedSyncError::Protocol)?;
    let summary_hop = send_encrypted(adapter, &mut channel, &local_summary, cancellation).await?;
    let peer_summary_bytes = receive_decrypted(adapter, &mut channel, cancellation).await?;
    let peer_summary =
        decode_v2_summary(&peer_summary_bytes, local.scope, V2_RESPONDER_SUMMARY_KIND)
            .map_err(AuthenticatedSyncError::Protocol)?;
    let plan = plan_sync(local, &peer_summary).map_err(AuthenticatedSyncError::Plan)?;
    let (requested, mut unresolved_dependencies, mut unresolved_ranges) =
        bounded_targets(&plan, max_plaintext);
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
    let request =
        encode_v2_request(local.scope, &requested).map_err(AuthenticatedSyncError::Protocol)?;
    let request_hop = send_encrypted(adapter, &mut channel, &request, cancellation).await?;
    exchange.request_hop = HopOutcome::Accepted(request_hop);
    let response = receive_decrypted(adapter, &mut channel, cancellation).await?;
    let expected = requested
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    let records = decode_v2_response(&response, local.scope, &expected)
        .map_err(AuthenticatedSyncError::Protocol)?;
    exchange.response = SyncReceiveOutcome::Received;

    let mut pending = expected;
    for record in records {
        let expected_id = match record.target {
            SyncRequestTarget::EventId(event_id) => Some(event_id),
            SyncRequestTarget::Sequence { author, sequence } => {
                known_summary_event(&peer_summary, author, sequence)
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
        if expected_id.is_some_and(|expected_id| expected_id != validated_id) {
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
        super::add_unresolved_target(target, &mut unresolved_dependencies, &mut unresolved_ranges);
    }
    exchange.unresolved_dependencies = sort_dedup(unresolved_dependencies);
    exchange.unresolved_ranges = normalize_ranges(unresolved_ranges);
    Ok(AuthenticatedSyncV2Exchange {
        authenticated_peer: pinned_peer,
        summary_hop: HopOutcome::Accepted(summary_hop),
        peer_summary,
        exchange,
    })
}

/// Receives one encrypted sync request from an authenticated, pinned peer.
///
/// The peer is transcript-bound to `pinned_peer` before any application frame is
/// considered. The first decrypted request's scope is parsed only to call
/// `authorize_scope`; `source.load` is never called unless that callback allows
/// the exact peer/scope pair. Malformed, replayed, or unauthorized frames fail
/// without a successful result or event-source access.
///
/// At most one response is sent. Its transport receipt means exact-hop
/// acceptance only. This method does not persist sync history or confer MLS or
/// event-level authorization.
/// Serialize calls on each adapter and discard it after any failed session.
///
/// # Errors
///
/// Returns an error for cancellation, transport or Noise failure, a failed
/// identity proof, unauthorized scope, or malformed sync bytes.
#[allow(clippy::too_many_lines)] // Keeps scoped request handling auditable.
pub async fn serve_authenticated_sync_request_once<A, S, Z>(
    adapter: &A,
    local_identity: &DeviceIdentity,
    pinned_peer: PinnedIdentity,
    source: &mut S,
    mut authorize_scope: Z,
    cancellation: &CancellationToken,
) -> Result<AuthenticatedSyncServeResult, AuthenticatedSyncError>
where
    A: TransportAdapter + ?Sized,
    S: SyncEventSource + ?Sized,
    Z: FnMut(&PinnedIdentity, ScopeId) -> bool,
{
    let mut channel = establish_authenticated_channel(
        adapter,
        local_identity,
        pinned_peer,
        NoiseRole::Responder,
        cancellation,
    )
    .await?;
    let request = receive_decrypted(adapter, &mut channel, cancellation).await?;
    let requested_scope = request_scope(&request).map_err(AuthenticatedSyncError::Protocol)?;
    if !authorize_scope(&pinned_peer, requested_scope) {
        return Err(AuthenticatedSyncError::ScopeUnauthorized);
    }
    let targets =
        decode_request(&request, requested_scope).map_err(AuthenticatedSyncError::Protocol)?;

    let max_plaintext = max_plaintext_frame(adapter);
    let mut response = response_header(requested_scope);
    let mut omitted_targets = Vec::with_capacity(targets.len());
    let mut included_events = 0_usize;
    for target in targets {
        let Some(record) = source
            .load(requested_scope, target)
            .map_err(AuthenticatedSyncError::EventSource)?
        else {
            omitted_targets.push(target);
            continue;
        };
        if record.sequence == 0
            || record.bytes.is_empty()
            || record.bytes.len() > lattice_platform::MAX_EVENT_BYTES
            || !record_matches_target(target, &record)
        {
            omitted_targets.push(target);
            continue;
        }
        let Some(record_size) = super::target_wire_size(target)
            .checked_add(32 + 8 + 32 + 4)
            .and_then(|size| size.checked_add(record.bytes.len()))
        else {
            omitted_targets.push(target);
            continue;
        };
        if response
            .len()
            .checked_add(record_size)
            .is_none_or(|size| size > max_plaintext)
        {
            omitted_targets.push(target);
            continue;
        }
        super::encode_target(&mut response, target);
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
    let count = u16::try_from(included_events)
        .map_err(|_| AuthenticatedSyncError::Protocol(SyncProtocolError::InvalidCount))?;
    response[38..40].copy_from_slice(&count.to_be_bytes());
    let response_hop = send_encrypted(adapter, &mut channel, &response, cancellation).await?;

    Ok(AuthenticatedSyncServeResult {
        authenticated_peer: pinned_peer,
        authorized_scope: requested_scope,
        exchange: SyncServeResult {
            receive: SyncServeReceiveOutcome::Received,
            response_hop: HopOutcome::Accepted(response_hop),
            included_events,
            omitted_targets,
        },
    })
}

/// Serves one v2 summary exchange and one bounded event-request batch.
///
/// The request header is inspected only to identify the requested scope. The
/// callback runs before the remote summary is decoded or either caller-owned
/// summary/event source is accessed. After exchanging validated summaries, the
/// responder serves only targets present in their bounded sync plan.
///
/// # Errors
///
/// Returns an error for cancellation, failed Noise or pinned-identity
/// authentication, denied scope, invalid summaries/frames, or source failure.
#[allow(clippy::too_many_lines)]
pub async fn serve_authenticated_sync_v2_once<A, S, M, Z>(
    adapter: &A,
    local_identity: &DeviceIdentity,
    pinned_peer: PinnedIdentity,
    summary_source: &mut M,
    event_source: &mut S,
    mut authorize_scope: Z,
    cancellation: &CancellationToken,
) -> Result<AuthenticatedSyncV2ServeResult, AuthenticatedSyncError>
where
    A: TransportAdapter + ?Sized,
    S: SyncEventSource + ?Sized,
    M: SyncSummarySource + ?Sized,
    Z: FnMut(&PinnedIdentity, ScopeId) -> bool,
{
    let mut channel = establish_authenticated_channel_v2(
        adapter,
        local_identity,
        pinned_peer,
        NoiseRole::Responder,
        cancellation,
    )
    .await?;
    let initiator_summary_bytes = receive_decrypted(adapter, &mut channel, cancellation).await?;
    let requested_scope =
        request_scope_v2(&initiator_summary_bytes).map_err(AuthenticatedSyncError::Protocol)?;
    if !authorize_scope(&pinned_peer, requested_scope) {
        return Err(AuthenticatedSyncError::ScopeUnauthorized);
    }
    let peer_summary = decode_v2_summary(
        &initiator_summary_bytes,
        requested_scope,
        V2_INITIATOR_SUMMARY_KIND,
    )
    .map_err(AuthenticatedSyncError::Protocol)?;
    plan_sync(&peer_summary, &peer_summary).map_err(AuthenticatedSyncError::Plan)?;
    let local_summary = summary_source
        .load_summary(requested_scope)
        .map_err(AuthenticatedSyncError::EventSource)?;
    let plan = plan_sync(&peer_summary, &local_summary).map_err(AuthenticatedSyncError::Plan)?;
    let max_plaintext = max_v2_plaintext_frame(adapter);
    let summary_response =
        encode_v2_summary(&local_summary, V2_RESPONDER_SUMMARY_KIND, max_plaintext)
            .map_err(AuthenticatedSyncError::Protocol)?;
    let summary_hop =
        send_encrypted(adapter, &mut channel, &summary_response, cancellation).await?;

    let request = receive_decrypted(adapter, &mut channel, cancellation).await?;
    let targets =
        decode_v2_request(&request, requested_scope).map_err(AuthenticatedSyncError::Protocol)?;
    if !super::request_targets_are_planned(&plan, &targets) {
        return Err(AuthenticatedSyncError::Protocol(
            SyncProtocolError::UnrequestedTarget,
        ));
    }
    let mut response =
        encode_v2_response_header(requested_scope).map_err(AuthenticatedSyncError::Protocol)?;
    let mut omitted_targets = Vec::with_capacity(targets.len());
    let mut included_events = 0_usize;
    for target in targets {
        let Some(record) = event_source
            .load(requested_scope, target)
            .map_err(AuthenticatedSyncError::EventSource)?
        else {
            omitted_targets.push(target);
            continue;
        };
        if record.sequence == 0
            || record.bytes.is_empty()
            || record.bytes.len() > lattice_platform::MAX_EVENT_BYTES
            || !record_matches_target(target, &record)
        {
            omitted_targets.push(target);
            continue;
        }
        let Some(record_size) = super::target_wire_size(target)
            .checked_add(32 + 8 + 32 + 4)
            .and_then(|size| size.checked_add(record.bytes.len()))
        else {
            omitted_targets.push(target);
            continue;
        };
        if response
            .len()
            .checked_add(record_size)
            .is_none_or(|size| size > max_plaintext)
        {
            omitted_targets.push(target);
            continue;
        }
        super::encode_target(&mut response, target);
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
    let count = u16::try_from(included_events)
        .map_err(|_| AuthenticatedSyncError::Protocol(SyncProtocolError::InvalidCount))?;
    response[38..40].copy_from_slice(&count.to_be_bytes());
    let response_hop = send_encrypted(adapter, &mut channel, &response, cancellation).await?;

    Ok(AuthenticatedSyncV2ServeResult {
        authenticated_peer: pinned_peer,
        authorized_scope: requested_scope,
        summary_hop: HopOutcome::Accepted(summary_hop),
        peer_summary,
        exchange: SyncServeResult {
            receive: SyncServeReceiveOutcome::Received,
            response_hop: HopOutcome::Accepted(response_hop),
            included_events,
            omitted_targets,
        },
    })
}

async fn establish_authenticated_channel<A: TransportAdapter + ?Sized>(
    adapter: &A,
    local_identity: &DeviceIdentity,
    pinned_peer: PinnedIdentity,
    role: NoiseRole,
    cancellation: &CancellationToken,
) -> Result<EstablishedNoiseTransportSession, AuthenticatedSyncError> {
    establish_authenticated_channel_with_protocol(
        adapter,
        local_identity,
        pinned_peer,
        role,
        cancellation,
        DIRECT_SYNC_PROLOGUE,
        IDENTITY_PROOF_DOMAIN,
    )
    .await
}

async fn establish_authenticated_channel_v2<A: TransportAdapter + ?Sized>(
    adapter: &A,
    local_identity: &DeviceIdentity,
    pinned_peer: PinnedIdentity,
    role: NoiseRole,
    cancellation: &CancellationToken,
) -> Result<EstablishedNoiseTransportSession, AuthenticatedSyncError> {
    establish_authenticated_channel_with_protocol(
        adapter,
        local_identity,
        pinned_peer,
        role,
        cancellation,
        DIRECT_SYNC_V2_PROLOGUE,
        IDENTITY_PROOF_V2_DOMAIN,
    )
    .await
}

async fn establish_authenticated_channel_with_protocol<A: TransportAdapter + ?Sized>(
    adapter: &A,
    local_identity: &DeviceIdentity,
    pinned_peer: PinnedIdentity,
    role: NoiseRole,
    cancellation: &CancellationToken,
    prologue: &[u8],
    proof_domain: &[u8],
) -> Result<EstablishedNoiseTransportSession, AuthenticatedSyncError> {
    let mut handshake = NoiseSession::new(role, prologue)?;
    match role {
        NoiseRole::Initiator => {
            let message1 = handshake.write_message(&[])?;
            send_plain(adapter, message1, cancellation).await?;
            let message2 = receive_plain(adapter, cancellation).await?;
            if !handshake.read_message(message2.as_bytes())?.is_empty() {
                return Err(AuthenticatedSyncError::IdentityBinding);
            }
            let message3 = handshake.write_message(&[])?;
            send_plain(adapter, message3, cancellation).await?;
        }
        NoiseRole::Responder => {
            let message1 = receive_plain(adapter, cancellation).await?;
            if !handshake.read_message(message1.as_bytes())?.is_empty() {
                return Err(AuthenticatedSyncError::IdentityBinding);
            }
            let message2 = handshake.write_message(&[])?;
            send_plain(adapter, message2, cancellation).await?;
            let message3 = receive_plain(adapter, cancellation).await?;
            if !handshake.read_message(message3.as_bytes())?.is_empty() {
                return Err(AuthenticatedSyncError::IdentityBinding);
            }
        }
    }

    let mut channel = handshake.finish_transport()?;
    let local_bundle = local_identity.public_bundle().to_bytes();
    let peer_bundle = pinned_peer.bundle().to_bytes();
    match role {
        NoiseRole::Initiator => {
            let proof = identity_proof(
                local_identity,
                role,
                &channel,
                &local_bundle,
                &peer_bundle,
                proof_domain,
            );
            send_encrypted(adapter, &mut channel, &proof, cancellation).await?;
            let peer_proof = receive_decrypted(adapter, &mut channel, cancellation).await?;
            verify_identity_proof(
                &peer_proof,
                NoiseRole::Responder,
                &channel,
                &local_bundle,
                &peer_bundle,
                pinned_peer,
                proof_domain,
            )?;
        }
        NoiseRole::Responder => {
            let peer_proof = receive_decrypted(adapter, &mut channel, cancellation).await?;
            verify_identity_proof(
                &peer_proof,
                NoiseRole::Initiator,
                &channel,
                &peer_bundle,
                &local_bundle,
                pinned_peer,
                proof_domain,
            )?;
            let proof = identity_proof(
                local_identity,
                role,
                &channel,
                &local_bundle,
                &peer_bundle,
                proof_domain,
            );
            send_encrypted(adapter, &mut channel, &proof, cancellation).await?;
        }
    }
    Ok(channel)
}

fn identity_proof(
    identity: &DeviceIdentity,
    role: NoiseRole,
    channel: &EstablishedNoiseTransportSession,
    local_bundle: &[u8; 65],
    peer_bundle: &[u8; 65],
    proof_domain: &[u8],
) -> [u8; IDENTITY_PROOF_BYTES] {
    let (initiator_bundle, responder_bundle) = match role {
        NoiseRole::Initiator => (local_bundle, peer_bundle),
        NoiseRole::Responder => (peer_bundle, local_bundle),
    };
    let context = identity_proof_context(
        proof_domain,
        channel.session_hash(),
        role,
        initiator_bundle,
        responder_bundle,
    );
    let signature = identity.sign(&context);
    let mut proof = [0_u8; IDENTITY_PROOF_BYTES];
    proof[..4].copy_from_slice(IDENTITY_PROOF_MAGIC);
    proof[4] = IDENTITY_PROOF_VERSION;
    proof[5] = role_byte(role);
    proof[6..].copy_from_slice(&signature);
    proof
}

fn verify_identity_proof(
    proof: &[u8],
    expected_role: NoiseRole,
    channel: &EstablishedNoiseTransportSession,
    initiator_bundle: &[u8; 65],
    responder_bundle: &[u8; 65],
    pinned_peer: PinnedIdentity,
    proof_domain: &[u8],
) -> Result<(), AuthenticatedSyncError> {
    if proof.len() != IDENTITY_PROOF_BYTES
        || &proof[..4] != IDENTITY_PROOF_MAGIC
        || proof[4] != IDENTITY_PROOF_VERSION
        || proof[5] != role_byte(expected_role)
    {
        return Err(AuthenticatedSyncError::IdentityBinding);
    }
    let context = identity_proof_context(
        proof_domain,
        channel.session_hash(),
        expected_role,
        initiator_bundle,
        responder_bundle,
    );
    verify(
        &pinned_peer.bundle().ed25519_public_key(),
        &context,
        &proof[6..],
    )
    .map_err(|_| AuthenticatedSyncError::IdentityBinding)
}

fn identity_proof_context(
    proof_domain: &[u8],
    session_hash: &[u8; 32],
    role: NoiseRole,
    initiator_bundle: &[u8; 65],
    responder_bundle: &[u8; 65],
) -> Vec<u8> {
    let mut context = Vec::with_capacity(proof_domain.len() + 1 + 32 + 130);
    context.extend_from_slice(proof_domain);
    context.push(role_byte(role));
    context.extend_from_slice(session_hash);
    context.extend_from_slice(initiator_bundle);
    context.extend_from_slice(responder_bundle);
    context
}

const fn role_byte(role: NoiseRole) -> u8 {
    match role {
        NoiseRole::Initiator => 1,
        NoiseRole::Responder => 2,
    }
}

async fn send_plain<A: TransportAdapter + ?Sized>(
    adapter: &A,
    message: Vec<u8>,
    cancellation: &CancellationToken,
) -> Result<TransportReceipt, AuthenticatedSyncError> {
    let envelope = EnvelopeBytes::try_from(message)
        .map_err(|_| AuthenticatedSyncError::Transport(TransportError::EnvelopeTooLarge))?;
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(AuthenticatedSyncError::Cancelled),
        result = send_bounded(adapter, envelope) => result.map_err(AuthenticatedSyncError::Transport),
    }
}

async fn receive_plain<A: TransportAdapter + ?Sized>(
    adapter: &A,
    cancellation: &CancellationToken,
) -> Result<EnvelopeBytes, AuthenticatedSyncError> {
    let incoming = tokio::select! {
        biased;
        () = cancellation.cancelled() => return Err(AuthenticatedSyncError::Cancelled),
        result = receive_bounded(adapter) => result.map_err(AuthenticatedSyncError::Transport)?,
    };
    incoming.ok_or(AuthenticatedSyncError::PeerClosed)
}

async fn send_encrypted<A: TransportAdapter + ?Sized>(
    adapter: &A,
    channel: &mut EstablishedNoiseTransportSession,
    plaintext: &[u8],
    cancellation: &CancellationToken,
) -> Result<TransportReceipt, AuthenticatedSyncError> {
    let ciphertext = channel.encrypt(plaintext)?;
    let envelope = EnvelopeBytes::try_from(ciphertext)
        .map_err(|_| AuthenticatedSyncError::Transport(TransportError::EnvelopeTooLarge))?;
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(AuthenticatedSyncError::Cancelled),
        result = send_bounded(adapter, envelope) => result.map_err(AuthenticatedSyncError::Transport),
    }
}

async fn receive_decrypted<A: TransportAdapter + ?Sized>(
    adapter: &A,
    channel: &mut EstablishedNoiseTransportSession,
    cancellation: &CancellationToken,
) -> Result<Vec<u8>, AuthenticatedSyncError> {
    let ciphertext = receive_plain(adapter, cancellation).await?;
    channel
        .decrypt(ciphertext.as_bytes())
        .map_err(AuthenticatedSyncError::NoiseTransport)
}

fn max_plaintext_frame<A: TransportAdapter + ?Sized>(adapter: &A) -> usize {
    adapter
        .capabilities()
        .max_envelope_bytes()
        .min(MAX_NOISE_TRANSPORT_MESSAGE_SIZE)
}

fn max_v2_plaintext_frame<A: TransportAdapter + ?Sized>(adapter: &A) -> usize {
    adapter
        .capabilities()
        .max_envelope_bytes()
        .saturating_sub(16)
        .min(MAX_NOISE_TRANSPORT_MESSAGE_SIZE)
}

fn request_scope(bytes: &[u8]) -> Result<ScopeId, SyncProtocolError> {
    if bytes.len() < WIRE_HEADER_BYTES {
        return Err(SyncProtocolError::Truncated);
    }
    let mut reader = super::Reader::new(bytes);
    if reader.take(4)? != &WIRE_MAGIC[..] {
        return Err(SyncProtocolError::InvalidMagic);
    }
    if reader.u8()? != WIRE_VERSION {
        return Err(SyncProtocolError::UnsupportedVersion);
    }
    if reader.u8()? != REQUEST_KIND {
        return Err(SyncProtocolError::UnexpectedMessage);
    }
    Ok(ScopeId::new(reader.array32()?))
}

fn request_scope_v2(bytes: &[u8]) -> Result<ScopeId, SyncProtocolError> {
    if bytes.len() < WIRE_HEADER_BYTES {
        return Err(SyncProtocolError::Truncated);
    }
    let mut reader = super::Reader::new(bytes);
    if reader.take(4)? != &WIRE_MAGIC[..] {
        return Err(SyncProtocolError::InvalidMagic);
    }
    if reader.u8()? != WIRE_VERSION_V2 {
        return Err(SyncProtocolError::UnsupportedVersion);
    }
    if reader.u8()? != V2_INITIATOR_SUMMARY_KIND {
        return Err(SyncProtocolError::UnexpectedMessage);
    }
    Ok(ScopeId::new(reader.array32()?))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use lattice_crypto::NoiseRole;
    use lattice_identity::{DeviceIdentity, PinnedIdentity};
    use lattice_sync::{EventId, ScopeId, ScopeSummary};
    use lattice_transport::{TcpPeerAdapter, TcpPeerListener};
    use tokio_util::sync::CancellationToken;

    use super::{
        AuthenticatedSyncError, SyncRequestTarget, SyncSourceError,
        establish_authenticated_channel_v2, max_v2_plaintext_frame, receive_decrypted,
        send_encrypted, serve_authenticated_sync_v2_once,
    };
    use crate::sync::{SyncEventRecord, SyncProtocolError};

    #[tokio::test]
    async fn responder_rejects_unplanned_v2_target_before_event_source_access() {
        let scope = ScopeId::new([0x61; 32]);
        let alice = DeviceIdentity::generate().expect("generate initiator identity");
        let bob = DeviceIdentity::generate().expect("generate responder identity");
        let alice_pin =
            PinnedIdentity::from_verified_fingerprint(alice.public_bundle(), alice.fingerprint())
                .expect("pin initiator identity");
        let bob_pin =
            PinnedIdentity::from_verified_fingerprint(bob.public_bundle(), bob.fingerprint())
                .expect("pin responder identity");
        let listener = TcpPeerListener::bind("127.0.0.1:0", 4096)
            .await
            .expect("bind test listener");
        let endpoint = listener.local_addr().expect("read listener address");
        let (client_adapter, server_result) =
            tokio::join!(TcpPeerAdapter::connect(endpoint, 4096), listener.accept());
        let client_adapter = client_adapter.expect("connect test initiator");
        let (server_adapter, _) = server_result.expect("accept test responder");

        let summary_calls = Cell::new(0);
        let mut summary_source = |requested_scope| {
            summary_calls.set(summary_calls.get() + 1);
            if requested_scope == scope {
                Ok(ScopeSummary::new(scope))
            } else {
                Err(SyncSourceError::new("unexpected scope"))
            }
        };
        let event_calls = Cell::new(0);
        let mut event_source = |_: ScopeId, _: SyncRequestTarget| {
            event_calls.set(event_calls.get() + 1);
            Ok::<_, SyncSourceError>(None::<SyncEventRecord>)
        };
        let server_cancellation = CancellationToken::new();
        let server_future = serve_authenticated_sync_v2_once(
            &server_adapter,
            &bob,
            alice_pin,
            &mut summary_source,
            &mut event_source,
            |peer, requested_scope| {
                peer.fingerprint() == alice.fingerprint() && requested_scope == scope
            },
            &server_cancellation,
        );
        let client_cancellation = CancellationToken::new();
        let client_future = async {
            let mut channel = establish_authenticated_channel_v2(
                &client_adapter,
                &alice,
                bob_pin,
                NoiseRole::Initiator,
                &client_cancellation,
            )
            .await?;
            let summary = ScopeSummary::new(scope);
            let summary_frame = crate::sync::encode_v2_summary(
                &summary,
                crate::sync::V2_INITIATOR_SUMMARY_KIND,
                max_v2_plaintext_frame(&client_adapter),
            )
            .expect("encode valid summary");
            send_encrypted(
                &client_adapter,
                &mut channel,
                &summary_frame,
                &client_cancellation,
            )
            .await?;
            let _ = receive_decrypted(&client_adapter, &mut channel, &client_cancellation).await?;
            let request = crate::sync::encode_v2_request(
                scope,
                &[SyncRequestTarget::EventId(EventId::new([0x62; 32]))],
            )
            .expect("encode bounded request");
            send_encrypted(
                &client_adapter,
                &mut channel,
                &request,
                &client_cancellation,
            )
            .await?;
            Ok::<_, AuthenticatedSyncError>(())
        };
        let (server, client) = tokio::join!(server_future, client_future);

        assert!(matches!(
            server,
            Err(AuthenticatedSyncError::Protocol(
                SyncProtocolError::UnrequestedTarget
            ))
        ));
        client.expect("send authenticated but unplanned request");
        assert_eq!(summary_calls.get(), 1);
        assert_eq!(event_calls.get(), 0);
    }
}
