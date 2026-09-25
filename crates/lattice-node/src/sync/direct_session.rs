use lattice_crypto::{
    EstablishedNoiseTransportSession, MAX_NOISE_TRANSPORT_MESSAGE_SIZE, NoiseRole, NoiseSession,
    NoiseSessionError, NoiseTransportError,
};
use lattice_identity::{DeviceIdentity, PinnedIdentity, verify};
use lattice_platform::{EnvelopeBytes, TransportAdapter, TransportError, TransportReceipt};
use lattice_router::{DeduplicationOutcome, EventDeduplicator, EventId as RouterEventId};
use lattice_sync::{PlanError, ScopeId, ScopeSummary, plan_sync};
use lattice_transport::{receive_bounded, send_bounded};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use super::{
    HopOutcome, REQUEST_KIND, SyncEventRejection, SyncEventSource, SyncEventValidator,
    SyncExchange, SyncProtocolError, SyncReceiveOutcome, SyncRequestTarget,
    SyncServeReceiveOutcome, SyncServeResult, SyncSourceError, ValidatedSyncEvent,
    WIRE_HEADER_BYTES, WIRE_MAGIC, WIRE_VERSION, bounded_targets, decode_request, decode_response,
    encode_request, known_summary_event, normalize_ranges, record_matches_target, response_header,
    sort_dedup,
};

const DIRECT_SYNC_PROLOGUE: &[u8] = b"lattice:direct-sync:noise-xx:v1\0";
const IDENTITY_PROOF_MAGIC: &[u8; 4] = b"LIDP";
const IDENTITY_PROOF_VERSION: u8 = 1;
const IDENTITY_PROOF_BYTES: usize = 4 + 1 + 1 + 64;
const IDENTITY_PROOF_DOMAIN: &[u8] = b"lattice:direct-sync-identity-proof:v1\0";

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

async fn establish_authenticated_channel<A: TransportAdapter + ?Sized>(
    adapter: &A,
    local_identity: &DeviceIdentity,
    pinned_peer: PinnedIdentity,
    role: NoiseRole,
    cancellation: &CancellationToken,
) -> Result<EstablishedNoiseTransportSession, AuthenticatedSyncError> {
    let mut handshake = NoiseSession::new(role, DIRECT_SYNC_PROLOGUE)?;
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
            let proof = identity_proof(local_identity, role, &channel, &local_bundle, &peer_bundle);
            send_encrypted(adapter, &mut channel, &proof, cancellation).await?;
            let peer_proof = receive_decrypted(adapter, &mut channel, cancellation).await?;
            verify_identity_proof(
                &peer_proof,
                NoiseRole::Responder,
                &channel,
                &local_bundle,
                &peer_bundle,
                pinned_peer,
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
            )?;
            let proof = identity_proof(local_identity, role, &channel, &local_bundle, &peer_bundle);
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
) -> [u8; IDENTITY_PROOF_BYTES] {
    let (initiator_bundle, responder_bundle) = match role {
        NoiseRole::Initiator => (local_bundle, peer_bundle),
        NoiseRole::Responder => (peer_bundle, local_bundle),
    };
    let context = identity_proof_context(
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
) -> Result<(), AuthenticatedSyncError> {
    if proof.len() != IDENTITY_PROOF_BYTES
        || &proof[..4] != IDENTITY_PROOF_MAGIC
        || proof[4] != IDENTITY_PROOF_VERSION
        || proof[5] != role_byte(expected_role)
    {
        return Err(AuthenticatedSyncError::IdentityBinding);
    }
    let context = identity_proof_context(
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
    session_hash: &[u8; 32],
    role: NoiseRole,
    initiator_bundle: &[u8; 65],
    responder_bundle: &[u8; 65],
) -> Vec<u8> {
    let mut context = Vec::with_capacity(IDENTITY_PROOF_DOMAIN.len() + 1 + 32 + 130);
    context.extend_from_slice(IDENTITY_PROOF_DOMAIN);
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
