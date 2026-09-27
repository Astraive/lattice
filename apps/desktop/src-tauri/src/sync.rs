use std::{net::SocketAddr, path::Path, time::Duration};

use lattice_core::{Client, CreatedSpace, SyncedApplicationOutcome};
use lattice_events::{EventKind, VerifiedSignatureOnlyEvent};
use lattice_node::sync::{
    StoreSyncEventSource, StoreSyncSummarySource, SyncSummarySource, ValidatedSyncEvent,
    execute_authenticated_sync_v2_once, serve_authenticated_sync_v2_once,
    space_generation_scope_id,
};
use lattice_platform::{MAX_ENVELOPE_BYTES, OsKeyringProtector};
use lattice_router::EventDeduplicator;
use lattice_storage::Store;
use lattice_sync::{EventId, ScopeId};
use lattice_transport::{TcpPeerAdapter, TcpPeerListener};
use serde::Serialize;
use tokio_util::sync::CancellationToken;

use crate::{encoding, profile};

const SYNC_STAGE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
struct SyncTarget {
    connect: SocketAddr,
    space_id: [u8; 16],
    group_reference: [u8; 32],
    peer_fingerprint: [u8; 32],
    scope: ScopeId,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DesktopSyncResult {
    state: &'static str,
    listen_address: String,
    peer_fingerprint: String,
    accepted_events: usize,
    pending_events: usize,
    duplicate_events: usize,
    offered_events: usize,
    network_contacted: bool,
    converged: bool,
}

#[tauri::command]
pub(crate) async fn sync_local_space_once(
    connect_address: String,
    listen_address: String,
    space_id_hex: String,
    group_reference_hex: String,
    peer_fingerprint_hex: String,
) -> Result<DesktopSyncResult, String> {
    let connect = connect_address
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid peer address: {error}"))?;
    let listen = listen_address
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid listen address: {error}"))?;
    let space_id = encoding::parse_fixed_hex::<16>(&space_id_hex, "Space ID")?;
    let group_reference = encoding::parse_fixed_hex::<32>(&group_reference_hex, "group reference")?;
    let peer_fingerprint =
        encoding::parse_fixed_hex::<32>(&peer_fingerprint_hex, "peer fingerprint")?;
    let (database_path, protector) = profile::open_profile()?;
    tauri::async_runtime::spawn_blocking(move || {
        run_sync_once(
            listen,
            SyncTarget {
                connect,
                space_id,
                group_reference,
                peer_fingerprint,
                scope: space_generation_scope_id(&space_id, &group_reference),
            },
            &database_path,
            &protector,
        )
    })
    .await
    .map_err(|error| format!("desktop sync worker failed: {error}"))?
}

fn run_sync_once(
    listen: SocketAddr,
    target: SyncTarget,
    database_path: &Path,
    protector: &OsKeyringProtector,
) -> Result<DesktopSyncResult, String> {
    let (mut client, mut created) = open_sync_profile(database_path, protector, target)?;

    let store = Store::open(database_path).map_err(|error| format!("open event store: {error}"))?;
    let mut summary_source = StoreSyncSummarySource::new(
        &store,
        target.scope,
        target.space_id,
        target.group_reference,
    );
    let local_summary = summary_source
        .load_summary(target.scope)
        .map_err(|error| format!("load local sync summary: {error}"))?;
    let mut event_source = StoreSyncEventSource::new(
        &store,
        target.scope,
        target.space_id,
        target.group_reference,
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("build Desktop sync runtime: {error}"))?;
    let (bound, outbound_adapter, inbound_adapter) =
        connect_sync_adapters(&runtime, listen, target)?;
    let mut deduplicator = EventDeduplicator::new(128)
        .map_err(|error| format!("create sync event deduplicator: {error:?}"))?;
    let cancellation = CancellationToken::new();
    let mut validator = |requested_scope: ScopeId,
                         author: lattice_sync::AuthorId,
                         sequence: u64,
                         expected_id: Option<EventId>,
                         bytes: &[u8]|
     -> Result<EventId, &'static str> {
        validate_event(
            target,
            requested_scope,
            author,
            sequence,
            expected_id,
            bytes,
        )
    };
    let authenticated = runtime
        .block_on(async {
            tokio::time::timeout(
                SYNC_STAGE_TIMEOUT,
                client.with_pinned_identity(
                    &target.peer_fingerprint,
                    |identity, pinned_peer| async move {
                        let outbound = execute_authenticated_sync_v2_once(
                            &outbound_adapter,
                            identity,
                            pinned_peer,
                            &local_summary,
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
                            &mut summary_source,
                            &mut event_source,
                            |peer, requested_scope| {
                                peer.fingerprint() == target.peer_fingerprint
                                    && requested_scope == target.scope
                            },
                            &cancellation,
                        );
                        tokio::try_join!(outbound, inbound)
                    },
                ),
            )
            .await
        })
        .map_err(|_| "authenticated Desktop sync timed out after 30 seconds".to_owned())?
        .map_err(|error| format!("load pinned Desktop identity: {error}"))?
        .ok_or_else(|| "requested peer fingerprint is no longer pinned".to_owned())?
        .map_err(|error| format!("authenticated Desktop sync failed: {error}"))?;

    let (outbound, inbound) = authenticated;
    let (accepted_events, pending_events, duplicate_events) =
        apply_synced_events(&mut client, &mut created, outbound.exchange.events)?;

    Ok(DesktopSyncResult {
        state: "bounded_sync_round_completed",
        listen_address: bound.to_string(),
        peer_fingerprint: encoding::hex(&target.peer_fingerprint),
        accepted_events,
        pending_events,
        duplicate_events,
        offered_events: inbound.exchange.included_events,
        network_contacted: true,
        converged: false,
    })
}

fn open_sync_profile(
    database_path: &Path,
    protector: &OsKeyringProtector,
    target: SyncTarget,
) -> Result<(Client, CreatedSpace), String> {
    let mut client = Client::open_existing(database_path, protector)
        .map_err(|error| format!("open Desktop profile: {error}"))?;
    let created = client
        .restore_space(&target.space_id, &target.group_reference)
        .map_err(|error| format!("restore selected Space generation: {error}"))?;
    if client
        .pinned_identity(&target.peer_fingerprint)
        .map_err(|error| format!("read peer pin: {error}"))?
        .is_none()
    {
        return Err("requested peer fingerprint is not pinned in this profile".to_owned());
    }
    Ok((client, created))
}

fn connect_sync_adapters(
    runtime: &tokio::runtime::Runtime,
    listen: SocketAddr,
    target: SyncTarget,
) -> Result<(SocketAddr, TcpPeerAdapter, TcpPeerAdapter), String> {
    let listener = runtime
        .block_on(TcpPeerListener::bind(listen, MAX_ENVELOPE_BYTES))
        .map_err(|error| format!("bind Desktop sync listener: {error:?}"))?;
    let bound = listener
        .local_addr()
        .map_err(|error| format!("read Desktop sync listener address: {error:?}"))?;
    let (outbound, (inbound, _remote_address)) = runtime
        .block_on(async {
            tokio::time::timeout(SYNC_STAGE_TIMEOUT, async {
                tokio::try_join!(
                    TcpPeerAdapter::connect(target.connect, MAX_ENVELOPE_BYTES),
                    listener.accept()
                )
            })
            .await
        })
        .map_err(|_| "Desktop connect/accept timed out after 30 seconds".to_owned())?
        .map_err(|error| format!("Desktop connect/accept failed: {error:?}"))?;
    Ok((bound, outbound, inbound))
}

struct MembershipEventBundles {
    transition_for_control: Vec<Option<usize>>,
    policy_for_control: Vec<Option<usize>>,
    paired_transition: Vec<bool>,
    bundled_policy: Vec<bool>,
    ambiguous: Vec<bool>,
}

fn pair_membership_events(
    events: &[(ValidatedSyncEvent, VerifiedSignatureOnlyEvent)],
) -> MembershipEventBundles {
    let mut bundles = MembershipEventBundles {
        transition_for_control: vec![None; events.len()],
        policy_for_control: vec![None; events.len()],
        paired_transition: vec![false; events.len()],
        bundled_policy: vec![false; events.len()],
        ambiguous: vec![false; events.len()],
    };
    for (control_index, (_, control)) in events.iter().enumerate() {
        if control.kind() != EventKind::MlsControl {
            continue;
        }
        let control_id = *control.event_id().as_bytes();
        let mut transitions = events.iter().enumerate().filter_map(|(index, (_, event))| {
            (event.kind() == EventKind::Membership
                && event
                    .parents()
                    .iter()
                    .any(|parent| parent.as_bytes() == &control_id))
            .then_some(index)
        });
        let Some(transition_index) = transitions.next() else {
            continue;
        };
        if transitions.next().is_some() {
            bundles.ambiguous[control_index] = true;
            continue;
        }
        bundles.transition_for_control[control_index] = Some(transition_index);
        bundles.paired_transition[transition_index] = true;

        let mut policy_parents = control.parents().iter().filter_map(|parent| {
            events.iter().enumerate().find_map(|(index, (_, event))| {
                (event.kind() == EventKind::Membership
                    && event.event_id().as_bytes() == parent.as_bytes())
                .then_some(index)
            })
        });
        if let Some(policy_index) = policy_parents.next() {
            if policy_parents.next().is_some() {
                bundles.ambiguous[control_index] = true;
                continue;
            }
            bundles.policy_for_control[control_index] = Some(policy_index);
            bundles.bundled_policy[policy_index] = true;
        }
    }
    bundles
}

fn apply_synced_events(
    client: &mut Client,
    created: &mut CreatedSpace,
    events: Vec<ValidatedSyncEvent>,
) -> Result<(usize, usize, usize), String> {
    let mut events = events
        .into_iter()
        .map(|event| {
            let verified = VerifiedSignatureOnlyEvent::decode_verify(&event.bytes)
                .map_err(|error| format!("verify synchronized event: {error}"))?;
            Ok((event, verified))
        })
        .collect::<Result<Vec<_>, String>>()?;
    events.sort_unstable_by_key(|(event, verified)| {
        (
            verified.mls_epoch(),
            *verified.author_fingerprint(),
            event.sequence,
        )
    });

    let bundles = pair_membership_events(&events);

    let mut counts = (0, 0, 0);
    for (index, (received, event)) in events.iter().enumerate() {
        match event.kind() {
            EventKind::MlsControl => {
                let Some(transition_index) = bundles.transition_for_control[index] else {
                    counts.1 += 1;
                    continue;
                };
                if bundles.ambiguous[index] {
                    counts.1 += 1;
                    continue;
                }
                let policy_bytes = bundles.policy_for_control[index]
                    .map(|parent| events[parent].0.bytes.as_slice());
                let accepted = client
                    .accept_synced_space_membership_transition(
                        created,
                        policy_bytes,
                        &received.bytes,
                        &events[transition_index].0.bytes,
                    )
                    .map_err(|error| {
                        format!("Core rejected synchronized membership transition: {error}")
                    })?;
                let bundle_size = 2 + usize::from(policy_bytes.is_some());
                if accepted {
                    counts.0 += bundle_size;
                } else {
                    counts.2 += bundle_size;
                }
            }
            EventKind::Membership | EventKind::Ephemeral => counts.1 += 1,
            EventKind::Message
            | EventKind::Edit
            | EventKind::Tombstone
            | EventKind::Reaction
            | EventKind::Pin
            | EventKind::FileManifest
            | EventKind::VoiceSignal => {
                let outcome = client
                    .accept_synced_application_event(created, &received.bytes)
                    .map_err(|error| format!("Core rejected synchronized event: {error}"))?;
                count_sync_outcome(&mut counts, &outcome);
            }
        }
    }
    for outcome in client
        .retry_ready_synced_application_events(created)
        .map_err(|error| format!("retry pending synchronized events: {error}"))?
    {
        count_sync_outcome(&mut counts, &outcome);
    }
    Ok(counts)
}

fn count_sync_outcome(counts: &mut (usize, usize, usize), outcome: &SyncedApplicationOutcome) {
    match outcome {
        SyncedApplicationOutcome::Accepted { .. } => counts.0 += 1,
        SyncedApplicationOutcome::Pending { .. } => counts.1 += 1,
        SyncedApplicationOutcome::Duplicate { .. } => counts.2 += 1,
    }
}

fn validate_event(
    target: SyncTarget,
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
