use std::{net::SocketAddr, path::Path, time::Duration};

use lattice_core::{
    Client, CreatedSpace, MAX_OUTBOX_PAGE_SIZE, SyncedApplicationOutcome,
    space::MAX_SPACE_PAYLOAD_BYTES,
};
use lattice_events::{EventKind, VerifiedSignatureOnlyEvent};
use lattice_identity::PrivateKeyProtector;
use lattice_mls::api::CredentialTrustPolicy;
use lattice_node::sync::{
    StoreSyncEventSource, StoreSyncSummarySource, SyncSummarySource, ValidatedSyncEvent,
    execute_authenticated_sync_v2_once, serve_authenticated_sync_v2_once,
    space_generation_scope_id,
};
use lattice_platform::MAX_ENVELOPE_BYTES;
use lattice_router::EventDeduplicator;
use lattice_storage::Store;
use lattice_sync::{EventId, ScopeId};
use lattice_transport::{TcpPeerAdapter, TcpPeerListener};
use serde::Serialize;
use tokio_util::sync::CancellationToken;

use crate::{encoding, profile};

const SYNC_STAGE_TIMEOUT: Duration = Duration::from_secs(30);
const WEBRTC_EVENT_PAGE_SIZE: usize = 64;
const WEBRTC_SYNC_BYTES_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DesktopWebEventPage {
    events: Vec<Vec<u8>>,
    next_cursor: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DesktopWebIngressResult {
    state: &'static str,
    event_id: String,
    missing_dependencies: Vec<String>,
}

// Tauri decodes command payloads into owned arguments.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub(crate) fn list_local_web_event_page(
    space_id_hex: String,
    group_reference_hex: String,
    after_event_id_hex: Option<String>,
) -> Result<DesktopWebEventPage, String> {
    let space_id = encoding::parse_fixed_hex::<16>(&space_id_hex, "Space ID")?;
    let group_reference = encoding::parse_fixed_hex::<32>(&group_reference_hex, "group reference")?;
    let after_event_id = after_event_id_hex
        .map(|value| encoding::parse_fixed_hex::<32>(&value, "outbox cursor"))
        .transpose()?;
    let (database_path, protector) = profile::open_profile()?;
    let mut client = profile::open_existing_client(database_path, &protector)
        .map_err(|error| format!("open Desktop profile: {error}"))?;
    client
        .restore_space(&space_id, &group_reference)
        .map_err(|error| format!("restore selected Space generation: {error}"))?;
    let page = client
        .outbox_application_event_page(
            &space_id,
            &group_reference,
            after_event_id,
            WEBRTC_EVENT_PAGE_SIZE.min(MAX_OUTBOX_PAGE_SIZE),
        )
        .map_err(|error| format!("read Desktop event outbox: {error}"))?;
    let page_bytes = page
        .events()
        .iter()
        .try_fold(0usize, |sum, event| sum.checked_add(event.len()))
        .ok_or_else(|| "Desktop outbox page size overflowed".to_owned())?;
    if page
        .events()
        .iter()
        .any(|event| event.is_empty() || event.len() > MAX_SPACE_PAYLOAD_BYTES)
        || page_bytes > WEBRTC_SYNC_BYTES_LIMIT
    {
        return Err("Desktop outbox page exceeded WebRTC transfer bounds".to_owned());
    }
    Ok(DesktopWebEventPage {
        events: page.events().to_vec(),
        next_cursor: page.next_cursor().map(|cursor| encoding::hex(&cursor)),
    })
}

// Tauri decodes command payloads into owned arguments.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub(crate) fn accept_local_web_event(
    space_id_hex: String,
    group_reference_hex: String,
    canonical_event: Vec<u8>,
) -> Result<DesktopWebIngressResult, String> {
    if canonical_event.is_empty() || canonical_event.len() > MAX_SPACE_PAYLOAD_BYTES {
        return Err("incoming event is empty or exceeds the 256 KiB limit".to_owned());
    }
    let space_id = encoding::parse_fixed_hex::<16>(&space_id_hex, "Space ID")?;
    let group_reference = encoding::parse_fixed_hex::<32>(&group_reference_hex, "group reference")?;
    let (database_path, protector) = profile::open_profile()?;
    let mut client = profile::open_existing_client(database_path, &protector)
        .map_err(|error| format!("open Desktop profile: {error}"))?;
    let mut created = client
        .restore_space(&space_id, &group_reference)
        .map_err(|error| format!("restore selected Space generation: {error}"))?;
    let outcome = client
        .accept_synced_application_event(&mut created, &canonical_event)
        .map_err(|error| format!("Core rejected synchronized event: {error}"))?;
    let (state, event_id, missing_dependencies) = match outcome {
        SyncedApplicationOutcome::Accepted { event_id } => ("accepted", event_id, Vec::new()),
        SyncedApplicationOutcome::Duplicate { event_id } => ("duplicate", event_id, Vec::new()),
        SyncedApplicationOutcome::CheckpointExcluded { event_id } => {
            ("checkpoint_excluded", event_id, Vec::new())
        }
        SyncedApplicationOutcome::Pending {
            event_id,
            missing_dependencies,
        } => (
            "pending",
            event_id,
            missing_dependencies
                .into_iter()
                .map(|dependency| encoding::hex(&dependency))
                .collect(),
        ),
    };
    Ok(DesktopWebIngressResult {
        state,
        event_id: encoding::hex(&event_id),
        missing_dependencies,
    })
}

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
    checkpoint_excluded_events: usize,
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
    let trust_policy = profile::credential_trust_policy()?;
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
            trust_policy,
        )
    })
    .await
    .map_err(|error| format!("desktop sync worker failed: {error}"))?
}

fn run_sync_once<P: PrivateKeyProtector>(
    listen: SocketAddr,
    target: SyncTarget,
    database_path: &Path,
    protector: &P,
    trust_policy: CredentialTrustPolicy,
) -> Result<DesktopSyncResult, String> {
    let (mut client, mut created) =
        open_sync_profile(database_path, protector, trust_policy, target)?;

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
    let (accepted_events, pending_events, duplicate_events, checkpoint_excluded_events) =
        apply_synced_events(&mut client, &mut created, outbound.exchange.events)?;

    Ok(DesktopSyncResult {
        state: "bounded_sync_round_completed",
        listen_address: bound.to_string(),
        peer_fingerprint: encoding::hex(&target.peer_fingerprint),
        accepted_events,
        pending_events,
        duplicate_events,
        checkpoint_excluded_events,
        offered_events: inbound.exchange.included_events,
        network_contacted: true,
        converged: false,
    })
}

fn open_sync_profile<P: PrivateKeyProtector>(
    database_path: &Path,
    protector: &P,
    trust_policy: CredentialTrustPolicy,
    target: SyncTarget,
) -> Result<(Client, CreatedSpace), String> {
    let mut client =
        Client::open_existing_with_trust_policy(database_path, protector, trust_policy)
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
                    && event.mls_epoch() == control.mls_epoch()
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

fn mark_conflict_bundle(index: usize, bundles: &MembershipEventBundles, conflicted: &mut [bool]) {
    conflicted[index] = true;
    if let Some(transition) = bundles.transition_for_control[index] {
        conflicted[transition] = true;
    }
    if let Some(policy) = bundles.policy_for_control[index] {
        conflicted[policy] = true;
    }
}

type DecodedSyncEvent = (ValidatedSyncEvent, VerifiedSignatureOnlyEvent);

fn quarantine_sibling_membership_conflicts(
    client: &mut Client,
    created: &mut CreatedSpace,
    events: &[DecodedSyncEvent],
) -> Result<(MembershipEventBundles, Vec<bool>), String> {
    let bundles = pair_membership_events(events);
    let mut conflicted = vec![false; events.len()];
    let mut examined = vec![false; events.len()];
    for (first_index, (_, first)) in events.iter().enumerate() {
        if examined[first_index] || first.kind() != EventKind::MlsControl {
            continue;
        }
        let siblings = events
            .iter()
            .enumerate()
            .filter_map(|(index, (_, event))| {
                (event.kind() == EventKind::MlsControl
                    && event.mls_epoch() == first.mls_epoch()
                    && event.parents() == first.parents())
                .then_some(index)
            })
            .collect::<Vec<_>>();
        if siblings.len() < 2 {
            continue;
        }
        for index in &siblings {
            examined[*index] = true;
        }
        if siblings.len() != 2
            || events[siblings[0]].1.author_fingerprint()
                == events[siblings[1]].1.author_fingerprint()
        {
            for index in siblings {
                mark_conflict_bundle(index, &bundles, &mut conflicted);
            }
            continue;
        }

        let space_id = *created.space_id();
        let group_reference = *created.group_reference();
        let group_id = created.group_id().to_vec();
        client
            .record_space_membership_conflict(
                &group_id,
                created.reducer(),
                &events[siblings[0]].1,
                &events[siblings[1]].1,
            )
            .map_err(|error| format!("Core rejected sibling membership Commits: {error}"))?;
        *created = client
            .restore_space(&space_id, &group_reference)
            .map_err(|error| format!("restore conflicted Space generation: {error}"))?;
        for index in siblings {
            mark_conflict_bundle(index, &bundles, &mut conflicted);
        }
    }
    Ok((bundles, conflicted))
}

fn apply_unconflicted_sync_events(
    client: &mut Client,
    created: &mut CreatedSpace,
    events: &[DecodedSyncEvent],
    bundles: &MembershipEventBundles,
    conflicted: &[bool],
) -> Result<(usize, usize, usize, usize), String> {
    let mut counts = (0, conflicted.iter().filter(|value| **value).count(), 0, 0);
    for (index, (received, event)) in events.iter().enumerate() {
        if conflicted[index] || bundles.paired_transition[index] || bundles.bundled_policy[index] {
            continue;
        }
        if matches!(
            created.reducer().status(),
            lattice_core::space::ReducerStatus::PolicyConflicted
        ) {
            counts.1 += 1;
            continue;
        }
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
            EventKind::Membership | EventKind::Ephemeral | EventKind::RelayMailboxControl => {
                counts.1 += 1;
            }
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
    if !matches!(
        created.reducer().status(),
        lattice_core::space::ReducerStatus::PolicyConflicted
    ) {
        for outcome in client
            .retry_ready_synced_application_events(created)
            .map_err(|error| format!("retry pending synchronized events: {error}"))?
        {
            count_sync_outcome(&mut counts, &outcome);
        }
    }
    Ok(counts)
}

fn apply_synced_events(
    client: &mut Client,
    created: &mut CreatedSpace,
    events: Vec<ValidatedSyncEvent>,
) -> Result<(usize, usize, usize, usize), String> {
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
    let (bundles, conflicted) = quarantine_sibling_membership_conflicts(client, created, &events)?;
    apply_unconflicted_sync_events(client, created, &events, &bundles, &conflicted)
}

fn count_sync_outcome(
    counts: &mut (usize, usize, usize, usize),
    outcome: &SyncedApplicationOutcome,
) {
    match outcome {
        SyncedApplicationOutcome::Accepted { .. } => counts.0 += 1,
        SyncedApplicationOutcome::Pending { .. } => counts.1 += 1,
        SyncedApplicationOutcome::Duplicate { .. } => counts.2 += 1,
        SyncedApplicationOutcome::CheckpointExcluded { .. } => counts.3 += 1,
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

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use lattice_core::{
        Client, CoreError, CreatedSpace, InitialChannel,
        space::{ChannelType, MemberStatus, ReducerStatus},
    };
    use lattice_events::{EventDraft, EventKind, VerifiedSignatureOnlyEvent};
    use lattice_identity::{PrivateKeyProtectionError, PrivateKeyProtector};
    use lattice_mls::api::{DeviceCredentialInput, GroupState};
    use lattice_storage::Store;
    use lattice_sync::{AuthorId, EventId};
    use openmls::credentials::{Credential, CredentialType};

    use super::*;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "lattice-desktop-sync-{}-{sequence}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("create test profile directory");
            Self(path)
        }

        fn database(&self, profile: &str) -> PathBuf {
            self.0.join(format!("{profile}.sqlite"))
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct TestProtector;

    impl PrivateKeyProtector for TestProtector {
        fn wrap(&self, clear_material: &[u8]) -> Result<Vec<u8>, PrivateKeyProtectionError> {
            Ok(clear_material.to_vec())
        }

        fn unwrap(&self, ciphertext: &[u8]) -> Result<Vec<u8>, PrivateKeyProtectionError> {
            Ok(ciphertext.to_vec())
        }
    }

    fn test_credential(client: &mut Client) -> DeviceCredentialInput {
        let credential = Credential::new(
            CredentialType::X509,
            b"desktop sync test credential".to_vec(),
        );
        client
            .with_mls_transaction(|identity, _, _| {
                DeviceCredentialInput::from_untrusted_x509_credential_for_tests(
                    identity,
                    &credential,
                )
                .map_err(CoreError::from)
            })
            .expect("bind test credential to profile identity")
    }

    fn create_space(client: &mut Client, credential: &DeviceCredentialInput) -> CreatedSpace {
        client
            .create_space(
                credential,
                vec![InitialChannel {
                    channel_type: ChannelType::Text,
                    name: "general".to_owned(),
                    default_allow: 0,
                    default_deny: 0,
                    role_overrides: Vec::new(),
                }],
            )
            .expect("create test Space")
    }

    fn signed_control(
        client: &mut Client,
        space: &CreatedSpace,
        parent: [u8; 32],
        epoch: u64,
        commit: Vec<u8>,
    ) -> VerifiedSignatureOnlyEvent {
        let author_sequence = client
            .next_author_sequence()
            .expect("reserve author sequence");
        let space_id = *space.space_id();
        let group_reference = *space.group_reference();
        client
            .with_mls_transaction(|identity, _, _| {
                Ok::<_, CoreError>(
                    VerifiedSignatureOnlyEvent::create(
                        identity,
                        EventDraft {
                            space_id,
                            channel_id: None,
                            author_sequence,
                            lamport: author_sequence,
                            wall_time_hint: 0,
                            parents: vec![lattice_protocol::EventId::from_bytes(parent)],
                            kind: EventKind::MlsControl,
                            protected_body: commit,
                            mls_group_reference: group_reference,
                            mls_epoch: epoch,
                        },
                    )
                    .expect("sign sibling membership control"),
                )
            })
            .expect("create signed membership control")
    }

    fn validated_event(bytes: Vec<u8>) -> ValidatedSyncEvent {
        let event = VerifiedSignatureOnlyEvent::decode_verify(&bytes)
            .expect("decode and verify synchronized event");
        ValidatedSyncEvent {
            author: AuthorId::new(*event.author_fingerprint()),
            sequence: event.author_sequence(),
            event_id: EventId::new(*event.event_id().as_bytes()),
            bytes,
        }
    }

    fn persisted_event(path: &std::path::Path, event_id: &[u8; 32]) -> Vec<u8> {
        Store::open(path)
            .expect("open profile store")
            .load_event(event_id)
            .expect("load synchronized event")
            .expect("event record exists")
            .canonical_bytes
    }

    fn admission_bundle(
        client: &Client,
        path: &std::path::Path,
        invite_event_id: &[u8; 32],
    ) -> Vec<ValidatedSyncEvent> {
        let store = Store::open(path).expect("open inviter event store");
        let events = client
            .outbox_page(None, 128)
            .expect("list inviter outbox")
            .into_iter()
            .filter_map(|entry| {
                store
                    .load_event(&entry.event_id)
                    .expect("load inviter outbox event")
                    .map(|record| record.canonical_bytes)
            })
            .filter_map(|bytes| VerifiedSignatureOnlyEvent::decode_verify(&bytes).ok())
            .collect::<Vec<_>>();
        let policy = events
            .iter()
            .find(|event| event.event_id().as_bytes() == invite_event_id)
            .expect("invite policy event");
        let control = events
            .iter()
            .find(|event| {
                event.kind() == EventKind::MlsControl
                    && event
                        .parents()
                        .iter()
                        .any(|parent| parent.as_bytes() == invite_event_id)
            })
            .expect("invite MLS control event");
        let control_id = *control.event_id().as_bytes();
        let transition = events
            .iter()
            .find(|event| {
                event.kind() == EventKind::Membership
                    && event
                        .parents()
                        .iter()
                        .any(|parent| parent.as_bytes() == &control_id)
            })
            .expect("invite membership transition event");
        vec![
            validated_event(policy.encoded_bytes().to_vec()),
            validated_event(control.encoded_bytes().to_vec()),
            validated_event(transition.encoded_bytes().to_vec()),
        ]
    }

    fn epoch(client: &mut Client, space: &CreatedSpace) -> u64 {
        let group_id = space.group_id().to_vec();
        client
            .with_mls_transaction(|_, provider, _| {
                Ok::<_, CoreError>(GroupState::load(provider, &group_id)?.epoch())
            })
            .expect("read persisted MLS epoch")
    }

    fn joined_profiles(
        directory: &TestDirectory,
    ) -> (
        Client,
        CreatedSpace,
        DeviceCredentialInput,
        Client,
        CreatedSpace,
        DeviceCredentialInput,
        [u8; 32],
    ) {
        let mut admin = Client::open_or_create(directory.database("admin"), &TestProtector)
            .expect("open admin profile");
        let admin_credential = test_credential(&mut admin);
        let mut space = create_space(&mut admin, &admin_credential);
        let mut member = Client::open_or_create(directory.database("member"), &TestProtector)
            .expect("open member profile");
        let member_credential = test_credential(&mut member);
        let member_fingerprint = member.identity_info().fingerprint;
        let key_package = member
            .publish_key_package(&member_credential, 100)
            .expect("publish member KeyPackage");
        let invitation = admin
            .create_space_invite(
                &mut space,
                &admin_credential,
                &key_package,
                None,
                2_000,
                Some(1),
            )
            .expect("invite member through client API");
        let admin_identity = admin.identity_info();
        member
            .pin_identity(&admin_identity.public_bundle, admin_identity.fingerprint)
            .expect("pin inviter identity");
        let joined = member
            .join_space_from_welcome_bootstrap(
                invitation.welcome_bootstrap(),
                admin_identity.fingerprint,
                &member_credential,
            )
            .expect("join through pinned Welcome");
        let joined = member
            .restore_space(joined.space_id(), joined.group_reference())
            .expect("restore joined client generation");
        (
            admin,
            space,
            admin_credential,
            member,
            joined,
            member_credential,
            member_fingerprint,
        )
    }

    fn available_loopback_address() -> SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve test port");
        let address = listener.local_addr().expect("read test address");
        drop(listener);
        address
    }

    fn assert_removed_profiles_converged(
        directory: &TestDirectory,
        space_id: &[u8; 16],
        group_reference: &[u8; 32],
        member_fingerprint: [u8; 32],
    ) {
        let mut admin = Client::open_existing(directory.database("admin"), &TestProtector)
            .expect("reopen admin after authenticated sync");
        let admin_space = admin
            .restore_space(space_id, group_reference)
            .expect("restore admin Space");
        let mut member = Client::open_existing(directory.database("member"), &TestProtector)
            .expect("reopen member after authenticated sync");
        let member_space = member
            .restore_space(space_id, group_reference)
            .expect("restore receiving member Space");
        assert_eq!(epoch(&mut admin, &admin_space), 2);
        assert_eq!(epoch(&mut member, &member_space), 2);
        for space in [&admin_space, &member_space] {
            assert_eq!(
                space
                    .reducer()
                    .policy()
                    .expect("converged membership policy")
                    .members
                    .iter()
                    .find(|entry| entry.fingerprint == member_fingerprint)
                    .map(|entry| entry.status),
                Some(MemberStatus::Removed)
            );
        }
        assert_eq!(
            admin_space
                .reducer()
                .policy()
                .expect("admin policy")
                .revision,
            member_space
                .reducer()
                .policy()
                .expect("member policy")
                .revision
        );
    }

    #[test]
    fn desktop_sync_delivers_member_removal_over_authenticated_loopback() {
        let directory = TestDirectory::new();
        let (
            mut admin,
            mut admin_space,
            admin_credential,
            member,
            member_space,
            _member_credential,
            member_fingerprint,
        ) = joined_profiles(&directory);
        let admin_path = directory.database("admin");
        let member_path = directory.database("member");
        let space_id = *admin_space.space_id();
        let group_reference = *admin_space.group_reference();
        let admin_fingerprint = admin.identity_info().fingerprint;
        let member_identity = member.identity_info();
        admin
            .pin_identity(&member_identity.public_bundle, member_identity.fingerprint)
            .expect("pin member for authenticated sync");
        admin
            .remove_space_member(&mut admin_space, &admin_credential, member_fingerprint)
            .expect("commit removal before network sync");
        drop(admin_space);
        drop(admin);
        drop(member_space);
        drop(member);

        let admin_listen = available_loopback_address();
        let member_listen = available_loopback_address();
        let scope = space_generation_scope_id(&space_id, &group_reference);
        let admin_target = SyncTarget {
            connect: member_listen,
            space_id,
            group_reference,
            peer_fingerprint: member_fingerprint,
            scope,
        };
        let member_target = SyncTarget {
            connect: admin_listen,
            space_id,
            group_reference,
            peer_fingerprint: admin_fingerprint,
            scope,
        };
        let admin_sync = std::thread::spawn(move || {
            run_sync_once(
                admin_listen,
                admin_target,
                &admin_path,
                &TestProtector,
                CredentialTrustPolicy::native_system(),
            )
        });
        let member_sync = std::thread::spawn(move || {
            run_sync_once(
                member_listen,
                member_target,
                &member_path,
                &TestProtector,
                CredentialTrustPolicy::native_system(),
            )
        });
        let admin_result = admin_sync
            .join()
            .expect("admin sync worker")
            .expect("admin sync");
        let member_result = member_sync
            .join()
            .expect("member sync worker")
            .expect("member sync");
        assert!(admin_result.network_contacted);
        assert!(member_result.network_contacted);

        assert_removed_profiles_converged(
            &directory,
            &space_id,
            &group_reference,
            member_fingerprint,
        );
    }

    #[test]
    fn desktop_sync_applies_member_removal_and_both_profiles_converge_after_restart() {
        let directory = TestDirectory::new();
        let (
            mut admin,
            mut admin_space,
            admin_credential,
            mut member,
            mut member_space,
            _member_credential,
            member_fingerprint,
        ) = joined_profiles(&directory);
        let admin_path = directory.database("admin");
        let member_path = directory.database("member");
        let space_id = *admin_space.space_id();
        let group_reference = *admin_space.group_reference();
        let group_id = admin_space.group_id().to_vec();

        let removal = admin
            .remove_space_member(&mut admin_space, &admin_credential, member_fingerprint)
            .expect("commit Remove and rekey");
        let control_bytes = persisted_event(&admin_path, removal.control_event_id());
        let transition_bytes = persisted_event(&admin_path, removal.transition_event_id());
        let received = || {
            vec![
                validated_event(transition_bytes.clone()),
                validated_event(control_bytes.clone()),
            ]
        };
        let counts = apply_synced_events(&mut member, &mut member_space, received())
            .expect("apply removal through Desktop sync ingress");
        assert_eq!(counts, (2, 0, 0, 0));
        assert_eq!(
            member_space.reducer().status(),
            ReducerStatus::Active { revision: 3 }
        );
        assert_eq!(epoch(&mut member, &member_space), 2);
        let member_policy = member_space.reducer().policy().expect("member policy");
        assert_eq!(
            member_policy
                .members
                .iter()
                .find(|entry| entry.fingerprint == member_fingerprint)
                .map(|entry| entry.status),
            Some(MemberStatus::Removed)
        );

        drop(member_space);
        drop(member);
        let mut member = Client::open_existing(&member_path, &TestProtector)
            .expect("reopen removed member profile");
        let mut member_space = member
            .restore_space(&space_id, &group_reference)
            .expect("restore member after sync");
        assert_eq!(epoch(&mut member, &member_space), 2);
        let replay_counts = apply_synced_events(&mut member, &mut member_space, received())
            .expect("replay removal after restart");
        assert_eq!(replay_counts, (0, 0, 2, 0));

        drop(admin_space);
        drop(admin);
        let mut admin =
            Client::open_existing(&admin_path, &TestProtector).expect("reopen admin profile");
        let admin_space = admin
            .restore_space(&space_id, &group_reference)
            .expect("restore admin after local removal");
        assert_eq!(epoch(&mut admin, &admin_space), 2);
        let admin_policy = admin_space.reducer().policy().expect("admin policy");
        assert_eq!(
            admin_policy
                .members
                .iter()
                .find(|entry| entry.fingerprint == member_fingerprint)
                .map(|entry| entry.status),
            Some(MemberStatus::Removed)
        );
        assert_eq!(
            admin_policy.revision,
            member_space
                .reducer()
                .policy()
                .expect("converged member policy")
                .revision
        );
        assert_eq!(admin_space.group_id(), group_id);
    }

    fn sibling_add_controls(
        directory: &TestDirectory,
        admin: &mut Client,
        admin_space: &mut CreatedSpace,
        admin_credential: &DeviceCredentialInput,
        member: &mut Client,
        member_space: &mut CreatedSpace,
    ) -> [VerifiedSignatureOnlyEvent; 2] {
        let admin_path = directory.database("admin");
        let mut charlie = Client::open_or_create(directory.database("charlie"), &TestProtector)
            .expect("open third active profile");
        let charlie_credential = test_credential(&mut charlie);
        let charlie_key_package = charlie
            .publish_key_package(&charlie_credential, 100)
            .expect("publish third member KeyPackage");
        let invitation = admin
            .create_space_invite(
                admin_space,
                admin_credential,
                &charlie_key_package,
                None,
                2_000,
                Some(1),
            )
            .expect("invite third active member");
        let admin_identity = admin.identity_info();
        charlie
            .pin_identity(&admin_identity.public_bundle, admin_identity.fingerprint)
            .expect("pin inviter on third profile");
        let charlie_space = charlie
            .join_space_from_welcome_bootstrap(
                invitation.welcome_bootstrap(),
                admin_identity.fingerprint,
                &charlie_credential,
            )
            .expect("third member joins by Welcome");
        assert_eq!(charlie_space.group_id(), admin_space.group_id());
        let member_addition = admission_bundle(admin, &admin_path, invitation.invite_event_id());
        assert_eq!(
            apply_synced_events(member, member_space, member_addition)
                .expect("sync third-member addition to second branch author"),
            (3, 0, 0, 0)
        );
        let parent = admin_space
            .reducer()
            .policy()
            .expect("active policy after third admission")
            .heads[0];
        let group_id = admin_space.group_id().to_vec();
        let mut dave = Client::open_or_create(directory.database("dave"), &TestProtector)
            .expect("open first branch target");
        let dave_credential = test_credential(&mut dave);
        let dave_key_package = dave
            .publish_key_package(&dave_credential, 100)
            .expect("publish first branch KeyPackage");
        let mut eve = Client::open_or_create(directory.database("eve"), &TestProtector)
            .expect("open second branch target");
        let eve_credential = test_credential(&mut eve);
        let eve_key_package = eve
            .publish_key_package(&eve_credential, 100)
            .expect("publish second branch KeyPackage");
        let member_credential = test_credential(member);
        let member_commit = member
            .with_mls_transaction(|identity, provider, _| {
                let mut group = GroupState::load(provider, &group_id)?;
                let prepared =
                    group.prepare_add(provider, identity, &member_credential, &dave_key_package)?;
                Ok::<_, CoreError>(prepared.commit().as_bytes().to_vec())
            })
            .expect("prepare member branch Commit");
        let charlie_commit = charlie
            .with_mls_transaction(|identity, provider, _| {
                let mut group = GroupState::load(provider, &group_id)?;
                let prepared =
                    group.prepare_add(provider, identity, &charlie_credential, &eve_key_package)?;
                Ok::<_, CoreError>(prepared.commit().as_bytes().to_vec())
            })
            .expect("prepare third-member sibling Commit");
        [
            signed_control(member, admin_space, parent, 2, member_commit),
            signed_control(&mut charlie, admin_space, parent, 2, charlie_commit),
        ]
    }

    #[test]
    fn desktop_sync_quarantines_sibling_commits_and_recovery_survives_restart() {
        let directory = TestDirectory::new();
        let (
            mut admin,
            mut admin_space,
            admin_credential,
            mut member,
            mut member_space,
            _member_credential,
            _member_fingerprint,
        ) = joined_profiles(&directory);
        let admin_path = directory.database("admin");
        let space_id = *admin_space.space_id();
        let group_reference = *admin_space.group_reference();
        let sibling_controls = sibling_add_controls(
            &directory,
            &mut admin,
            &mut admin_space,
            &admin_credential,
            &mut member,
            &mut member_space,
        );
        let counts = apply_synced_events(
            &mut admin,
            &mut admin_space,
            sibling_controls
                .iter()
                .map(|event| validated_event(event.encoded_bytes().to_vec()))
                .collect(),
        )
        .expect("record sibling Commit conflict through Desktop sync ingress");
        assert_eq!(counts, (0, 2, 0, 0));
        assert_eq!(
            admin_space.reducer().status(),
            ReducerStatus::PolicyConflicted
        );
        drop(admin_space);
        drop(admin);
        let mut admin =
            Client::open_existing(&admin_path, &TestProtector).expect("reopen conflicted admin");
        let conflicted = admin
            .restore_space(&space_id, &group_reference)
            .expect("restore quarantined generation");
        assert_eq!(
            conflicted.reducer().status(),
            ReducerStatus::PolicyConflicted
        );
        let recovery_credential = test_credential(&mut admin);
        let recovered = admin
            .create_space_recovery_generation(&conflicted, &recovery_credential)
            .expect("create authorized recovery generation");
        assert_eq!(recovered.space_id(), &space_id);
        assert_ne!(recovered.group_reference(), &group_reference);
        assert_eq!(epoch(&mut admin, &recovered), 0);
        assert_eq!(
            recovered
                .reducer()
                .policy()
                .expect("recovery policy")
                .members
                .len(),
            1
        );
        assert_eq!(
            admin
                .restore_space(&space_id, &group_reference)
                .expect("prior conflicted generation remains retained")
                .reducer()
                .status(),
            ReducerStatus::PolicyConflicted
        );
    }
}
