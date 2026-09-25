use std::{error::Error, io, net::SocketAddr, path::Path};

use clap::Subcommand;
use lattice_core::{Client, CoreError};
use lattice_events::VerifiedSignatureOnlyEvent;
use lattice_node::sync::{
    AuthenticatedSyncExchange, AuthenticatedSyncServeResult, StoreSyncEventSource,
    execute_authenticated_sync_once, serve_authenticated_sync_request_once,
    space_generation_scope_id,
};
use lattice_platform::{MAX_EVENT_BYTES, OsKeyringProtector};
use lattice_router::EventDeduplicator;
use lattice_storage::{MAX_EVENT_PAGE_SIZE, MAX_OUTBOX_PAGE_SIZE, OutboxState, Store};
use lattice_sync::{EventId, ScopeId, ScopeSummary};
use lattice_transport::{TcpPeerAdapter, TcpPeerListener};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Subcommand)]
pub(super) enum SyncCommand {
    /// Inspect local event, dependency, and outbox state without networking.
    Status,
    /// Fetch and apply one exact application event from a pinned direct peer.
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
        /// Exact event ID as 64 hexadecimal characters.
        #[arg(long)]
        event_id: String,
    },
    /// Accept one pinned peer and serve one authenticated direct-sync request.
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
            super::parse_fixed_hex::<32>(event_id, "event ID")?;
            Ok(())
        }
        SyncCommand::ServeOnce {
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
                event_id,
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
    }
}

#[derive(Clone, Copy)]
struct FetchOnceRequest<'a> {
    connect: SocketAddr,
    space_id: &'a str,
    group_reference: &'a str,
    peer_fingerprint: &'a str,
    event_id: &'a str,
}

#[derive(Clone, Copy)]
struct FetchOnceTarget {
    connect: SocketAddr,
    space_id: [u8; 16],
    group_reference: [u8; 32],
    peer_fingerprint: [u8; 32],
    event_id: [u8; 32],
    scope: ScopeId,
}

#[derive(Default)]
struct FetchEventCounts {
    accepted: usize,
    accepted_event_ids: Vec<String>,
    pending: usize,
    pending_dependency_ids: Vec<String>,
    duplicates: usize,
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
    let event_id = super::parse_fixed_hex::<32>(request.event_id, "event ID")
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
    let authenticated = fetch_from_peer(&client, target)?;
    let counts = accept_fetched_events(&mut client, &mut created, &authenticated.exchange.events)?;
    print_fetch_result(
        target,
        &counts,
        authenticated.exchange.rejected_events.len(),
        authenticated.exchange.unresolved_dependencies.len(),
        json,
    );
    Ok(())
}

fn fetch_from_peer(
    client: &Client,
    target: FetchOnceTarget,
) -> Result<AuthenticatedSyncExchange<&'static str>, Box<dyn Error>> {
    let mut local_summary = ScopeSummary::new(target.scope);
    local_summary
        .missing_dependencies
        .push(EventId::new(target.event_id));
    let peer_summary = ScopeSummary::new(target.scope);
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
            execute_authenticated_sync_once(
                &adapter,
                identity,
                pinned_peer,
                &local_summary,
                &peer_summary,
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
                "requested peer fingerprint is not pinned in this profile",
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

fn print_fetch_result(
    target: FetchOnceTarget,
    counts: &FetchEventCounts,
    rejected_events: usize,
    unresolved_dependencies: usize,
    json: bool,
) {
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
                "scope_id": super::hex(target.scope.as_bytes()),
                "requested_event_id": super::hex(&target.event_id),
                "accepted_events": counts.accepted,
                "accepted_event_ids": counts.accepted_event_ids,
                "pending_dependency_ids": counts.pending_dependency_ids,
                "pending_events": counts.pending,
                "duplicate_events": counts.duplicates,
                "rejected_events": rejected_events,
                "unresolved_dependencies": unresolved_dependencies,
                "recipient_delivery_claimed": false,
            })
        );
    } else {
        println!(
            "Authenticated direct sync received {} event(s), retained {} pending, recognized {} duplicates, and rejected {rejected_events}.",
            counts.accepted, counts.pending, counts.duplicates
        );
        println!("No recipient-delivery claim is made.");
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
            serve_authenticated_sync_request_once(
                &adapter,
                identity,
                pinned_peer,
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
        result,
    );
    Ok(())
}

fn print_serve_result(
    json: bool,
    bound: SocketAddr,
    remote_address: SocketAddr,
    peer_fingerprint: &[u8; 32],
    scope: ScopeId,
    result: AuthenticatedSyncServeResult,
) {
    let exchange = result.exchange;
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
    use super::pending_event_summaries;
    use lattice_events::{EventDraft, EventKind, VerifiedSignatureOnlyEvent};
    use lattice_identity::DeviceIdentity;
    use lattice_storage::Store;

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
}
