use std::{error::Error, io, net::SocketAddr, path::Path};

use clap::Subcommand;
use lattice_core::{Client, CoreError};
use lattice_node::sync::{
    AuthenticatedSyncServeResult, StoreSyncEventSource, serve_authenticated_sync_request_once,
    space_generation_scope_id,
};
use lattice_platform::{MAX_EVENT_BYTES, OsKeyringProtector};
use lattice_storage::{MAX_EVENT_PAGE_SIZE, MAX_OUTBOX_PAGE_SIZE, OutboxState, Store};
use lattice_sync::ScopeId;
use lattice_transport::TcpPeerListener;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Subcommand)]
pub(super) enum SyncCommand {
    /// Inspect locally stored pending events and outbox state; does not run synchronization.
    Status,
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
    let pending_event_count = store.pending_count()?;
    let mut committed_event_count = 0;
    let mut event_after = None;
    loop {
        let page = store.list_event_page(event_after, MAX_EVENT_PAGE_SIZE)?;
        committed_event_count += page.len();
        event_after = page.last().map(|event| event.event_id);
        if page.len() < MAX_EVENT_PAGE_SIZE {
            break;
        }
    }
    let mut outbox = OutboxCounts::default();
    let mut after_event_id = None;
    loop {
        let page = store.list_outbox_page(after_event_id, MAX_OUTBOX_PAGE_SIZE)?;
        if page.is_empty() {
            break;
        }
        for entry in &page {
            outbox.total += 1;
            match entry.state {
                OutboxState::Queued => outbox.queued += 1,
                OutboxState::Forwarded => outbox.forwarded += 1,
                OutboxState::Delivered => outbox.destination_receipt_recorded += 1,
                OutboxState::Failed => outbox.failed += 1,
            }
        }
        after_event_id = page.last().map(|entry| entry.event_id);
        if page.len() < MAX_OUTBOX_PAGE_SIZE {
            break;
        }
    }

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
                "pending_mls_epochs": null,
                "pending_mls_epochs_available": false,
                "destination_receipt_state_source": "local_outbox_record",
                "network_exchange_available": false,
                "recipient_delivery_claimed": false,
            })
        );
    } else {
        println!("Local event sequence ready: {next_local_event_sequence}");
        println!("Committed events: {committed_event_count}");
        println!("Pending dependency events: {pending_event_count}");
        println!(
            "Outbox: {} total ({} queued, {} forwarded, {} destination receipts recorded, {} failed).",
            outbox.total,
            outbox.queued,
            outbox.forwarded,
            outbox.destination_receipt_recorded,
            outbox.failed
        );
        println!(
            "Missing history ranges and pending MLS epochs are unavailable from current storage APIs."
        );
        println!("No synchronization scheduler or network exchange is running.");
        println!(
            "Destination-receipt counts reflect local outbox state and are not independently verified here."
        );
        println!("Forwarding or relay acceptance is not recipient delivery.");
    }
    Ok(())
}

#[derive(Default)]
struct OutboxCounts {
    total: usize,
    queued: usize,
    forwarded: usize,
    destination_receipt_recorded: usize,
    failed: usize,
}
