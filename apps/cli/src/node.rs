use std::{
    error::Error,
    io,
    net::SocketAddr,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use clap::Subcommand;
use lattice_core::Client;
use lattice_mesh::EnvelopeId;
use lattice_node::courier::{CourierSendResult, receive_courier_once, send_courier_once};
use lattice_platform::{MAX_ENVELOPE_BYTES, OsKeyringProtector};
use lattice_storage::{DEFAULT_COURIER_LIMITS, Store};
use lattice_transport::{TcpPeerAdapter, TcpPeerListener};
use tokio_util::sync::CancellationToken;

const MAX_NODE_SESSIONS: usize = 64;
const MAX_NODE_RUNTIME_SECONDS: u64 = 24 * 60 * 60;
const NODE_SESSION_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Subcommand)]
pub(super) enum NodeCommand {
    /// Opt into a bounded persistent pinned-peer courier listener.
    Run {
        /// TCP address to bind, for example `0.0.0.0:7000`.
        #[arg(long)]
        listen: SocketAddr,
        /// Exact previously verified and pinned peer fingerprint.
        #[arg(long)]
        peer_fingerprint: String,
        /// Maximum accepted connection attempts before exiting (1–64).
        #[arg(long, default_value_t = 16)]
        max_sessions: usize,
        /// Maximum listener lifetime in seconds (1–86400).
        #[arg(long, default_value_t = 3600)]
        run_seconds: u64,
    },
    /// Transfer one selected local courier envelope to a pinned TCP peer.
    ForwardOnce {
        /// TCP endpoint to connect, for example `127.0.0.1:7000`.
        #[arg(long)]
        connect: SocketAddr,
        /// Exact previously verified and pinned peer fingerprint.
        #[arg(long)]
        peer_fingerprint: String,
        /// Local queued envelope identifier from `lattice node queue`.
        #[arg(long)]
        envelope_id: String,
    },
    /// Inspect opt-in state and bounded local queue identifiers.
    Queue,
}

pub(super) fn validate_command(command: &NodeCommand) -> Result<(), String> {
    match command {
        NodeCommand::Run {
            peer_fingerprint,
            max_sessions,
            run_seconds,
            ..
        } => {
            super::parse_fixed_hex::<32>(peer_fingerprint, "peer fingerprint")?;
            if !(1..=MAX_NODE_SESSIONS).contains(max_sessions) {
                return Err(format!(
                    "max sessions must be between 1 and {MAX_NODE_SESSIONS}"
                ));
            }
            if !(1..=MAX_NODE_RUNTIME_SECONDS).contains(run_seconds) {
                return Err(format!(
                    "run duration must be between 1 and {MAX_NODE_RUNTIME_SECONDS} seconds"
                ));
            }
            Ok(())
        }
        NodeCommand::ForwardOnce {
            peer_fingerprint,
            envelope_id,
            ..
        } => {
            super::parse_fixed_hex::<32>(peer_fingerprint, "peer fingerprint")?;
            super::parse_fixed_hex::<16>(envelope_id, "local envelope ID")?;
            Ok(())
        }
        NodeCommand::Queue => Ok(()),
    }
}

pub(super) fn execute(
    command: &NodeCommand,
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    match command {
        NodeCommand::Queue => print_queue(database_path, json),
        NodeCommand::Run {
            listen,
            peer_fingerprint,
            max_sessions,
            run_seconds,
        } => run_listener(
            *listen,
            peer_fingerprint,
            *max_sessions,
            *run_seconds,
            database_path,
            protector,
            json,
        ),
        NodeCommand::ForwardOnce {
            connect,
            peer_fingerprint,
            envelope_id,
        } => forward_once(
            *connect,
            peer_fingerprint,
            envelope_id,
            database_path,
            protector,
            json,
        ),
    }
}

fn print_queue(database_path: &Path, json: bool) -> Result<(), Box<dyn Error>> {
    let mut store = Store::open(database_path)?;
    store.purge_expired_courier_envelopes(unix_millis())?;
    let status = store.courier_queue_status()?;
    let ids = store.list_courier_envelope_ids(lattice_storage::MAX_COURIER_QUEUE_PAGE_SIZE)?;
    let ids = ids
        .iter()
        .map(|id| super::hex(id.as_bytes()))
        .collect::<Vec<_>>();
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "command": "node_queue",
                "enabled": status.enabled,
                "queued_items": status.usage.items,
                "queued_bytes": status.usage.bytes,
                "limits": {
                    "max_object_bytes": status.limits.max_object_bytes,
                    "max_peer_bytes": status.limits.max_peer_bytes,
                    "max_peer_items": status.limits.max_peer_items,
                    "max_total_bytes": status.limits.max_total_bytes,
                    "max_total_items": status.limits.max_total_items,
                },
                "local_envelope_ids": ids,
                "recipient_delivery_claimed": false,
            })
        );
    } else {
        println!(
            "Courier queue: {}; {} item(s), {} opaque byte(s).",
            if status.enabled {
                "enabled"
            } else {
                "disabled"
            },
            status.usage.items,
            status.usage.bytes
        );
        for id in ids {
            println!("Local envelope ID: {id}");
        }
        println!("Queue retention is not evidence of recipient delivery.");
    }
    Ok(())
}

fn run_listener(
    listen: SocketAddr,
    peer_fingerprint: &str,
    max_sessions: usize,
    run_seconds: u64,
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    let peer_fingerprint = super::parse_fixed_hex::<32>(peer_fingerprint, "peer fingerprint")
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let client = Client::open_existing(database_path, protector)?;
    if client.pinned_identity(&peer_fingerprint)?.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "requested peer fingerprint is not pinned in this profile",
        )
        .into());
    }
    let mut store = Store::open(database_path)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let listener = runtime
        .block_on(TcpPeerListener::bind(listen, MAX_ENVELOPE_BYTES))
        .map_err(|error| io::Error::other(format!("{error:?}")))?;
    let bound = listener
        .local_addr()
        .map_err(|error| io::Error::other(format!("{error:?}")))?;
    store.purge_expired_courier_envelopes(unix_millis())?;
    store.configure_courier_queue(true, DEFAULT_COURIER_LIMITS)?;
    let deadline = Instant::now() + Duration::from_secs(run_seconds);
    let cancellation = CancellationToken::new();
    let mut accepted = 0_usize;
    let mut rejected = 0_usize;
    while accepted + rejected < max_sessions {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let (adapter, _remote_address) =
            match runtime.block_on(tokio::time::timeout(remaining, listener.accept())) {
                Ok(Ok(connection)) => connection,
                Ok(Err(error)) => return Err(io::Error::other(format!("{error:?}")).into()),
                Err(_) => break,
            };
        let session_timeout =
            NODE_SESSION_TIMEOUT.min(deadline.saturating_duration_since(Instant::now()));
        if session_timeout.is_zero() {
            break;
        }
        let store_ref = &mut store;
        let session_cancellation = cancellation.clone();
        let result = runtime.block_on(tokio::time::timeout(
            session_timeout,
            client.with_pinned_identity(&peer_fingerprint, |identity, pinned| async move {
                receive_courier_once(&adapter, identity, pinned, store_ref, &session_cancellation)
                    .await
            }),
        ))?;
        match result {
            Ok(Some(Ok(_receipt))) => accepted += 1,
            Ok(Some(Err(_))) | Err(_) => rejected += 1,
            Ok(None) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "requested peer fingerprint is no longer pinned",
                )
                .into());
            }
        }
    }
    let final_status = store.courier_queue_status()?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "command": "node_run",
                "bound_address": bound.to_string(),
                "courier_enabled": final_status.enabled,
                "max_sessions": max_sessions,
                "run_seconds": run_seconds,
                "accepted_envelopes": accepted,
                "rejected_sessions": rejected,
                "queue_items": final_status.usage.items,
                "queue_bytes": final_status.usage.bytes,
                "recipient_delivery_claimed": false,
            })
        );
    } else {
        println!(
            "Courier listener stopped after {accepted} accepted envelope(s) and {rejected} rejected session(s); queue contains {} item(s), {} byte(s). No recipient-delivery claim is made.",
            final_status.usage.items, final_status.usage.bytes
        );
    }
    Ok(())
}

fn forward_once(
    connect: SocketAddr,
    peer_fingerprint: &str,
    local_envelope_id: &str,
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    let peer_fingerprint = super::parse_fixed_hex::<32>(peer_fingerprint, "peer fingerprint")
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let local_envelope_id = super::parse_fixed_hex::<16>(local_envelope_id, "local envelope ID")
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let client = Client::open_existing(database_path, protector)?;
    if client.pinned_identity(&peer_fingerprint)?.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "requested peer fingerprint is not pinned in this profile",
        )
        .into());
    }
    let mut store = Store::open(database_path)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let adapter = runtime
        .block_on(TcpPeerAdapter::connect(connect, MAX_ENVELOPE_BYTES))
        .map_err(|error| io::Error::other(format!("{error:?}")))?;
    let cancellation = CancellationToken::new();
    let result = runtime.block_on(tokio::time::timeout(
        NODE_SESSION_TIMEOUT,
        client.with_pinned_identity(&peer_fingerprint, |identity, pinned| async move {
            send_courier_once(
                &adapter,
                identity,
                pinned,
                &mut store,
                EnvelopeId::new(local_envelope_id),
                &cancellation,
            )
            .await
        }),
    ))??;
    let result = result.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "requested peer fingerprint is no longer pinned",
        )
    })??;
    print_forward_result(result, json);
    Ok(())
}

fn print_forward_result(result: CourierSendResult, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "command": "node_forward_once",
                "state": "accepted_by_pinned_peer",
                "source_local_envelope_id": super::hex(&result.source_local_envelope_id),
                "forwarded_envelope_id": super::hex(&result.forwarded_envelope_id),
                "source_sequence": result.source_sequence,
                "bytes_sent": result.bytes_sent,
                "source_consumed_before_transfer": true,
                "recipient_delivery_claimed": false,
            })
        );
    } else {
        println!(
            "Pinned peer accepted {} transferred byte(s); source sequence {} was consumed before send. This does not claim recipient delivery.",
            result.bytes_sent, result.source_sequence
        );
    }
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}
