use std::{error::Error, path::Path};

use clap::Subcommand;
use lattice_core::{Client, CoreError};
use lattice_platform::OsKeyringProtector;
use lattice_storage::{MAX_OUTBOX_PAGE_SIZE, OutboxState, Store};

#[derive(Debug, Subcommand)]
pub(super) enum SyncCommand {
    /// Inspect locally stored pending events and outbox state; does not run synchronization.
    Status,
}

pub(super) fn execute(
    command: &SyncCommand,
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    match command {
        SyncCommand::Status => print_status(database_path, protector, json),
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
