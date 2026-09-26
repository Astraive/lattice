use std::path::PathBuf;

use clap::Subcommand;

use super::{hex, space_cursor_hex};

#[derive(Debug, Subcommand)]
pub(super) enum SpaceCommand {
    /// Create a locally recoverable one-member MLS Genesis snapshot.
    Create {
        /// RFC 9420 TLS-encoded X.509 certificate vector for this device.
        #[arg(long)]
        credential: PathBuf,
        /// Initial text channel name; specify one or more times.
        #[arg(long = "channel", required = true)]
        channels: Vec<String>,
    },
    /// Import a versioned Welcome bootstrap package into the local protected profile.
    ///
    /// The inviter fingerprint must already be pinned locally. Import validates
    /// the package and persists local MLS/policy state only; it does not contact
    /// relays, deliver to peers, or replay general message history.
    Join {
        /// Path to the raw versioned Welcome bootstrap package bytes.
        #[arg(long)]
        package: PathBuf,
        /// Pinned inviter fingerprint as exactly 64 hexadecimal characters.
        #[arg(long)]
        inviter_fingerprint: String,
        /// Path to the RFC 9420 TLS-encoded X.509 credential vector.
        #[arg(long)]
        credential: PathBuf,
    },
    /// Restore one locally persisted Space Genesis snapshot by its identifiers.
    ///
    /// Restoration verifies the local signed Genesis and protected MLS snapshot;
    /// it does not establish remote membership or contact the network.
    Restore {
        /// Random 16-byte Space ID as exactly 32 hexadecimal characters.
        #[arg(long)]
        space_id: String,
        /// 32-byte MLS group reference as exactly 64 hexadecimal characters.
        #[arg(long)]
        group_reference: String,
    },
    /// Create a new one-member recovery generation from a local snapshot.
    ///
    /// This preserves the Space ID and channel descriptors but resets membership
    /// to the local authorized administrator; it does not contact the network.
    Recover {
        /// Random 16-byte Space ID as exactly 32 hexadecimal characters.
        #[arg(long)]
        space_id: String,
        /// 32-byte prior MLS group reference as exactly 64 hexadecimal characters.
        #[arg(long)]
        group_reference: String,
        /// RFC 9420 TLS-encoded X.509 credential vector for this device.
        #[arg(long)]
        credential: PathBuf,
    },
    /// Show one bounded page of locally persisted Spaces; each result is restored and verified.
    /// Use --after with the returned cursor to continue.
    List {
        /// Exclusive cursor encoded as 96 hexadecimal characters.
        #[arg(long)]
        after: Option<String>,
    },
    /// Read one bounded page of the encrypted local text-message cache.
    ///
    /// The device-local cache may include messages accepted through `sync
    /// fetch-once`; it is not a complete transcript. Outbox state is local
    /// and does not prove recipient delivery.
    History {
        /// Random 16-byte Space ID as exactly 32 hexadecimal characters.
        #[arg(long)]
        space_id: String,
        /// 32-byte MLS group reference as exactly 64 hexadecimal characters.
        #[arg(long)]
        group_reference: String,
        /// Random 16-byte channel ID as exactly 32 hexadecimal characters.
        #[arg(long)]
        channel_id: String,
    },
    /// Search the full bounded local text cache without contacting the network.
    Search {
        /// Random 16-byte Space ID as exactly 32 hexadecimal characters.
        #[arg(long)]
        space_id: String,
        /// 32-byte MLS group reference as exactly 64 hexadecimal characters.
        #[arg(long)]
        group_reference: String,
        /// Random 16-byte channel ID as exactly 32 hexadecimal characters.
        #[arg(long)]
        channel_id: String,
        /// Non-empty Unicode case-insensitive substring query.
        #[arg(long)]
        query: String,
    },
    /// Queue an authorized immutable edit to a locally authored message.
    ///
    /// The edit and encrypted local cached body are committed locally; no
    /// forwarding or recipient delivery is implied.
    Edit {
        /// Random 16-byte Space ID as exactly 32 hexadecimal characters.
        #[arg(long)]
        space_id: String,
        /// 32-byte MLS group reference as exactly 64 hexadecimal characters.
        #[arg(long)]
        group_reference: String,
        /// Path to the RFC 9420 TLS-encoded X.509 credential vector.
        #[arg(long)]
        credential: PathBuf,
        /// Random 16-byte channel ID as exactly 32 hexadecimal characters.
        #[arg(long)]
        channel_id: String,
        /// 32-byte immutable ID of the authored message to edit.
        #[arg(long)]
        target_message_id: String,
        /// Replacement text to queue.
        #[arg(long)]
        text: String,
    },
}

pub(super) fn channel_summaries(
    reducer: &lattice_core::space::SpaceReducer,
) -> Vec<serde_json::Value> {
    reducer
        .policy()
        .map(|policy| {
            policy
                .channels
                .iter()
                .map(|channel| {
                    let channel_type = match channel.channel_type {
                        lattice_core::space::ChannelType::Text => "text",
                        lattice_core::space::ChannelType::Announcement => "announcement",
                        lattice_core::space::ChannelType::Voice => "voice",
                    };
                    serde_json::json!({
                        "id": hex(&channel.id),
                        "name": channel.name,
                        "type": channel_type,
                        "archived": channel.archived,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn print_space_page(page: &lattice_core::RestoredSpacePage, json: bool) {
    let spaces = page
        .spaces()
        .iter()
        .map(|space| {
            serde_json::json!({
                "space_id": hex(space.space_id()),
                "group_reference": hex(space.group_reference()),
                "channels": channel_summaries(space.reducer()),
            })
        })
        .collect::<Vec<_>>();
    let next_cursor = space_cursor_hex(page.next_cursor());
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "command": "space_list",
                "spaces": spaces,
                "next_cursor": next_cursor,
            })
        );
    } else if page.spaces().is_empty() {
        println!("No locally recoverable Spaces.");
    } else {
        for space in page.spaces() {
            println!(
                "Space {} (MLS group {})",
                hex(space.space_id()),
                hex(space.group_reference())
            );
            for channel in channel_summaries(space.reducer()) {
                println!(
                    "  Channel {} ({}, type: {}, archived: {})",
                    channel["id"].as_str().unwrap_or_default(),
                    channel["name"].as_str().unwrap_or_default(),
                    channel["type"].as_str().unwrap_or_default(),
                    channel["archived"].as_bool().unwrap_or(false)
                );
            }
        }
        if let Some(cursor) = next_cursor {
            println!("Next page cursor: {cursor}");
        }
    }
}
fn outbox_state_name(state: Option<lattice_core::OutboxState>) -> Option<&'static str> {
    state.map(|state| match state {
        lattice_core::OutboxState::Queued => "queued",
        lattice_core::OutboxState::Forwarded => "forwarded",
        lattice_core::OutboxState::Delivered => "delivered",
        lattice_core::OutboxState::Failed => "failed",
    })
}

fn message_json(message: &lattice_core::LocalTextMessageRecord) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "event_id": hex(&message.event_id),
        "channel_id": hex(&message.channel_id),
        "author_id": hex(&message.author_id),
        "author_sequence": message.author_sequence,
        "lamport": message.lamport,
        "content": message.content,
        "outbox_state": outbox_state_name(message.outbox_state),
    })
}

pub(super) fn print_space_history(
    space_id: &[u8; 16],
    group_reference: &[u8; 32],
    channel_id: &[u8; 16],
    messages: &[lattice_core::LocalTextMessageRecord],
    json: bool,
) {
    if json {
        let messages = messages.iter().map(message_json).collect::<Vec<_>>();
        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "command": "space_history",
                "space_id": hex(space_id),
                "group_reference": hex(group_reference),
                "channel_id": hex(channel_id),
                "source": "encrypted_local_text_cache",
                "outbox_state_source": "local_outbox_record",
                "recipient_delivery_claimed": false,
                "network_contacted": false,
                "messages": messages,
            })
        );
    } else if messages.is_empty() {
        println!(
            "No locally retained text messages for channel {}.",
            hex(channel_id)
        );
    } else {
        println!(
            "Recent locally retained text messages for channel {}:",
            hex(channel_id)
        );
        for message in messages {
            let state = outbox_state_name(message.outbox_state).unwrap_or("retained locally");
            println!(
                "{} [{state}] {}",
                hex(&message.event_id),
                message.content.escape_default()
            );
        }
        println!("No synchronized or incoming history was loaded; no network contact was made.");
        println!(
            "Outbox states are local records; a destination-receipt state is not independently verified here."
        );
    }
}

pub(super) fn space_search_json(
    space_id: &[u8; 16],
    group_reference: &[u8; 32],
    channel_id: &[u8; 16],
    query: &str,
    result: &lattice_core::LocalTextMessageSearchResult,
) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "command": "space_search",
        "space_id": hex(space_id),
        "group_reference": hex(group_reference),
        "channel_id": hex(channel_id),
        "query": query,
        "source": "encrypted_local_text_cache",
        "network_contacted": false,
        "total_matches": result.total_matches,
        "scanned_messages": result.scanned_messages,
        "returned_matches": result.messages.len(),
        "messages": result.messages.iter().map(message_json).collect::<Vec<_>>(),
    })
}

pub(super) fn print_space_search(
    space_id: &[u8; 16],
    group_reference: &[u8; 32],
    channel_id: &[u8; 16],
    query: &str,
    result: &lattice_core::LocalTextMessageSearchResult,
    json: bool,
) {
    if json {
        println!(
            "{}",
            space_search_json(space_id, group_reference, channel_id, query, result)
        );
        return;
    }
    println!(
        "{} matching message(s) among {} locally retained messages; showing {} newest matches.",
        result.total_matches,
        result.scanned_messages,
        result.messages.len()
    );
    for message in &result.messages {
        let state = outbox_state_name(message.outbox_state).unwrap_or("retained locally");
        println!(
            "{} [{state}] {}",
            hex(&message.event_id),
            message.content.escape_default()
        );
    }
    println!("Search used the encrypted local cache; no network contact was made.");
}
