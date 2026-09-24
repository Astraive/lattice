use clap::Subcommand;

use super::{hex, space_cursor_hex};

#[derive(Debug, Subcommand)]
pub(super) enum SpaceCommand {
    /// Show one bounded page; use --after with the returned cursor to continue.
    List {
        /// Exclusive cursor encoded as 96 hexadecimal characters.
        #[arg(long)]
        after: Option<String>,
    },
}

pub(super) fn print_space_page(page: &lattice_core::RestoredSpacePage, json: bool) {
    let spaces = page
        .spaces()
        .iter()
        .map(|space| {
            serde_json::json!({
                "space_id": hex(space.space_id()),
                "group_reference": hex(space.group_reference()),
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
        }
        if let Some(cursor) = next_cursor {
            println!("Next page cursor: {cursor}");
        }
    }
}
