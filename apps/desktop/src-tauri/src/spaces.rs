use lattice_core::Client;
use serde::Serialize;

use super::{encoding, profile};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalSpaceSummary {
    space_id: String,
    group_reference: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LocalSpacePage {
    spaces: Vec<LocalSpaceSummary>,
    next_cursor: Option<String>,
}

// Tauri decodes command arguments into owned strings.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub(crate) fn list_local_spaces(after: Option<String>) -> Result<LocalSpacePage, String> {
    let after = after
        .as_deref()
        .map(encoding::parse_space_cursor)
        .transpose()?;
    let (database_path, protector) = profile::open_profile()?;
    let mut client =
        Client::open_existing(database_path, &protector).map_err(|error| error.to_string())?;
    let page = client
        .restore_space_page(after)
        .map_err(|error| error.to_string())?;
    let spaces = page
        .spaces()
        .iter()
        .map(|space| LocalSpaceSummary {
            space_id: encoding::hex(space.space_id()),
            group_reference: encoding::hex(space.group_reference()),
        })
        .collect();
    Ok(LocalSpacePage {
        spaces,
        next_cursor: page.next_cursor().map(encoding::space_cursor_hex),
    })
}
