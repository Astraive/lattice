use lattice_relay::settings::{add_relay, list_relays, remove_relay};
use serde::Serialize;

use super::profile;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RelayListStatus {
    relay_urls: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RelayMutationStatus {
    relay_url: String,
    changed: bool,
}

fn settings_dir() -> Result<std::path::PathBuf, String> {
    Ok(profile::data_dir()?.join("relays"))
}

/// List optional relay URLs saved in this local profile; performs no network request.
#[tauri::command]
pub(crate) fn list_local_relays() -> Result<RelayListStatus, String> {
    let relay_urls = list_relays(&settings_dir()?).map_err(|error| error.to_string())?;
    Ok(RelayListStatus { relay_urls })
}

/// Save one secure relay URL in this local profile without connecting to it.
#[tauri::command]
pub(crate) fn add_local_relay(url: String) -> Result<RelayMutationStatus, String> {
    let changed = add_relay(&settings_dir()?, &url).map_err(|error| error.to_string())?;
    Ok(RelayMutationStatus {
        relay_url: url,
        changed,
    })
}

/// Remove one exact relay URL from this local profile without contacting it.
#[tauri::command]
pub(crate) fn remove_local_relay(url: String) -> Result<RelayMutationStatus, String> {
    let changed = remove_relay(&settings_dir()?, &url).map_err(|error| error.to_string())?;
    Ok(RelayMutationStatus {
        relay_url: url,
        changed,
    })
}
