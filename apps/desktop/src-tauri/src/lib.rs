use std::path::PathBuf;

use directories::BaseDirs;
use lattice_core::{Client, DeviceIdentityInfo, SpaceGenesisCursor};
use lattice_platform::OsKeyringProtector;
use serde::Serialize;

const PROFILE_ID: &str = "default";
const DATABASE_NAME: &str = "lattice.sqlite";

#[derive(Serialize)]
struct DeviceIdentityStatus {
    fingerprint: String,
    public_bundle: String,
    next_author_sequence: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalSpaceSummary {
    space_id: String,
    group_reference: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalSpacePage {
    spaces: Vec<LocalSpaceSummary>,
    next_cursor: Option<String>,
}

fn open_profile() -> Result<(PathBuf, OsKeyringProtector), String> {
    let data_dir = BaseDirs::new()
        .map(|directories| {
            directories
                .data_local_dir()
                .join("Astraive")
                .join("Lattice")
        })
        .ok_or_else(|| "user data directory is unavailable".to_owned())?;
    std::fs::create_dir_all(&data_dir)
        .map_err(|error| format!("create app data directory: {error}"))?;
    let protector = OsKeyringProtector::new(PROFILE_ID).map_err(|error| error.to_string())?;
    Ok((data_dir.join(DATABASE_NAME), protector))
}

fn status_from_client(client: &Client) -> Result<DeviceIdentityStatus, String> {
    let info: DeviceIdentityInfo = client.identity_info();
    Ok(DeviceIdentityStatus {
        fingerprint: hex(&info.fingerprint),
        public_bundle: hex(&info.public_bundle),
        next_author_sequence: client
            .next_author_sequence()
            .map_err(|error| error.to_string())?,
    })
}

#[tauri::command]
fn initialize_device_identity() -> Result<DeviceIdentityStatus, String> {
    let (database_path, protector) = open_profile()?;
    let client =
        Client::open_or_create(database_path, &protector).map_err(|error| error.to_string())?;
    status_from_client(&client)
}

#[tauri::command]
fn get_device_identity() -> Result<DeviceIdentityStatus, String> {
    let (database_path, protector) = open_profile()?;
    let client =
        Client::open_existing(database_path, &protector).map_err(|error| error.to_string())?;
    status_from_client(&client)
}

#[tauri::command]
fn list_local_spaces(after: Option<String>) -> Result<LocalSpacePage, String> {
    let (database_path, protector) = open_profile()?;
    let after = after.map(parse_space_cursor).transpose()?;
    let mut client =
        Client::open_existing(database_path, &protector).map_err(|error| error.to_string())?;
    let page = client
        .restore_space_page(after)
        .map_err(|error| error.to_string())?;
    let spaces = page
        .spaces()
        .iter()
        .map(|space| LocalSpaceSummary {
            space_id: hex(space.space_id()),
            group_reference: hex(space.group_reference()),
        })
        .collect();
    Ok(LocalSpacePage {
        spaces,
        next_cursor: page.next_cursor().map(space_cursor_hex),
    })
}

fn parse_space_cursor(value: String) -> Result<SpaceGenesisCursor, String> {
    let input = value.into_bytes();
    if input.len() != 96 {
        return Err("Space cursor must contain exactly 96 hexadecimal characters".to_owned());
    }
    let mut bytes = [0_u8; 48];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let high = hex_value(input[index * 2])?;
        let low = hex_value(input[index * 2 + 1])?;
        *byte = (high << 4) | low;
    }
    let mut space_id = [0_u8; 16];
    space_id.copy_from_slice(&bytes[..16]);
    let mut group_reference = [0_u8; 32];
    group_reference.copy_from_slice(&bytes[16..]);
    Ok(SpaceGenesisCursor {
        space_id,
        group_reference,
    })
}

fn space_cursor_hex(cursor: SpaceGenesisCursor) -> String {
    let mut bytes = [0_u8; 48];
    bytes[..16].copy_from_slice(&cursor.space_id);
    bytes[16..].copy_from_slice(&cursor.group_reference);
    hex(&bytes)
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("Space cursor contains a non-hexadecimal character".to_owned()),
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

/// Starts the native Lattice desktop process.
///
/// # Panics
///
/// Panics when Tauri cannot initialize the configured application runtime.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            initialize_device_identity,
            get_device_identity,
            list_local_spaces
        ])
        .run(tauri::generate_context!())
        .expect("failed to run the Lattice desktop application");
}
