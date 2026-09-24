use std::path::PathBuf;

use directories::BaseDirs;
use lattice_core::{Client, DeviceIdentityInfo};
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
            get_device_identity
        ])
        .run(tauri::generate_context!())
        .expect("failed to run the Lattice desktop application");
}
