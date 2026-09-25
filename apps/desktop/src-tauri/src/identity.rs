use base64::Engine as _;
use lattice_core::{Client, DeviceIdentityInfo};
use serde::Serialize;

use super::{encoding, profile};

#[derive(Serialize)]
pub(crate) struct DeviceIdentityStatus {
    fingerprint: String,
    public_bundle: String,
    next_author_sequence: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PinnedIdentityStatus {
    fingerprint: String,
    public_bundle: String,
}

fn status_from_client(client: &Client) -> Result<DeviceIdentityStatus, String> {
    let info: DeviceIdentityInfo = client.identity_info();
    Ok(DeviceIdentityStatus {
        fingerprint: encoding::hex(&info.fingerprint),
        public_bundle: encoding::hex(&info.public_bundle),
        next_author_sequence: client
            .next_author_sequence()
            .map_err(|error| error.to_string())?,
    })
}

#[tauri::command]
pub(crate) fn initialize_device_identity() -> Result<DeviceIdentityStatus, String> {
    let (database_path, protector) = profile::open_profile()?;
    let client =
        Client::open_or_create(database_path, &protector).map_err(|error| error.to_string())?;
    status_from_client(&client)
}

#[tauri::command]
pub(crate) fn get_device_identity() -> Result<DeviceIdentityStatus, String> {
    let (database_path, protector) = profile::open_profile()?;
    let client =
        Client::open_existing(database_path, &protector).map_err(|error| error.to_string())?;
    status_from_client(&client)
}

#[tauri::command]
pub(crate) fn get_device_certificate_signing_request() -> Result<String, String> {
    let (database_path, protector) = profile::open_profile()?;
    let client =
        Client::open_existing(database_path, &protector).map_err(|error| error.to_string())?;
    let csr = client
        .certificate_signing_request()
        .map_err(|error| error.to_string())?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(csr);
    let mut pem = String::with_capacity(encoded.len() + 80);
    pem.push_str("-----BEGIN CERTIFICATE REQUEST-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 output is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE REQUEST-----\n");
    Ok(pem)
}

// Tauri decodes command arguments into owned strings.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub(crate) fn pin_peer_identity(
    bundle_hex: String,
    expected_fingerprint_hex: String,
) -> Result<PinnedIdentityStatus, String> {
    let public_bundle = encoding::parse_fixed_hex::<65>(&bundle_hex, "bundle")?;
    let expected_fingerprint =
        encoding::parse_fixed_hex::<32>(&expected_fingerprint_hex, "fingerprint")?;
    let (database_path, protector) = profile::open_profile()?;
    let mut client =
        Client::open_existing(database_path, &protector).map_err(|error| error.to_string())?;
    let pinned = client
        .pin_identity(&public_bundle, expected_fingerprint)
        .map_err(|error| error.to_string())?;
    Ok(PinnedIdentityStatus {
        fingerprint: encoding::hex(&pinned.fingerprint()),
        public_bundle: encoding::hex(&pinned.bundle().to_bytes()),
    })
}

// Tauri decodes command arguments into owned strings.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub(crate) fn get_pinned_identity(
    fingerprint_hex: String,
) -> Result<Option<PinnedIdentityStatus>, String> {
    let fingerprint = encoding::parse_fixed_hex::<32>(&fingerprint_hex, "fingerprint")?;
    let (database_path, protector) = profile::open_profile()?;
    let client =
        Client::open_existing(database_path, &protector).map_err(|error| error.to_string())?;
    let Some(pinned) = client
        .pinned_identity(&fingerprint)
        .map_err(|error| error.to_string())?
    else {
        return Ok(None);
    };
    Ok(Some(PinnedIdentityStatus {
        fingerprint: encoding::hex(&pinned.fingerprint()),
        public_bundle: encoding::hex(&pinned.bundle().to_bytes()),
    }))
}

// Tauri decodes command arguments into owned strings.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub(crate) fn unpin_peer_identity(fingerprint_hex: String) -> Result<bool, String> {
    let fingerprint = encoding::parse_fixed_hex::<32>(&fingerprint_hex, "fingerprint")?;
    let (database_path, protector) = profile::open_profile()?;
    let mut client =
        Client::open_existing(database_path, &protector).map_err(|error| error.to_string())?;
    client
        .unpin_identity(&fingerprint)
        .map_err(|error| error.to_string())
}
