use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use fs4::fs_std::FileExt as _;
use lattice_core::Client;
use lattice_files::{
    AttachmentManifest, AttachmentStagingLimits, AttachmentStagingStore, MAX_FILE_SIZE,
};
use lattice_node::sync::{
    AttachmentReceiveResult, AttachmentSendResult, AuthenticatedAttachmentError,
    receive_authenticated_attachment_once, send_authenticated_attachment_once,
};
use lattice_platform::MAX_ENVELOPE_BYTES;
use lattice_transport::{TcpPeerAdapter, TcpPeerListener};
use serde::Serialize;
use tauri_plugin_dialog::{DialogExt as _, MessageDialogButtons};
use tokio_util::sync::CancellationToken;

use super::{encoding, profile};

const MAX_DESKTOP_ATTACHMENT_FILE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_DESKTOP_ATTACHMENT_CACHE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_DESKTOP_ATTACHMENT_CACHE_FILES: usize = 64;
const MAX_DESKTOP_ATTACHMENT_STAGING_BYTES: u64 = 512 * 1024 * 1024;
const MAX_DESKTOP_ATTACHMENT_STAGING_FILES: usize = 64;
const DESKTOP_ATTACHMENT_RETENTION: Duration = Duration::from_hours(168);
const ATTACHMENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const ATTACHMENT_ACCEPT_TIMEOUT: Duration = Duration::from_mins(5);
const ATTACHMENT_SESSION_TIMEOUT: Duration = Duration::from_mins(30);
static NEXT_UPLOAD_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)] // Reports independent transfer facts, not a single state.
pub(crate) struct AttachmentTransferSummary {
    state: &'static str,
    event_id: String,
    authenticated_peer_fingerprint: String,
    file_name: String,
    file_size: u64,
    chunks_transferred: usize,
    integrity_verified: bool,
    exported_locally: bool,
    staging_removed: bool,
    cleanup_warning: Option<String>,
    recipient_delivery_claimed: bool,
    network_contacted: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct QueuedLocalFileAttachment {
    state: &'static str,
    event_id: String,
    file_name: String,
    file_size: u64,
    file_hash: String,
    chunk_count: usize,
    source_retained_locally: bool,
    network_contacted: bool,
    recipient_delivery_claimed: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AttachmentSourceSummary {
    hash: String,
    name: String,
    size: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AttachmentCacheStatus {
    sources: Vec<AttachmentSourceSummary>,
    stored_bytes: u64,
    stored_files: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AttachmentSourceRemoval {
    file_hash: String,
    removed: bool,
}

// Tauri decodes command arguments into owned strings.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub(crate) async fn queue_local_file_attachment(
    app: tauri::AppHandle,
    space_id_hex: String,
    group_reference_hex: String,
    credential_vector_hex: String,
    channel_id_hex: String,
) -> Result<Option<QueuedLocalFileAttachment>, String> {
    let space_id = encoding::parse_fixed_hex::<16>(&space_id_hex, "Space ID")?;
    let group_reference =
        encoding::parse_fixed_hex::<32>(&group_reference_hex, "MLS group reference")?;
    let channel_id = encoding::parse_fixed_hex::<16>(&channel_id_hex, "channel ID")?;
    let credential_vector = encoding::parse_hex_bytes(
        &credential_vector_hex,
        "RFC 9420 X.509 credential vector",
        lattice_core::MAX_SPACE_CREDENTIAL_BYTES,
    )?;
    let Some(selected_file) = app.dialog().file().blocking_pick_file() else {
        return Ok(None);
    };
    let source_path = selected_file
        .into_path()
        .map_err(|error| format!("selected file path is unavailable: {error}"))?;

    tauri::async_runtime::spawn_blocking(move || {
        queue_selected_file(
            &source_path,
            space_id,
            group_reference,
            credential_vector,
            channel_id,
        )
    })
    .await
    .map_err(|error| format!("attachment worker failed: {error}"))?
    .map(Some)
}

/// List profile-local attachment sources without exposing filesystem paths.
#[tauri::command]
pub(crate) fn list_local_attachment_sources() -> Result<AttachmentCacheStatus, String> {
    let source_dir = profile::data_dir()?.join("attachments").join("outgoing");
    create_private_directory(&source_dir)?;
    let _lock = acquire_cache_lock(&source_dir)?;
    let (stored_bytes, stored_files) = scan_cache(&source_dir)?;
    let entries = fs::read_dir(&source_dir)
        .map_err(|error| format!("list local attachment cache: {error}"))?;
    let mut sources = Vec::with_capacity(stored_files);
    for entry in entries {
        let entry = entry.map_err(|error| format!("read local attachment cache: {error}"))?;
        let path = entry.path();
        if path.extension().is_none_or(|extension| extension != "blob") {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("inspect cached attachment: {error}"))?;
        if !metadata.file_type().is_file() {
            return Err("attachment cache contains an unsafe entry".to_owned());
        }
        let file_hash = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or_else(|| "attachment cache identifier is invalid".to_owned())?
            .to_owned();
        let file_name = read_cached_filename(&path.with_extension("meta"))?;
        sources.push(AttachmentSourceSummary {
            hash: file_hash,
            name: file_name,
            size: metadata.len(),
        });
    }
    sources.sort_unstable_by(|left, right| left.hash.cmp(&right.hash));
    Ok(AttachmentCacheStatus {
        sources,
        stored_bytes,
        stored_files,
    })
}

/// Remove a profile-local source copy; queued manifests remain unchanged.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub(crate) fn remove_local_attachment_source(
    file_hash_hex: String,
) -> Result<AttachmentSourceRemoval, String> {
    let file_hash = encoding::parse_fixed_hex::<32>(&file_hash_hex, "attachment file hash")?;
    let source_dir = profile::data_dir()?.join("attachments").join("outgoing");
    create_private_directory(&source_dir)?;
    let _lock = acquire_cache_lock(&source_dir)?;
    let hash = encoding::hex(&file_hash);
    let path = source_dir.join(format!("{hash}.blob"));
    let removed = match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            fs::remove_file(&path)
                .map_err(|error| format!("remove local attachment source: {error}"))?;
            match fs::remove_file(path.with_extension("meta")) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(format!("remove attachment metadata: {error}")),
            }
            true
        }
        Ok(_) => return Err("attachment cache contains an unsafe entry".to_owned()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(format!("inspect local attachment source: {error}")),
    };
    Ok(AttachmentSourceRemoval {
        file_hash: hash,
        removed,
    })
}
/// Sends one Core-authorized manifest to an already pinned peer.
///
/// Only the content-addressed local source is opened. The manifest is re-read
/// and compared before transfer; no destination identity is learned or pinned
/// automatically.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub(crate) async fn send_authorized_attachment_once(
    connect_address: String,
    space_id_hex: String,
    group_reference_hex: String,
    event_id_hex: String,
    peer_fingerprint_hex: String,
) -> Result<AttachmentTransferSummary, String> {
    let target = parse_attachment_target(
        &connect_address,
        &space_id_hex,
        &group_reference_hex,
        &event_id_hex,
        &peer_fingerprint_hex,
    )?;
    tauri::async_runtime::spawn_blocking(move || send_attachment_blocking(target))
        .await
        .map_err(|error| format!("attachment send worker failed: {error}"))?
}

/// Receives one locally authorized manifest after pinned authentication and an
/// explicit native consent prompt, then exports only integrity-verified bytes.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub(crate) async fn receive_authorized_attachment_once(
    app: tauri::AppHandle,
    listen_address: String,
    space_id_hex: String,
    group_reference_hex: String,
    event_id_hex: String,
    peer_fingerprint_hex: String,
) -> Result<Option<AttachmentTransferSummary>, String> {
    let target = parse_attachment_target(
        &listen_address,
        &space_id_hex,
        &group_reference_hex,
        &event_id_hex,
        &peer_fingerprint_hex,
    )?;
    tauri::async_runtime::spawn_blocking(move || receive_attachment_blocking(app, target))
        .await
        .map_err(|error| format!("attachment receive worker failed: {error}"))?
}

#[derive(Clone, Copy)]
struct AttachmentTransferTarget {
    endpoint: SocketAddr,
    space_id: [u8; 16],
    group_reference: [u8; 32],
    event_id: [u8; 32],
    peer_fingerprint: [u8; 32],
}

fn parse_attachment_target(
    endpoint: &str,
    space_id_hex: &str,
    group_reference_hex: &str,
    event_id_hex: &str,
    peer_fingerprint_hex: &str,
) -> Result<AttachmentTransferTarget, String> {
    if endpoint.len() > 128 {
        return Err("attachment TCP endpoint is too long".to_owned());
    }
    let endpoint = endpoint
        .parse::<SocketAddr>()
        .map_err(|_| "attachment TCP endpoint must be an IP address and port".to_owned())?;
    if endpoint.port() == 0 {
        return Err("attachment TCP endpoint must use a nonzero port".to_owned());
    }
    let space_id = encoding::parse_fixed_hex::<16>(space_id_hex, "Space ID")?;
    let group_reference =
        encoding::parse_fixed_hex::<32>(group_reference_hex, "MLS group reference")?;
    let event_id = encoding::parse_fixed_hex::<32>(event_id_hex, "attachment event ID")?;
    let peer_fingerprint =
        encoding::parse_fixed_hex::<32>(peer_fingerprint_hex, "peer fingerprint")?;
    Ok(AttachmentTransferTarget {
        endpoint,
        space_id,
        group_reference,
        event_id,
        peer_fingerprint,
    })
}

fn send_attachment_blocking(
    target: AttachmentTransferTarget,
) -> Result<AttachmentTransferSummary, String> {
    let (database_path, protector) = profile::open_profile()?;
    let mut client =
        Client::open_existing(database_path, &protector).map_err(|error| error.to_string())?;
    if client
        .pinned_identity(&target.peer_fingerprint)
        .map_err(|error| format!("validate attachment peer pin: {error}"))?
        .is_none()
    {
        return Err("attachment destination fingerprint is not pinned in this profile".to_owned());
    }
    let created = client
        .restore_space(&target.space_id, &target.group_reference)
        .map_err(|error| format!("restore attachment Space generation: {error}"))?;
    let authorized = created
        .reducer()
        .authorized_attachment_manifest(&target.event_id)
        .ok_or_else(|| "attachment event is not authorized in this Space generation".to_owned())?;
    let manifest = authorized.manifest().clone();
    let event_id = *authorized.event_id();

    let source_dir = profile::data_dir()?.join("attachments").join("outgoing");
    create_private_directory(&source_dir)?;
    let _source_lock = acquire_cache_lock(&source_dir)?;
    let source_path = source_dir.join(format!("{}.blob", encoding::hex(&manifest.file_hash)));
    let mut source = open_verified_source(&source_path, &manifest)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("start attachment transfer runtime: {error}"))?;
    let adapter = runtime
        .block_on(tokio::time::timeout(
            ATTACHMENT_CONNECT_TIMEOUT,
            TcpPeerAdapter::connect(target.endpoint, MAX_ENVELOPE_BYTES),
        ))
        .map_err(|_| "attachment TCP connection timed out".to_owned())?
        .map_err(|error| format!("connect attachment peer: {error:?}"))?;
    let cancellation = CancellationToken::new();
    let transfer_manifest = manifest.clone();
    let transfer = runtime
        .block_on(tokio::time::timeout(
            ATTACHMENT_SESSION_TIMEOUT,
            client.with_pinned_identity(
                &target.peer_fingerprint,
                |identity, pinned_peer| async move {
                    send_authenticated_attachment_once(
                        &adapter,
                        identity,
                        pinned_peer,
                        event_id,
                        &transfer_manifest,
                        &mut source,
                        |peer, requested_event, requested_manifest| {
                            peer.fingerprint() == target.peer_fingerprint
                                && requested_event == &event_id
                                && requested_manifest == &transfer_manifest
                        },
                        &cancellation,
                    )
                    .await
                },
            ),
        ))
        .map_err(|_| "authenticated attachment session timed out".to_owned())?
        .map_err(|error| format!("load pinned attachment identity: {error}"))?
        .ok_or_else(|| "attachment destination pin is no longer present".to_owned())?
        .map_err(|error| format_attachment_error(&error))?;
    Ok(send_transfer_summary(&manifest, target.event_id, transfer))
}

#[allow(clippy::too_many_lines)] // Consent, transfer, and export ordering is security-sensitive.
fn receive_attachment_blocking(
    app: tauri::AppHandle,
    target: AttachmentTransferTarget,
) -> Result<Option<AttachmentTransferSummary>, String> {
    let (database_path, protector) = profile::open_profile()?;
    let mut client =
        Client::open_existing(database_path, &protector).map_err(|error| error.to_string())?;
    if client
        .pinned_identity(&target.peer_fingerprint)
        .map_err(|error| format!("validate attachment peer pin: {error}"))?
        .is_none()
    {
        return Err("attachment sender fingerprint is not pinned in this profile".to_owned());
    }
    let created = client
        .restore_space(&target.space_id, &target.group_reference)
        .map_err(|error| format!("restore attachment Space generation: {error}"))?;
    let authorized = created
        .reducer()
        .authorized_attachment_manifest(&target.event_id)
        .ok_or_else(|| "attachment event is not authorized in this Space generation".to_owned())?;
    let manifest = authorized.manifest().clone();
    let event_id = *authorized.event_id();
    let file_name = lattice_files::sanitize_filename_for_display(&manifest.filename);
    let Some(export_path) = app
        .dialog()
        .file()
        .set_file_name(&file_name)
        .blocking_save_file()
    else {
        return Ok(None);
    };
    let export_path = export_path
        .into_path()
        .map_err(|error| format!("selected export path is unavailable: {error}"))?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("start attachment transfer runtime: {error}"))?;
    let listener = runtime
        .block_on(TcpPeerListener::bind(target.endpoint, MAX_ENVELOPE_BYTES))
        .map_err(|error| format!("listen for pinned attachment sender: {error:?}"))?;
    let (adapter, _remote_address) = runtime
        .block_on(tokio::time::timeout(
            ATTACHMENT_ACCEPT_TIMEOUT,
            listener.accept(),
        ))
        .map_err(|_| "no attachment sender connected before the listener timed out".to_owned())?
        .map_err(|error| format!("accept attachment sender: {error:?}"))?;

    let staging_store = attachment_staging_store()?;
    staging_store
        .cleanup_expired()
        .map_err(|error| format!("clean expired attachment staging: {error}"))?;
    let staging_file = staging_store
        .open(&manifest, &event_id)
        .map_err(|error| format!("open resumable attachment staging: {error}"))?;
    let transfer_id = staging_file.transfer_id();
    let mut receiver = lattice_files::StreamedAttachmentReceiver::new(
        manifest.clone(),
        MAX_DESKTOP_ATTACHMENT_FILE_BYTES.min(MAX_FILE_SIZE),
        staging_file,
    )
    .map_err(|error| format!("initialize attachment receiver: {error}"))?;
    let transfer_manifest = manifest.clone();
    let cancellation = CancellationToken::new();
    let receiver_ref = &mut receiver;
    let transfer = runtime.block_on(tokio::time::timeout(
        ATTACHMENT_SESSION_TIMEOUT,
        client.with_pinned_identity(
            &target.peer_fingerprint,
            |identity, pinned_peer| async move {
                receive_authenticated_attachment_once(
                    &adapter,
                    identity,
                    pinned_peer,
                    event_id,
                    &transfer_manifest,
                    receiver_ref,
                    |peer, offered_event, offered_manifest| {
                        peer.fingerprint() == target.peer_fingerprint
                            && offered_event == &event_id
                            && offered_manifest == &transfer_manifest
                    },
                    |peer, received_manifest| {
                        app.dialog()
                            .message(format!(
                                "Receive {} ({} bytes)?\n\nPinned peer: {}\nSpace event: {}\n\nThe file will be exported only after integrity verification.",
                                lattice_files::sanitize_filename_for_display(
                                    &received_manifest.filename
                                ),
                                received_manifest.file_size,
                                encoding::hex(&peer.fingerprint()),
                                encoding::hex(&event_id),
                            ))
                            .title("Accept attachment transfer")
                            .buttons(MessageDialogButtons::OkCancel)
                            .blocking_show()
                    },
                    &cancellation,
                )
                .await
            },
        ),
    ));
    let transfer = match transfer {
        Err(_) => return Err("authenticated attachment session timed out".to_owned()),
        Ok(Err(error)) => return Err(format!("load pinned attachment identity: {error}")),
        Ok(Ok(None)) => return Err("attachment sender pin is no longer present".to_owned()),
        Ok(Ok(Some(Ok(transfer)))) => transfer,
        Ok(Ok(Some(Err(error)))) => {
            if matches!(error, AuthenticatedAttachmentError::TransferRejected) {
                drop(receiver);
                let _ = staging_store.remove(transfer_id);
            }
            return Err(format_attachment_error(&error));
        }
    };

    let export_cleanup_warning = export_verified_attachment(&mut receiver, &export_path)?;
    drop(receiver);
    let (staging_removed, staging_cleanup_warning) = match staging_store.remove(transfer_id) {
        Ok(removed) => (removed, None),
        Err(error) => (
            false,
            Some(format!("verified staging cleanup failed: {error}")),
        ),
    };
    let cleanup_warning = match (export_cleanup_warning, staging_cleanup_warning) {
        (Some(export_warning), Some(staging_warning)) => {
            Some(format!("{export_warning}; {staging_warning}"))
        }
        (Some(warning), None) | (None, Some(warning)) => Some(warning),
        (None, None) => None,
    };
    Ok(Some(receive_transfer_summary(
        &manifest,
        target.event_id,
        transfer,
        staging_removed,
        cleanup_warning,
    )))
}

fn attachment_staging_store() -> Result<AttachmentStagingStore, String> {
    let limits = AttachmentStagingLimits::new(
        MAX_DESKTOP_ATTACHMENT_FILE_BYTES.min(MAX_FILE_SIZE),
        MAX_DESKTOP_ATTACHMENT_STAGING_BYTES,
        MAX_DESKTOP_ATTACHMENT_STAGING_FILES,
        DESKTOP_ATTACHMENT_RETENTION,
    )
    .map_err(|error| format!("configure attachment staging limits: {error}"))?;
    AttachmentStagingStore::new(
        profile::data_dir()?.join("attachments").join("incoming"),
        limits,
    )
    .map_err(|error| format!("open private attachment staging store: {error}"))
}

fn export_verified_attachment<S>(
    receiver: &mut lattice_files::StreamedAttachmentReceiver<S>,
    destination: &Path,
) -> Result<Option<String>, String>
where
    S: Read + Write + Seek,
{
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let (temporary_path, mut temporary_file) = loop {
        let id = NEXT_UPLOAD_ID.fetch_add(1, Ordering::Relaxed);
        let temporary_path = parent.join(format!(
            ".lattice-attachment-export-{}-{id}.part",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match options.open(&temporary_path) {
            Ok(file) => break (temporary_path, file),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(format!("create private attachment export staging: {error}"));
            }
        }
    };
    let copy_result = receiver
        .copy_verified_to(&mut temporary_file)
        .and_then(|()| {
            temporary_file
                .sync_all()
                .map_err(lattice_files::AttachmentError::from)
        });
    drop(temporary_file);
    if let Err(error) = copy_result {
        let _ = fs::remove_file(&temporary_path);
        return Err(format!(
            "export verified attachment; private staging remains available for retry: {error}"
        ));
    }
    if let Err(error) = fs::hard_link(&temporary_path, destination) {
        let _ = fs::remove_file(&temporary_path);
        return Err(format!(
            "commit verified export without overwriting existing data; private staging remains available for retry: {error}"
        ));
    }
    match fs::remove_file(&temporary_path) {
        Ok(()) => Ok(None),
        Err(error) => Ok(Some(format!(
            "verified export succeeded but temporary output cleanup failed: {error}"
        ))),
    }
}

fn open_verified_source(path: &Path, expected: &AttachmentManifest) -> Result<File, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "retained attachment source is unavailable")?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err("retained attachment source is not a regular file".to_owned());
    }
    if metadata.len() != expected.file_size {
        return Err("retained attachment source size does not match its manifest".to_owned());
    }
    let mut source =
        File::open(path).map_err(|error| format!("open retained attachment source: {error}"))?;
    let actual = AttachmentManifest::from_reader(&mut source, &expected.filename, None)
        .map_err(|error| format!("verify retained attachment source: {error}"))?;
    if &actual != expected {
        return Err("retained attachment source does not match its authorized manifest".to_owned());
    }
    source
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("rewind retained attachment source: {error}"))?;
    Ok(source)
}

fn format_attachment_error(error: &AuthenticatedAttachmentError) -> String {
    format!("authenticated attachment transfer failed: {error}")
}

fn send_transfer_summary(
    manifest: &AttachmentManifest,
    event_id: [u8; 32],
    result: AttachmentSendResult,
) -> AttachmentTransferSummary {
    AttachmentTransferSummary {
        state: "peer_integrity_verified",
        event_id: encoding::hex(&event_id),
        authenticated_peer_fingerprint: encoding::hex(&result.authenticated_peer.fingerprint()),
        file_name: manifest.filename.clone(),
        file_size: manifest.file_size,
        chunks_transferred: result.chunks_sent,
        integrity_verified: result.receiver_verified_complete,
        exported_locally: false,
        staging_removed: false,
        cleanup_warning: None,
        recipient_delivery_claimed: false,
        network_contacted: true,
    }
}

fn receive_transfer_summary(
    manifest: &AttachmentManifest,
    event_id: [u8; 32],
    result: AttachmentReceiveResult,
    staging_removed: bool,
    cleanup_warning: Option<String>,
) -> AttachmentTransferSummary {
    AttachmentTransferSummary {
        state: "received_and_exported",
        event_id: encoding::hex(&event_id),
        authenticated_peer_fingerprint: encoding::hex(&result.authenticated_peer.fingerprint()),
        file_name: manifest.filename.clone(),
        file_size: manifest.file_size,
        chunks_transferred: result.chunks_received,
        integrity_verified: result.verified_complete,
        exported_locally: true,
        staging_removed,
        cleanup_warning,
        recipient_delivery_claimed: false,
        network_contacted: true,
    }
}

fn queue_selected_file(
    source_path: &Path,
    space_id: [u8; 16],
    group_reference: [u8; 32],
    credential_vector: Vec<u8>,
    channel_id: [u8; 16],
) -> Result<QueuedLocalFileAttachment, String> {
    let source_dir = profile::data_dir()?.join("attachments").join("outgoing");
    let (manifest, _) = stage_source_file(source_path, &source_dir)?;
    let (database_path, protector) = profile::open_profile()?;
    let mut client =
        Client::open_existing(database_path, &protector).map_err(|error| error.to_string())?;
    let queued = client
        .queue_file_manifest_from_x509_credential(
            &space_id,
            &group_reference,
            credential_vector,
            channel_id,
            &manifest,
        )
        .map_err(|error| error.to_string())?;
    Ok(QueuedLocalFileAttachment {
        state: "queued_locally",
        event_id: encoding::hex(queued.event_id()),
        file_name: manifest.filename,
        file_size: manifest.file_size,
        file_hash: encoding::hex(&manifest.file_hash),
        chunk_count: manifest.chunk_hashes.len(),
        source_retained_locally: true,
        network_contacted: false,
        recipient_delivery_claimed: false,
    })
}

fn stage_source_file(
    source_path: &Path,
    source_dir: &Path,
) -> Result<(AttachmentManifest, bool), String> {
    let source_metadata =
        fs::metadata(source_path).map_err(|_| "selected file could not be inspected".to_owned())?;
    if !source_metadata.is_file() {
        return Err("selected attachment is not a regular file".to_owned());
    }
    if source_metadata.len() > MAX_DESKTOP_ATTACHMENT_FILE_BYTES.min(MAX_FILE_SIZE) {
        return Err(format!(
            "desktop attachments are limited to {MAX_DESKTOP_ATTACHMENT_FILE_BYTES} bytes"
        ));
    }

    create_private_directory(source_dir)?;
    let _lock = acquire_cache_lock(source_dir)?;
    let (mut cached_bytes, mut cached_files) = scan_cache(source_dir)?;
    if cached_files >= MAX_DESKTOP_ATTACHMENT_CACHE_FILES
        || cached_bytes.saturating_add(source_metadata.len()) > MAX_DESKTOP_ATTACHMENT_CACHE_BYTES
    {
        return Err("desktop attachment cache quota is full".to_owned());
    }

    let temporary_path = create_staged_copy(source_path, source_dir)?;

    let filename = source_path.file_name().map_or_else(
        || "attachment".to_owned(),
        |name| name.to_string_lossy().into_owned(),
    );
    let mut staged = File::open(&temporary_path)
        .map_err(|error| format!("open local attachment staging: {error}"))?;
    let manifest = AttachmentManifest::from_reader(&mut staged, &filename, None)
        .map_err(|error| format!("attachment is invalid: {error}"))?;
    let final_path = source_dir.join(format!("{}.blob", encoding::hex(&manifest.file_hash)));
    match fs::symlink_metadata(&final_path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                let _ = fs::remove_file(&temporary_path);
                return Err("attachment cache contains an unsafe entry".to_owned());
            }
            let mut existing = File::open(&final_path)
                .map_err(|error| format!("open cached attachment: {error}"))?;
            let existing_manifest =
                AttachmentManifest::from_reader(&mut existing, &manifest.filename, None)
                    .map_err(|_| "cached attachment failed its integrity check".to_owned())?;
            if existing_manifest.file_hash != manifest.file_hash
                || existing_manifest.file_size != manifest.file_size
            {
                let _ = fs::remove_file(&temporary_path);
                return Err("cached attachment failed its integrity check".to_owned());
            }
            fs::remove_file(&temporary_path)
                .map_err(|error| format!("remove duplicate attachment staging: {error}"))?;
            Ok((manifest, false))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            cached_bytes = cached_bytes.saturating_add(manifest.file_size);
            cached_files = cached_files.saturating_add(1);
            if cached_bytes > MAX_DESKTOP_ATTACHMENT_CACHE_BYTES
                || cached_files > MAX_DESKTOP_ATTACHMENT_CACHE_FILES
            {
                let _ = fs::remove_file(&temporary_path);
                return Err("desktop attachment cache quota is full".to_owned());
            }
            fs::rename(&temporary_path, &final_path)
                .map_err(|error| format!("retain local attachment source: {error}"))?;
            if let Err(error) =
                write_cached_filename(&final_path.with_extension("meta"), &manifest.filename)
            {
                let _ = fs::remove_file(&final_path);
                return Err(error);
            }
            Ok((manifest, true))
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary_path);
            Err(format!("inspect cached attachment: {error}"))
        }
    }
}

fn create_staged_copy(source_path: &Path, source_dir: &Path) -> Result<PathBuf, String> {
    loop {
        let id = NEXT_UPLOAD_ID.fetch_add(1, Ordering::Relaxed);
        let path = source_dir.join(format!(".upload-{}-{id}.part", std::process::id()));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut destination) => {
                let source = File::open(source_path)
                    .map_err(|_| "selected file could not be opened".to_owned())?;
                let copied = io::copy(
                    &mut source.take(MAX_DESKTOP_ATTACHMENT_FILE_BYTES.saturating_add(1)),
                    &mut destination,
                )
                .map_err(|error| format!("copy attachment into local staging: {error}"))?;
                if copied > MAX_DESKTOP_ATTACHMENT_FILE_BYTES.min(MAX_FILE_SIZE) {
                    drop(destination);
                    let _ = fs::remove_file(&path);
                    return Err(
                        "selected attachment exceeds the desktop file-size limit".to_owned()
                    );
                }
                destination
                    .sync_all()
                    .map_err(|error| format!("flush local attachment staging: {error}"))?;
                return Ok(path);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("create local attachment staging: {error}")),
        }
    }
}

fn create_private_directory(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|error| format!("create attachment cache: {error}"))?;
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("inspect attachment cache: {error}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("attachment cache directory is unsafe".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("restrict attachment cache permissions: {error}"))?;
    }
    Ok(())
}

fn acquire_cache_lock(source_dir: &Path) -> Result<File, String> {
    let lock_path = source_dir.join(".quota.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
        .map_err(|error| format!("open attachment quota lock: {error}"))?;
    if !lock
        .try_lock_exclusive()
        .map_err(|error| format!("lock attachment cache: {error}"))?
    {
        return Err(
            "attachment cache is busy; retry after the other operation finishes".to_owned(),
        );
    }
    Ok(lock)
}

fn write_cached_filename(path: &Path, file_name: &str) -> Result<(), String> {
    static NEXT_METADATA_ID: AtomicU64 = AtomicU64::new(1);
    let id = NEXT_METADATA_ID.fetch_add(1, Ordering::Relaxed);
    let temporary_path = path.with_extension(format!("meta-{}-{id}.part", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary_path)
        .map_err(|error| format!("create attachment metadata: {error}"))?;
    if let Err(error) = file
        .write_all(file_name.as_bytes())
        .and_then(|()| file.sync_all())
    {
        drop(file);
        let _ = fs::remove_file(&temporary_path);
        return Err(format!("write attachment metadata: {error}"));
    }
    fs::rename(temporary_path, path).map_err(|error| format!("retain attachment metadata: {error}"))
}

fn read_cached_filename(path: &Path) -> Result<String, String> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok("attachment source".to_owned());
        }
        Err(error) => return Err(format!("open attachment metadata: {error}")),
    };
    let mut bytes = Vec::with_capacity(128);
    Read::take(&mut file, (lattice_files::MAX_FILENAME_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read attachment metadata: {error}"))?;
    if bytes.is_empty() || bytes.len() > lattice_files::MAX_FILENAME_BYTES {
        return Err("attachment metadata is invalid".to_owned());
    }
    let file_name = String::from_utf8(bytes)
        .map_err(|_| "attachment metadata is not valid UTF-8".to_owned())?;
    if lattice_files::sanitize_filename_for_display(&file_name) != file_name {
        return Err("attachment metadata contains an unsafe filename".to_owned());
    }
    Ok(file_name)
}

fn scan_cache(source_dir: &Path) -> Result<(u64, usize), String> {
    let entries = fs::read_dir(source_dir)
        .map_err(|error| format!("list local attachment cache: {error}"))?;
    let mut bytes = 0_u64;
    let mut files = 0_usize;
    for entry in entries {
        let entry = entry.map_err(|error| format!("read local attachment cache: {error}"))?;
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "part")
        {
            fs::remove_file(path)
                .map_err(|error| format!("remove interrupted attachment staging: {error}"))?;
            continue;
        }
        if path.extension().is_none_or(|extension| extension != "blob") {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("inspect cached attachment: {error}"))?;
        if !metadata.file_type().is_file() {
            return Err("attachment cache contains an unsafe entry".to_owned());
        }
        bytes = bytes
            .checked_add(metadata.len())
            .ok_or_else(|| "attachment cache byte accounting overflow".to_owned())?;
        files = files
            .checked_add(1)
            .ok_or_else(|| "attachment cache item accounting overflow".to_owned())?;
    }
    if bytes > MAX_DESKTOP_ATTACHMENT_CACHE_BYTES || files > MAX_DESKTOP_ATTACHMENT_CACHE_FILES {
        return Err("attachment cache exceeds its configured quota".to_owned());
    }
    Ok((bytes, files))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::Cursor,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{
        export_verified_attachment, open_verified_source, parse_attachment_target,
        read_cached_filename, stage_source_file,
    };

    #[test]
    fn selected_attachment_is_retained_by_content_hash_and_deduplicated() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "lattice-desktop-attachment-{}-{nonce}",
            std::process::id()
        ));
        let source_dir = root.join("cache");
        fs::create_dir_all(&root).expect("create temporary attachment root");
        let source_path = root.join("proof.bin");
        let content = vec![0x63; lattice_files::CHUNK_SIZE + 17];
        fs::write(&source_path, &content).expect("create selected source");

        let (manifest, stored) =
            stage_source_file(&source_path, &source_dir).expect("stage selected attachment");
        assert!(stored);
        assert_eq!(manifest.filename, "proof.bin");
        assert_eq!(
            manifest.file_size,
            u64::try_from(content.len()).expect("test content length fits u64")
        );
        assert_eq!(manifest.chunk_hashes.len(), 2);
        let source_copy = source_dir.join(format!(
            "{}.blob",
            crate::encoding::hex(&manifest.file_hash)
        ));
        assert_eq!(
            fs::read(&source_copy).expect("read retained source"),
            content
        );

        let (again, stored) =
            stage_source_file(&source_path, &source_dir).expect("deduplicate same content");
        assert!(!stored);
        assert_eq!(again.file_hash, manifest.file_hash);
        assert_eq!(
            manifest.file_hash,
            lattice_files::AttachmentManifest::from_reader(
                &mut Cursor::new(content),
                "proof.bin",
                None
            )
            .expect("rebuild manifest")
            .file_hash
        );
        assert_eq!(
            read_cached_filename(&source_dir.join(format!(
                "{}.meta",
                crate::encoding::hex(&manifest.file_hash)
            )))
            .expect("read cached source name"),
            "proof.bin"
        );

        fs::remove_dir_all(root).expect("remove temporary attachment cache");
    }
    #[test]
    fn attachment_target_requires_literal_socket_and_nonzero_port() {
        let space_id = "11".repeat(16);
        let group_reference = "22".repeat(32);
        let event_id = "33".repeat(32);
        let peer_fingerprint = "44".repeat(32);
        let valid = parse_attachment_target(
            "192.168.1.8:7332",
            &space_id,
            &group_reference,
            &event_id,
            &peer_fingerprint,
        )
        .expect("valid pinned endpoint");
        assert_eq!(valid.endpoint.port(), 7332);
        assert_eq!(valid.peer_fingerprint, [0x44; 32]);

        assert!(
            parse_attachment_target(
                "peer.example:7332",
                &space_id,
                &group_reference,
                &event_id,
                &peer_fingerprint,
            )
            .is_err()
        );
        assert!(
            parse_attachment_target(
                "192.168.1.8:0",
                &space_id,
                &group_reference,
                &event_id,
                &peer_fingerprint,
            )
            .is_err()
        );
    }

    #[test]
    fn changed_cached_source_is_rejected_against_authorized_manifest() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "lattice-desktop-attachment-source-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("create temporary attachment root");
        let source_path = root.join("proof.bin");
        let source_dir = root.join("cache");
        fs::write(&source_path, vec![0x63; 128]).expect("create source bytes");
        let (manifest, _) =
            stage_source_file(&source_path, &source_dir).expect("stage source bytes");
        let cached_path = source_dir.join(format!(
            "{}.blob",
            crate::encoding::hex(&manifest.file_hash)
        ));
        let mut altered = fs::read(&cached_path).expect("read staged source");
        altered[0] ^= 1;
        fs::write(&cached_path, altered).expect("alter staged source");

        assert!(open_verified_source(&cached_path, &manifest).is_err());
        fs::remove_dir_all(root).expect("remove temporary attachment root");
    }

    #[test]
    fn verified_export_is_complete_and_never_overwrites_existing_data() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "lattice-desktop-attachment-export-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("create temporary export directory");
        let content = vec![0x72; lattice_files::CHUNK_SIZE + 19];
        let manifest = lattice_files::AttachmentManifest::from_reader(
            &mut Cursor::new(content.clone()),
            "proof.bin",
            None,
        )
        .expect("build test manifest");
        let mut receiver = lattice_files::StreamedAttachmentReceiver::new(
            manifest,
            lattice_files::MAX_FILE_SIZE,
            Cursor::new(Vec::new()),
        )
        .expect("create streamed receiver");
        receiver.accept().expect("accept test transfer");
        for (index, chunk) in content.chunks(lattice_files::CHUNK_SIZE).enumerate() {
            receiver
                .submit_chunk(index, chunk)
                .expect("submit verified test chunk");
        }

        let destination = root.join("proof.bin");
        assert_eq!(
            export_verified_attachment(&mut receiver, &destination)
                .expect("export verified attachment"),
            None
        );
        assert_eq!(
            fs::read(&destination).expect("read verified export"),
            content
        );

        fs::write(&destination, b"keep existing file").expect("prepare existing destination");
        assert!(export_verified_attachment(&mut receiver, &destination).is_err());
        assert_eq!(
            fs::read(&destination).expect("read preserved destination"),
            b"keep existing file"
        );
        let leftover_parts = fs::read_dir(&root)
            .expect("list export directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "part")
            })
            .count();
        assert_eq!(leftover_parts, 0);
        fs::remove_dir_all(root).expect("remove temporary export directory");
    }
}
