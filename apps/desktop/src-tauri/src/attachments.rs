use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use fs4::fs_std::FileExt as _;
use lattice_core::Client;
use lattice_files::{AttachmentManifest, MAX_FILE_SIZE};
use serde::Serialize;
use tauri_plugin_dialog::DialogExt as _;

use super::{encoding, profile};

const MAX_DESKTOP_ATTACHMENT_FILE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_DESKTOP_ATTACHMENT_CACHE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_DESKTOP_ATTACHMENT_CACHE_FILES: usize = 64;
static NEXT_UPLOAD_ID: AtomicU64 = AtomicU64::new(1);

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

    use super::{read_cached_filename, stage_source_file};

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
}
