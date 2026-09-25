//! Quota-bounded private disk staging for resumable attachment transfers.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use fs4::fs_std::FileExt;

use crate::{AttachmentError, AttachmentManifest, AttachmentTransferId, MAX_FILE_SIZE};

const LOCK_FILE: &str = ".quota.lock";
const RESERVATION_MAGIC: &[u8; 8] = b"LATSTG1\0";
const RESERVATION_BYTES: u64 = 16;
const MAX_STAGING_RECORDS: usize = 1024;
const MAX_DIRECTORY_ENTRIES: usize = MAX_STAGING_RECORDS * 2 + 1;

/// Caller-selected limits for private attachment staging.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttachmentStagingLimits {
    /// Largest single manifest accepted into this store.
    pub per_file_bytes: u64,
    /// Sum of declared file sizes reserved across partial and completed staging.
    pub total_reserved_bytes: u64,
    /// Maximum number of partial or completed transfers retained at once.
    pub transfer_count: usize,
    /// Inactivity period after which an unexported staging record is removed.
    pub retention: Duration,
}

impl AttachmentStagingLimits {
    /// Construct validated per-file, global, count, and retention limits.
    ///
    /// # Errors
    ///
    /// Returns `InvalidStagingLimits` for zero or out-of-range configuration.
    pub fn new(
        per_file_bytes: u64,
        total_reserved_bytes: u64,
        transfer_count: usize,
        retention: Duration,
    ) -> Result<Self, AttachmentError> {
        if per_file_bytes == 0
            || per_file_bytes > MAX_FILE_SIZE
            || total_reserved_bytes == 0
            || transfer_count == 0
            || transfer_count > MAX_STAGING_RECORDS
            || retention.is_zero()
        {
            return Err(AttachmentError::InvalidStagingLimits);
        }
        Ok(Self {
            per_file_bytes,
            total_reserved_bytes,
            transfer_count,
            retention,
        })
    }
}

/// Summary of staging records removed during expiration and orphan cleanup.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StagingCleanupSummary {
    /// Expired transfers and incomplete orphan records removed.
    pub transfers_removed: usize,
    /// Logical bytes of expired staging or reserved quota released.
    pub bytes_released: u64,
}

/// Persistent quota manager for one caller-provided private staging directory.
///
/// The directory is dedicated to this store. A cross-process advisory lock
/// serializes quota accounting, while each active transfer holds an exclusive
/// lock on its data file. The store reserves each manifest's full declared size
/// before returning a writable file, so sparse files cannot evade global limits.
#[derive(Clone, Debug)]
pub struct AttachmentStagingStore {
    root: PathBuf,
    limits: AttachmentStagingLimits,
}

impl AttachmentStagingStore {
    /// Create or reopen a dedicated private staging directory.
    ///
    /// The caller must choose a private application data directory and use the
    /// same directory after restart to retain resumable chunks. This function
    /// never accepts a user filename as a path component.
    ///
    /// # Errors
    ///
    /// Returns `UnsafeStagingDirectory` for an untrusted root or an I/O error
    /// if the directory cannot be created or inspected.
    pub fn new(
        root: impl AsRef<Path>,
        limits: AttachmentStagingLimits,
    ) -> Result<Self, AttachmentError> {
        let root = root.as_ref();
        create_private_directory(root)?;
        let metadata = fs::symlink_metadata(root)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(AttachmentError::UnsafeStagingDirectory);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(AttachmentError::UnsafeStagingDirectory);
            }
        }
        Ok(Self {
            root: root.to_path_buf(),
            limits,
        })
    }

    /// Reserve bounded disk space for this event-bound manifest and reopen its
    /// resumable data file. Call only after the application has displayed the
    /// authenticated source and manifest size and obtained user consent.
    ///
    /// # Errors
    ///
    /// Returns an attachment validation, quota, transfer-count, busy-store,
    /// staging I/O, or staging metadata error.
    pub fn open(
        &self,
        manifest: &AttachmentManifest,
        event_id: &[u8; 32],
    ) -> Result<ManagedAttachmentFile, AttachmentError> {
        manifest.validate()?;
        if manifest.file_size > self.limits.per_file_bytes {
            return Err(AttachmentError::StagingQuotaExceeded {
                file_size: manifest.file_size,
                limit: self.limits.per_file_bytes,
            });
        }
        let transfer_id = manifest.transfer_id(event_id)?;
        let _global_lock = self.lock_global()?;
        let now = SystemTime::now();
        let usage = self.scan_and_clean_expired(now)?;
        let (data_path, reservation_path) = self.paths(transfer_id);
        let is_new = if let Some(size) = read_reservation(&reservation_path)? {
            if size != manifest.file_size {
                return Err(AttachmentError::StagingMetadataInvalid);
            }
            if size > self.limits.per_file_bytes {
                return Err(AttachmentError::StagingQuotaExceeded {
                    file_size: size,
                    limit: self.limits.per_file_bytes,
                });
            }
            false
        } else {
            if usage.transfers >= self.limits.transfer_count {
                return Err(AttachmentError::StagingTransferLimitExceeded {
                    limit: self.limits.transfer_count,
                });
            }
            let available_bytes = self
                .limits
                .total_reserved_bytes
                .saturating_sub(usage.reserved_bytes);
            if usage.reserved_bytes > self.limits.total_reserved_bytes
                || manifest.file_size > available_bytes
            {
                return Err(AttachmentError::GlobalStagingQuotaExceeded {
                    requested: manifest.file_size,
                    reserved: usage.reserved_bytes,
                    limit: self.limits.total_reserved_bytes,
                });
            }
            write_reservation(&reservation_path, manifest.file_size)?;
            true
        };
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        if !data_path.exists() {
            options.create_new(true);
        }
        let file = match options.open(&data_path) {
            Ok(file) => file,
            Err(error) => {
                if is_new {
                    let _ = fs::remove_file(&reservation_path);
                }
                return Err(error.into());
            }
        };
        if !file.try_lock_exclusive().map_err(AttachmentError::Io)? {
            return Err(AttachmentError::StagingBusy);
        }
        let file_length = file.metadata()?.len();
        if file_length > manifest.file_size {
            return Err(AttachmentError::StagingStoreTooLarge {
                actual: file_length,
                maximum: manifest.file_size,
            });
        }
        Ok(ManagedAttachmentFile {
            file,
            transfer_id,
            maximum_length: manifest.file_size,
        })
    }

    /// Remove expired staged transfers and incomplete orphan records.
    ///
    /// Active transfer files are skipped. Run this periodically from the owning
    /// application and before accepting new transfers; opening a new transfer
    /// also performs an expiration pass before enforcing quotas.
    ///
    /// # Errors
    ///
    /// Returns `StagingBusy` when quota accounting is locked, or an I/O or
    /// metadata error if the directory cannot be safely scanned.
    pub fn cleanup_expired(&self) -> Result<StagingCleanupSummary, AttachmentError> {
        let _global_lock = self.lock_global()?;
        Ok(self.scan_and_clean_expired(SystemTime::now())?.expired)
    }

    /// Remove one transfer's staging data after successful export or explicit
    /// rejection. The active receiver must first be dropped.
    ///
    /// # Errors
    ///
    /// Returns `StagingBusy` for an active transfer, or an I/O or metadata
    /// error when a staging entry cannot be safely removed.
    pub fn remove(&self, transfer_id: AttachmentTransferId) -> Result<bool, AttachmentError> {
        let _global_lock = self.lock_global()?;
        let (data_path, reservation_path) = self.paths(transfer_id);
        let mut removed = false;
        if data_path.exists() {
            let metadata = fs::symlink_metadata(&data_path)?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(AttachmentError::StagingMetadataInvalid);
            }
            let file = OpenOptions::new().read(true).write(true).open(&data_path)?;
            if !file.try_lock_exclusive()? {
                return Err(AttachmentError::StagingBusy);
            }
            file.unlock()?;
            drop(file);
            fs::remove_file(&data_path)?;
            removed = true;
        }
        if reservation_path.exists() {
            fs::remove_file(&reservation_path)?;
            removed = true;
        }
        Ok(removed)
    }

    fn lock_global(&self) -> Result<File, AttachmentError> {
        let path = self.root.join(LOCK_FILE);
        match fs::symlink_metadata(&path) {
            Ok(metadata)
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.len() != 0 =>
            {
                return Err(AttachmentError::StagingMetadataInvalid);
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(path)?;
        if !lock.try_lock_exclusive()? {
            return Err(AttachmentError::StagingBusy);
        }
        Ok(lock)
    }

    fn paths(&self, transfer_id: AttachmentTransferId) -> (PathBuf, PathBuf) {
        let key = transfer_key(transfer_id);
        (
            self.root.join(format!("{key}.part")),
            self.root.join(format!("{key}.reserve")),
        )
    }

    fn scan_and_clean_expired(&self, now: SystemTime) -> Result<StagingUsage, AttachmentError> {
        let mut records = HashMap::<String, StagingRecord>::new();
        let mut entries = 0_usize;
        for entry in fs::read_dir(&self.root)? {
            entries = entries.saturating_add(1);
            if entries > MAX_DIRECTORY_ENTRIES {
                return Err(AttachmentError::StagingDirectoryTooLarge {
                    limit: MAX_DIRECTORY_ENTRIES,
                });
            }
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| AttachmentError::StagingMetadataInvalid)?;
            if name == LOCK_FILE {
                continue;
            }
            let (key, is_data) = if let Some(key) = name.strip_suffix(".part") {
                (key, true)
            } else if let Some(key) = name.strip_suffix(".reserve") {
                (key, false)
            } else {
                return Err(AttachmentError::StagingMetadataInvalid);
            };
            if !valid_transfer_key(key) {
                return Err(AttachmentError::StagingMetadataInvalid);
            }
            let record = records.entry(key.to_owned()).or_default();
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(AttachmentError::StagingMetadataInvalid);
            }
            if is_data {
                record.data_path = Some(path);
                record.modified = Some(metadata.modified()?);
                record.data_length = Some(metadata.len());
            } else {
                record.reservation_path = Some(path);
            }
        }

        let mut usage = StagingUsage::default();
        for (_, record) in records {
            let Some(reservation_path) = record.reservation_path else {
                if let Some(data_path) = record.data_path {
                    let data_length = record
                        .data_length
                        .ok_or(AttachmentError::StagingMetadataInvalid)?;
                    if !remove_if_unlocked(&data_path)? {
                        return Err(AttachmentError::StagingBusy);
                    }
                    usage.expired.transfers_removed += 1;
                    usage.expired.bytes_released =
                        usage.expired.bytes_released.saturating_add(data_length);
                }
                continue;
            };
            let Some(data_path) = record.data_path else {
                let reserved_size = read_reservation(&reservation_path)?
                    .ok_or(AttachmentError::StagingMetadataInvalid)?;
                fs::remove_file(reservation_path)?;
                usage.expired.transfers_removed += 1;
                usage.expired.bytes_released =
                    usage.expired.bytes_released.saturating_add(reserved_size);
                continue;
            };
            let Some(modified) = record.modified else {
                return Err(AttachmentError::StagingMetadataInvalid);
            };
            let reserved_size = read_reservation(&reservation_path)?
                .ok_or(AttachmentError::StagingMetadataInvalid)?;
            if reserved_size > MAX_FILE_SIZE {
                return Err(AttachmentError::StagingMetadataInvalid);
            }
            let data_length = record
                .data_length
                .ok_or(AttachmentError::StagingMetadataInvalid)?;
            if data_length > reserved_size {
                return Err(AttachmentError::StagingStoreTooLarge {
                    actual: data_length,
                    maximum: reserved_size,
                });
            }
            if is_expired(now, modified, self.limits.retention) && remove_if_unlocked(&data_path)? {
                fs::remove_file(&reservation_path)?;
                usage.expired.transfers_removed += 1;
                usage.expired.bytes_released =
                    usage.expired.bytes_released.saturating_add(reserved_size);
                continue;
            }
            usage.transfers = usage.transfers.saturating_add(1);
            usage.reserved_bytes = usage.reserved_bytes.saturating_add(reserved_size);
        }
        Ok(usage)
    }
}

/// Exclusive seekable handle for a quota-reserved transfer.
pub struct ManagedAttachmentFile {
    file: File,
    transfer_id: AttachmentTransferId,
    maximum_length: u64,
}

impl ManagedAttachmentFile {
    /// Return the event-and-manifest-bound identity used for this staging file.
    #[must_use]
    pub const fn transfer_id(&self) -> AttachmentTransferId {
        self.transfer_id
    }
}

impl Read for ManagedAttachmentFile {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file.read(buffer)
    }
}

impl Write for ManagedAttachmentFile {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let position = self.file.stream_position()?;
        let requested = u64::try_from(buffer.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "write length overflow"))?;
        let end = position
            .checked_add(requested)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "write offset overflow"))?;
        if end > self.maximum_length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "attachment staging write exceeds its reserved file size",
            ));
        }
        self.file.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()?;
        self.file.sync_data()
    }
}

impl Seek for ManagedAttachmentFile {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.file.seek(position)
    }
}

#[derive(Default)]
struct StagingRecord {
    data_path: Option<PathBuf>,
    reservation_path: Option<PathBuf>,
    modified: Option<SystemTime>,
    data_length: Option<u64>,
}

#[derive(Default)]
struct StagingUsage {
    transfers: usize,
    reserved_bytes: u64,
    expired: StagingCleanupSummary,
}

fn create_private_directory(path: &Path) -> Result<(), AttachmentError> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn transfer_key(transfer_id: AttachmentTransferId) -> String {
    use std::fmt::Write as _;

    let mut key = String::with_capacity(64);
    for byte in transfer_id.0 {
        write!(key, "{byte:02x}").expect("writing to String cannot fail");
    }
    key
}

fn valid_transfer_key(key: &str) -> bool {
    key.len() == 64
        && key
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn write_reservation(path: &Path, file_size: u64) -> Result<(), AttachmentError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(RESERVATION_MAGIC)?;
    file.write_all(&file_size.to_le_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn read_reservation(path: &Path) -> Result<Option<u64>, AttachmentError> {
    if !path.exists() {
        return Ok(None);
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() != RESERVATION_BYTES
    {
        return Err(AttachmentError::StagingMetadataInvalid);
    }
    let mut file = File::open(path)?;
    let mut bytes = [0_u8; 16];
    file.read_exact(&mut bytes)?;
    if &bytes[..8] != RESERVATION_MAGIC {
        return Err(AttachmentError::StagingMetadataInvalid);
    }
    let size = u64::from_le_bytes(
        bytes[8..]
            .try_into()
            .map_err(|_| AttachmentError::StagingMetadataInvalid)?,
    );
    Ok(Some(size))
}

fn remove_if_unlocked(path: &Path) -> Result<bool, AttachmentError> {
    if !path.exists() {
        return Ok(true);
    }
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    if !file.try_lock_exclusive()? {
        return Ok(false);
    }
    file.unlock()?;
    drop(file);
    fs::remove_file(path)?;
    Ok(true)
}

fn is_expired(now: SystemTime, modified: SystemTime, retention: Duration) -> bool {
    now.duration_since(modified)
        .is_ok_and(|inactive| inactive >= retention)
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};
    use std::time::{Duration, SystemTime};

    use crate::{
        AttachmentManifest, AttachmentStagingLimits, AttachmentStagingStore, CHUNK_SIZE,
        MAX_FILE_SIZE,
    };

    fn temporary_root() -> std::path::PathBuf {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        std::env::temp_dir().join(format!(
            "lattice-files-staging-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
    }

    struct TemporaryRoot(std::path::PathBuf);

    impl Drop for TemporaryRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn limits(
        per_file: u64,
        total: u64,
        count: usize,
        retention: Duration,
    ) -> AttachmentStagingLimits {
        AttachmentStagingLimits::new(per_file, total, count, retention)
            .expect("valid staging limits")
    }

    fn manifest(content: &[u8]) -> AttachmentManifest {
        AttachmentManifest::from_reader(&mut Cursor::new(content), "safe.bin", None)
            .expect("valid attachment manifest")
    }

    #[test]
    fn quota_reservations_persist_across_reopen_and_expire_by_inactivity() {
        let root = TemporaryRoot(temporary_root());
        let policy = limits(32, 32, 2, Duration::from_mins(1));
        let store = AttachmentStagingStore::new(&root.0, policy).expect("create staging store");
        let bytes = b"persistent partial data";
        let first = manifest(bytes);
        let event_one = [1; 32];
        let mut file = store
            .open(&first, &event_one)
            .expect("reserve first transfer");
        file.write_all(bytes).expect("write staged data");
        file.flush().expect("flush staged data");
        let transfer_id = file.transfer_id();
        drop(file);

        let reopened = AttachmentStagingStore::new(&root.0, policy).expect("reopen store");
        let mut resumed = reopened
            .open(&first, &event_one)
            .expect("reuse persisted reservation");
        resumed
            .seek(SeekFrom::Start(0))
            .expect("seek resumed bytes");
        let mut staged = Vec::new();
        resumed
            .read_to_end(&mut staged)
            .expect("read resumed bytes");
        assert_eq!(staged, bytes);
        drop(resumed);

        let second = manifest(b"second transfer");
        assert!(matches!(
            reopened.open(&second, &[2; 32]),
            Err(crate::AttachmentError::GlobalStagingQuotaExceeded { .. })
        ));

        let old = SystemTime::now() - Duration::from_mins(2);
        let (data_path, _) = reopened.paths(transfer_id);
        let data = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(data_path)
            .expect("open staged file for timestamp setup");
        data.set_times(std::fs::FileTimes::new().set_modified(old))
            .expect("age partial staging");
        drop(data);
        let cleanup = reopened
            .cleanup_expired()
            .expect("remove expired partial staging");
        assert_eq!(cleanup.transfers_removed, 1);
        assert_eq!(
            cleanup.bytes_released,
            u64::try_from(bytes.len()).expect("test bytes fit u64")
        );
        reopened
            .open(&second, &[2; 32])
            .expect("released quota allows next transfer");
    }

    #[test]
    fn enforces_per_file_and_retained_transfer_count_limits() {
        let root = TemporaryRoot(temporary_root());
        let policy = limits(8, 64, 1, Duration::from_mins(1));
        let store = AttachmentStagingStore::new(&root.0, policy).expect("create staging store");
        let too_large = manifest(b"123456789");
        assert!(matches!(
            store.open(&too_large, &[5; 32]),
            Err(crate::AttachmentError::StagingQuotaExceeded {
                file_size: 9,
                limit: 8
            })
        ));
        let first = manifest(b"first");
        let mut staged_file = store
            .open(&first, &[6; 32])
            .expect("reserve first transfer");
        assert_eq!(
            staged_file
                .write(b"first!")
                .expect_err("staging cannot exceed the manifest size")
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert_eq!(staged_file.file.metadata().expect("staging file").len(), 0);
        drop(staged_file);
        let second = manifest(b"other");
        assert!(matches!(
            store.open(&second, &[7; 32]),
            Err(crate::AttachmentError::StagingTransferLimitExceeded { limit: 1 })
        ));
    }

    #[test]
    fn resumes_only_verified_chunks_and_exclusively_locks_active_transfer() {
        let root = TemporaryRoot(temporary_root());
        let policy = limits(MAX_FILE_SIZE, MAX_FILE_SIZE, 8, Duration::from_mins(1));
        let store = AttachmentStagingStore::new(&root.0, policy).expect("create staging store");
        let content = vec![0x55; CHUNK_SIZE + 3];
        let attachment = manifest(&content);
        let event_id = [3; 32];
        let staged_file = store.open(&attachment, &event_id).expect("open transfer");
        assert!(matches!(
            store.open(&attachment, &event_id),
            Err(crate::AttachmentError::StagingBusy)
        ));
        let mut receiver =
            crate::StreamedAttachmentReceiver::new(attachment.clone(), MAX_FILE_SIZE, staged_file)
                .expect("create receiver");
        receiver.accept().expect("accept private staging");
        receiver
            .submit_chunk(0, &content[..CHUNK_SIZE])
            .expect("write first verified chunk");
        let staged_file = receiver.into_storage();
        drop(staged_file);

        let mut reopened_receiver = crate::StreamedAttachmentReceiver::new(
            attachment,
            MAX_FILE_SIZE,
            store
                .open(&manifest(&content), &event_id)
                .expect("reopen transfer"),
        )
        .expect("recreate receiver");
        reopened_receiver
            .accept()
            .expect("rebuild verified chunk presence");
        assert_eq!(
            reopened_receiver.missing_ranges().expect("missing ranges"),
            vec![crate::ChunkRange {
                start: 1,
                end_exclusive: 2
            }]
        );
        reopened_receiver
            .submit_chunk(1, &content[CHUNK_SIZE..])
            .expect("complete remaining chunk");
        assert!(reopened_receiver.is_complete());
    }

    #[test]
    fn rejects_limits_and_malformed_reservation_metadata() {
        assert!(AttachmentStagingLimits::new(0, 10, 1, Duration::from_secs(1)).is_err());
        assert!(AttachmentStagingLimits::new(10, 10, 1, Duration::ZERO).is_err());
        let root = TemporaryRoot(temporary_root());
        let policy = limits(32, 32, 2, Duration::from_mins(1));
        let store = AttachmentStagingStore::new(&root.0, policy).expect("create staging store");
        let item = manifest(b"metadata");
        let transfer_id = item.transfer_id(&[4; 32]).expect("transfer ID");
        let (data_path, reserve_path) = store.paths(transfer_id);
        std::fs::write(data_path, b"").expect("create staging data file");
        std::fs::write(reserve_path, b"bad").expect("write invalid reservation");
        assert!(matches!(
            store.cleanup_expired(),
            Err(crate::AttachmentError::StagingMetadataInvalid)
        ));
    }
}
