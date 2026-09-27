//! Lattice attachment manifests and transfer state.

use std::fmt;
use std::io::{self, Read, Seek, SeekFrom, Write};

use sha2::{Digest as Sha2Digest, Sha256};
mod staging;

pub use staging::{
    AttachmentStagingLimits, AttachmentStagingStore, ManagedAttachmentFile, StagingCleanupSummary,
};

/// SHA-256 digest bytes.
pub type Sha256Hash = [u8; 32];
/// Deterministic identity for one manifest attached to one signed event.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AttachmentTransferId(pub Sha256Hash);

/// Fixed chunk size used for every attachment manifest.
pub const CHUNK_SIZE: usize = 64 * 1024;
/// Maximum number of chunks accepted in one manifest.
pub const MAX_CHUNKS: usize = 16_384;
/// Maximum file size accepted by this crate (1 GiB).
pub const MAX_FILE_SIZE: u64 = 1_073_741_824;
/// Maximum UTF-8 byte length of a filename hint.
pub const MAX_FILENAME_BYTES: usize = 255;
/// Maximum UTF-8 byte length of a MIME type hint.
pub const MAX_MIME_TYPE_BYTES: usize = 127;

/// Typed failures from attachment manifest creation and validation.
#[derive(Debug)]
pub enum AttachmentError {
    /// Reading the source stream failed.
    Io(io::Error),
    /// The stream or manifest exceeds the supported file size.
    FileTooLarge,
    /// The manifest contains more chunks than supported.
    TooManyChunks,
    /// The filename hint exceeds its byte limit.
    FilenameTooLong,
    /// The filename hint contains path components or unsafe display characters.
    InvalidFilenameHint,
    /// The MIME type hint exceeds its byte limit.
    MimeTypeTooLong,
    /// The declared file size and ordered chunk digest count disagree.
    ChunkCountMismatch { expected: usize, actual: usize },
    /// A requested chunk index is not in the manifest.
    InvalidChunkIndex,
    /// The supplied chunk length differs from its required length.
    ChunkLengthMismatch { expected: usize, actual: usize },
    /// The supplied chunk does not match its manifest digest.
    ChunkHashMismatch,
    /// A missing-chunk bitmap has the wrong number of bytes.
    InvalidBitmapLength { expected: usize, actual: usize },
    /// Unused high bits in the final bitmap byte must be zero.
    InvalidBitmapPadding,
    /// A manifest's chunk digests do not produce its declared whole-file digest.
    FileHashMismatch,
    /// The receiving session has not been explicitly accepted.
    TransferNotAccepted,
    /// The caller declined the transfer.
    TransferRejected,
    /// The manifest exceeds the caller's staging quota.
    StagingQuotaExceeded { file_size: u64, limit: u64 },
    /// A staging store contains bytes beyond the declared file size.
    StagingStoreTooLarge { actual: u64, maximum: u64 },
    /// The requested transfer would exceed the persistent global byte quota.
    GlobalStagingQuotaExceeded {
        requested: u64,
        reserved: u64,
        limit: u64,
    },
    /// The requested transfer would exceed the retained transfer count.
    StagingTransferLimitExceeded { limit: usize },
    /// A requested staging operation conflicts with an active transfer or store lock.
    StagingBusy,
    /// The staging root contains unsafe or invalid transfer metadata.
    StagingMetadataInvalid,
    /// The staging directory contains more entries than the scanner permits.
    StagingDirectoryTooLarge { limit: usize },
    /// The requested staging root is not a private regular directory.
    UnsafeStagingDirectory,
    /// A staging policy contains a zero or out-of-range limit.
    InvalidStagingLimits,
    /// The requested transfer has missing chunks.
    TransferIncomplete,
    /// This chunk was already received and verified.
    ChunkAlreadyPresent,
    /// The transfer failed its final whole-file integrity check.
    TransferIntegrityFailure,
    /// Staging memory could not be reserved without aborting.
    StagingAllocationFailed,
    /// A checked size or offset calculation could not be represented.
    ArithmeticOverflow,
}

impl fmt::Display for AttachmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "attachment staging I/O failed: {error}"),
            Self::FileTooLarge => write!(formatter, "attachment exceeds the maximum file size"),
            Self::TooManyChunks => write!(formatter, "attachment exceeds the maximum chunk count"),
            Self::FilenameTooLong => write!(formatter, "filename hint exceeds the maximum length"),
            Self::InvalidFilenameHint => {
                write!(
                    formatter,
                    "filename hint contains unsafe display characters"
                )
            }
            Self::MimeTypeTooLong => write!(formatter, "MIME type hint exceeds the maximum length"),
            Self::ChunkCountMismatch { expected, actual } => {
                write!(
                    formatter,
                    "manifest has {actual} chunk hashes; expected {expected}"
                )
            }
            Self::ChunkLengthMismatch { expected, actual } => {
                write!(formatter, "chunk has {actual} bytes; expected {expected}")
            }
            Self::StagingStoreTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "staging store has {actual} bytes; maximum is {maximum}"
                )
            }
            Self::InvalidChunkIndex => write!(formatter, "chunk index is outside the manifest"),
            Self::ChunkHashMismatch => write!(formatter, "chunk SHA-256 digest does not match"),
            Self::InvalidBitmapLength { expected, actual } => {
                write!(formatter, "bitmap has {actual} bytes; expected {expected}")
            }
            Self::InvalidBitmapPadding => {
                write!(formatter, "unused bits in the chunk bitmap must be zero")
            }
            Self::FileHashMismatch => write!(formatter, "whole-file SHA-256 digest does not match"),
            Self::TransferNotAccepted => {
                write!(formatter, "incoming transfer has not been accepted")
            }
            Self::TransferRejected => write!(formatter, "incoming transfer was rejected"),
            Self::StagingQuotaExceeded { file_size, limit } => {
                write!(
                    formatter,
                    "attachment size {file_size} exceeds staging quota {limit}"
                )
            }
            Self::GlobalStagingQuotaExceeded {
                requested,
                reserved,
                limit,
            } => write!(
                formatter,
                "attachment reservation {requested} with {reserved} already reserved exceeds global quota {limit}"
            ),
            Self::StagingTransferLimitExceeded { limit } => {
                write!(
                    formatter,
                    "attachment staging reached transfer limit {limit}"
                )
            }
            Self::StagingBusy => write!(formatter, "attachment staging store is busy"),
            Self::StagingMetadataInvalid => {
                write!(formatter, "attachment staging metadata is invalid")
            }
            Self::StagingDirectoryTooLarge { limit } => {
                write!(
                    formatter,
                    "attachment staging directory exceeds {limit} entries"
                )
            }
            Self::UnsafeStagingDirectory => {
                write!(
                    formatter,
                    "attachment staging root must be a non-symlink directory"
                )
            }
            Self::InvalidStagingLimits => {
                write!(formatter, "attachment staging limits are invalid")
            }
            Self::StagingAllocationFailed => {
                write!(formatter, "attachment staging allocation failed")
            }
            Self::TransferIncomplete => write!(formatter, "attachment transfer is incomplete"),
            Self::ChunkAlreadyPresent => write!(formatter, "chunk is already present"),
            Self::TransferIntegrityFailure => {
                write!(
                    formatter,
                    "attachment failed its whole-file integrity check"
                )
            }
            Self::ArithmeticOverflow => write!(formatter, "attachment size calculation overflowed"),
        }
    }
}

impl std::error::Error for AttachmentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for AttachmentError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Bounded metadata and ordered integrity digests for one attachment.
///
/// The hashes detect accidental or malicious content changes but do not
/// authenticate a sender or authorize access to the attachment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentManifest {
    /// Display filename hint; it is not a filesystem path.
    pub filename: String,
    /// Untrusted MIME type hint; consumers must not use it to authorize or
    /// execute content.
    pub mime_type: Option<String>,
    /// Total attachment length in bytes.
    pub file_size: u64,
    /// SHA-256 digest of the complete stream.
    pub file_hash: Sha256Hash,
    /// SHA-256 digests in fixed-size chunk order.
    pub chunk_hashes: Vec<Sha256Hash>,
}

/// Half-open range of missing chunk indexes: `[start, end_exclusive)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkRange {
    /// First missing chunk index.
    pub start: usize,
    /// One past the final missing chunk index.
    pub end_exclusive: usize,
}

impl AttachmentManifest {
    /// Bind this manifest's bounded metadata and integrity digests to an event ID.
    ///
    /// This identity is deterministic, not an authorization proof. Callers
    /// must obtain the event ID and manifest from their authenticated policy
    /// boundary before using it to route a transfer.
    ///
    /// # Errors
    ///
    /// Returns `AttachmentError` if the manifest is not valid within this
    /// crate's size, metadata, and digest bounds.
    pub fn transfer_id(
        &self,
        event_id: &[u8; 32],
    ) -> Result<AttachmentTransferId, AttachmentError> {
        self.validate()?;
        let mut hasher = Sha256::new();
        hasher.update(b"lattice-attachment-transfer-v1\0");
        hasher.update(event_id);
        hasher.update(self.file_size.to_le_bytes());
        hasher.update(self.file_hash);
        hasher.update((self.filename.len() as u64).to_le_bytes());
        hasher.update(self.filename.as_bytes());
        match &self.mime_type {
            Some(mime_type) => {
                hasher.update([1]);
                hasher.update((mime_type.len() as u64).to_le_bytes());
                hasher.update(mime_type.as_bytes());
            }
            None => hasher.update([0]),
        }
        hasher.update((self.chunk_hashes.len() as u64).to_le_bytes());
        for hash in &self.chunk_hashes {
            hasher.update(hash);
        }
        Ok(AttachmentTransferId(hasher.finalize().into()))
    }

    /// Hash a reader incrementally and construct a bounded manifest.
    ///
    /// At most one fixed-size chunk is held in memory at a time. The filename
    /// is reduced to a sanitized display hint; this function performs no
    /// filesystem access or persistence.
    ///
    /// # Errors
    ///
    /// Returns `AttachmentError` for an input limit violation, an oversized
    /// stream, arithmetic overflow, or a reader failure.
    pub fn from_reader<R: Read>(
        reader: &mut R,
        filename: &str,
        mime_type: Option<&str>,
    ) -> Result<Self, AttachmentError> {
        if filename.len() > MAX_FILENAME_BYTES {
            return Err(AttachmentError::FilenameTooLong);
        }
        if mime_type.is_some_and(|value| value.len() > MAX_MIME_TYPE_BYTES) {
            return Err(AttachmentError::MimeTypeTooLong);
        }

        let mut whole_file_hasher = Sha256::new();
        let mut buffer = vec![0_u8; CHUNK_SIZE].into_boxed_slice();
        let mut file_size = 0_u64;
        let mut chunk_hashes = Vec::new();

        loop {
            if file_size == MAX_FILE_SIZE {
                let mut probe = [0_u8; 1];
                let bytes_read = read_chunk(reader, &mut probe)?;
                if bytes_read != 0 {
                    return Err(AttachmentError::FileTooLarge);
                }
                break;
            }

            let remaining = MAX_FILE_SIZE - file_size;
            let read_length = usize::try_from(remaining.min(CHUNK_SIZE as u64))
                .map_err(|_| AttachmentError::ArithmeticOverflow)?;
            let bytes_read = read_chunk(reader, &mut buffer[..read_length])?;
            if bytes_read == 0 {
                break;
            }

            let bytes_read_u64 =
                u64::try_from(bytes_read).map_err(|_| AttachmentError::ArithmeticOverflow)?;
            file_size = file_size
                .checked_add(bytes_read_u64)
                .ok_or(AttachmentError::ArithmeticOverflow)?;
            if file_size > MAX_FILE_SIZE {
                return Err(AttachmentError::FileTooLarge);
            }
            if chunk_hashes.len() >= MAX_CHUNKS {
                return Err(AttachmentError::TooManyChunks);
            }

            let chunk = &buffer[..bytes_read];
            whole_file_hasher.update(chunk);
            chunk_hashes.push(sha256(chunk));
        }

        let manifest = Self {
            filename: sanitize_filename_for_display(filename),
            mime_type: mime_type.map(str::to_owned),
            file_size,
            file_hash: whole_file_hasher.finalize().into(),
            chunk_hashes,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// Validate all manifest limits and the file-size/chunk-count relationship.
    ///
    /// # Errors
    ///
    /// Returns `AttachmentError` when metadata limits or chunk-count
    /// relationships are invalid.
    pub fn validate(&self) -> Result<(), AttachmentError> {
        if self.file_size > MAX_FILE_SIZE {
            return Err(AttachmentError::FileTooLarge);
        }
        if self.chunk_hashes.len() > MAX_CHUNKS {
            return Err(AttachmentError::TooManyChunks);
        }
        if self.filename.len() > MAX_FILENAME_BYTES {
            return Err(AttachmentError::FilenameTooLong);
        }
        if sanitize_filename_for_display(&self.filename) != self.filename {
            return Err(AttachmentError::InvalidFilenameHint);
        }
        if self
            .mime_type
            .as_ref()
            .is_some_and(|value| value.len() > MAX_MIME_TYPE_BYTES)
        {
            return Err(AttachmentError::MimeTypeTooLong);
        }

        let expected = expected_chunk_count(self.file_size)?;
        if expected != self.chunk_hashes.len() {
            return Err(AttachmentError::ChunkCountMismatch {
                expected,
                actual: self.chunk_hashes.len(),
            });
        }
        Ok(())
    }

    /// Read one manifest chunk from a seekable source and verify it before
    /// returning it to a transport caller.
    ///
    /// The caller supplies the output buffer so repeated reads can reuse a
    /// single chunk-sized allocation. The buffer must exactly match the
    /// manifest-declared length for `index`; source contents are checked
    /// against the chunk digest before success.
    ///
    /// # Errors
    ///
    /// Returns `AttachmentError` for an invalid manifest, index, output
    /// length, source read/seek failure, or changed source content.
    pub fn read_verified_chunk_into<R: Read + Seek>(
        &self,
        source: &mut R,
        index: usize,
        output: &mut [u8],
    ) -> Result<(), AttachmentError> {
        self.validate()?;
        let expected_length = self.expected_chunk_size(index)?;
        if output.len() != expected_length {
            return Err(AttachmentError::ChunkLengthMismatch {
                expected: expected_length,
                actual: output.len(),
            });
        }
        let offset = chunk_offset(index)?;
        source.seek(SeekFrom::Start(offset))?;
        source.read_exact(output)?;
        self.verify_chunk_validated(index, output)
    }

    /// Verify a chunk's expected index, exact length, and SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Returns `AttachmentError` when the manifest is invalid, the index or
    /// chunk length is wrong, or the chunk digest does not match.
    pub fn verify_chunk(&self, index: usize, bytes: &[u8]) -> Result<(), AttachmentError> {
        self.validate()?;
        self.verify_chunk_validated(index, bytes)
    }

    fn verify_chunk_validated(&self, index: usize, bytes: &[u8]) -> Result<(), AttachmentError> {
        let expected_hash = self
            .chunk_hashes
            .get(index)
            .ok_or(AttachmentError::InvalidChunkIndex)?;
        let expected_length = self.expected_chunk_size(index)?;
        if bytes.len() != expected_length {
            return Err(AttachmentError::ChunkLengthMismatch {
                expected: expected_length,
                actual: bytes.len(),
            });
        }
        if &sha256(bytes) != expected_hash {
            return Err(AttachmentError::ChunkHashMismatch);
        }
        Ok(())
    }

    /// Return contiguous missing chunk ranges from a packed presence bitmap.
    ///
    /// Bits are ordered least-significant first within each byte; set bits
    /// mean present, and unset bits mean missing. The bitmap must have exactly
    /// `ceil(chunk_count / 8)` bytes, with all unused high bits clear.
    ///
    /// # Errors
    ///
    /// Returns `AttachmentError` when the manifest is invalid or the bitmap
    /// has invalid length or padding.
    pub fn missing_chunk_ranges(&self, bitmap: &[u8]) -> Result<Vec<ChunkRange>, AttachmentError> {
        self.validate()?;
        let chunk_count = self.chunk_hashes.len();
        let bitmap_length = chunk_count
            .checked_add(7)
            .ok_or(AttachmentError::ArithmeticOverflow)?
            / 8;
        if bitmap.len() != bitmap_length {
            return Err(AttachmentError::InvalidBitmapLength {
                expected: bitmap_length,
                actual: bitmap.len(),
            });
        }
        let remainder = chunk_count % 8;
        if remainder != 0 {
            let valid_bits = (1_u8 << remainder) - 1;
            if bitmap[bitmap_length - 1] & !valid_bits != 0 {
                return Err(AttachmentError::InvalidBitmapPadding);
            }
        }

        let is_present = |index: usize| bitmap[index / 8] & (1 << (index % 8)) != 0;
        let mut ranges = Vec::new();
        let mut index = 0;
        while index < chunk_count {
            if is_present(index) {
                index += 1;
                continue;
            }
            let start = index;
            while index < chunk_count && !is_present(index) {
                index += 1;
            }
            ranges.push(ChunkRange {
                start,
                end_exclusive: index,
            });
        }
        Ok(ranges)
    }

    fn expected_chunk_size(&self, index: usize) -> Result<usize, AttachmentError> {
        let index_u64 = u64::try_from(index).map_err(|_| AttachmentError::ArithmeticOverflow)?;
        let offset = index_u64
            .checked_mul(CHUNK_SIZE as u64)
            .ok_or(AttachmentError::ArithmeticOverflow)?;
        let remaining = self
            .file_size
            .checked_sub(offset)
            .ok_or(AttachmentError::InvalidChunkIndex)?;
        usize::try_from(remaining.min(CHUNK_SIZE as u64))
            .map_err(|_| AttachmentError::ArithmeticOverflow)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReceiverState {
    Pending,
    Accepted,
    Rejected,
    IntegrityFailed,
    Complete,
}

/// In-memory receiver for one manifest, with an explicit user-acceptance gate.
///
/// Constructing a receiver validates metadata but allocates no file-sized
/// buffer. `accept` allocates at most the caller quota and crate maximum;
/// incoming chunks are copied only after their length and digest are checked.
/// `verified_bytes` exposes bytes only after every chunk and the whole-file
/// digest pass. The caller MUST separately authenticate/authorize the
/// manifest and transfer before creating a receiver or accepting any data.
/// This type does not verify signatures, membership, permissions, or sender
/// possession and never chooses or writes a filesystem export path.
pub struct AttachmentReceiver {
    manifest: AttachmentManifest,
    presence: Vec<u8>,
    staged: Option<Vec<u8>>,
    staging_limit: u64,
    state: ReceiverState,
}

impl AttachmentReceiver {
    /// Create a receiver bounded by the caller's maximum staged bytes.
    ///
    /// # Errors
    ///
    /// Returns `AttachmentError` for invalid metadata, staging-quota excess,
    /// or a checked-size overflow.
    pub fn new(manifest: AttachmentManifest, staging_limit: u64) -> Result<Self, AttachmentError> {
        manifest.validate()?;
        if manifest.file_size > staging_limit {
            return Err(AttachmentError::StagingQuotaExceeded {
                file_size: manifest.file_size,
                limit: staging_limit,
            });
        }
        let bitmap_length = manifest
            .chunk_hashes
            .len()
            .checked_add(7)
            .ok_or(AttachmentError::ArithmeticOverflow)?
            / 8;
        Ok(Self {
            manifest,
            presence: vec![0; bitmap_length],
            staged: None,
            staging_limit,
            state: ReceiverState::Pending,
        })
    }

    /// Explicitly accept the transfer and allocate its bounded staging buffer.
    ///
    /// # Errors
    ///
    /// Returns `AttachmentError` if the transfer was already decided, staging
    /// memory cannot be reserved, or a zero-length file fails its digest.
    pub fn accept(&mut self) -> Result<(), AttachmentError> {
        self.ensure_pending()?;
        let size = usize::try_from(self.manifest.file_size)
            .map_err(|_| AttachmentError::ArithmeticOverflow)?;
        let mut staged = Vec::new();
        staged
            .try_reserve_exact(size)
            .map_err(|_| AttachmentError::StagingAllocationFailed)?;
        staged.resize(size, 0);
        self.staged = Some(staged);
        self.state = ReceiverState::Accepted;
        if self.manifest.chunk_hashes.is_empty() {
            if sha256(self.staged.as_deref().unwrap_or_default()) != self.manifest.file_hash {
                self.state = ReceiverState::IntegrityFailed;
                return Err(AttachmentError::FileHashMismatch);
            }
            self.state = ReceiverState::Complete;
        }
        Ok(())
    }

    /// Decline the transfer and release any staged content.
    ///
    /// # Errors
    ///
    /// Returns `TransferRejected` or `TransferNotAccepted` if the receiver is
    /// no longer pending.
    pub fn reject(&mut self) -> Result<(), AttachmentError> {
        self.ensure_pending()?;
        self.state = ReceiverState::Rejected;
        self.staged = None;
        Ok(())
    }

    /// Verify and stage one chunk. Chunks may arrive in any order.
    ///
    /// # Errors
    ///
    /// Returns `AttachmentError` if the transfer is not accepted, chunk
    /// metadata or digest is invalid, the chunk was already received, or the
    /// completed file fails its digest.
    pub fn submit_chunk(&mut self, index: usize, bytes: &[u8]) -> Result<(), AttachmentError> {
        self.ensure_accepted()?;
        self.manifest.verify_chunk(index, bytes)?;
        if self.is_present(index) {
            return Err(AttachmentError::ChunkAlreadyPresent);
        }
        let offset = index
            .checked_mul(CHUNK_SIZE)
            .ok_or(AttachmentError::ArithmeticOverflow)?;
        let end = offset
            .checked_add(bytes.len())
            .ok_or(AttachmentError::ArithmeticOverflow)?;
        let staged = self
            .staged
            .as_mut()
            .ok_or(AttachmentError::TransferNotAccepted)?;
        staged[offset..end].copy_from_slice(bytes);
        self.presence[index / 8] |= 1 << (index % 8);
        if self.all_present() {
            let staged = self
                .staged
                .as_ref()
                .ok_or(AttachmentError::TransferNotAccepted)?;
            if sha256(staged) != self.manifest.file_hash {
                self.state = ReceiverState::IntegrityFailed;
                return Err(AttachmentError::FileHashMismatch);
            }
            self.state = ReceiverState::Complete;
        }
        Ok(())
    }

    /// Return missing chunk ranges suitable for resume requests.
    ///
    /// # Errors
    ///
    /// Returns `AttachmentError` if the manifest or received bitmap is invalid.
    pub fn missing_ranges(&self) -> Result<Vec<ChunkRange>, AttachmentError> {
        self.manifest.missing_chunk_ranges(&self.presence)
    }

    /// Whether the verified whole-file digest gates have passed.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(self.state, ReceiverState::Complete)
    }

    /// Borrow the completed content only after all integrity checks pass.
    ///
    /// # Errors
    ///
    /// Returns `TransferRejected`, `TransferIntegrityFailure`,
    /// `TransferNotAccepted`, or `TransferIncomplete` until verified bytes
    /// are available.
    pub fn verified_bytes(&self) -> Result<&[u8], AttachmentError> {
        match self.state {
            ReceiverState::Rejected => Err(AttachmentError::TransferRejected),
            ReceiverState::IntegrityFailed => Err(AttachmentError::TransferIntegrityFailure),
            ReceiverState::Pending => Err(AttachmentError::TransferNotAccepted),
            ReceiverState::Accepted => Err(AttachmentError::TransferIncomplete),
            ReceiverState::Complete => self
                .staged
                .as_deref()
                .ok_or(AttachmentError::TransferNotAccepted),
        }
    }

    fn ensure_pending(&self) -> Result<(), AttachmentError> {
        match self.state {
            ReceiverState::Rejected => return Err(AttachmentError::TransferRejected),
            ReceiverState::Pending => {}
            _ => return Err(AttachmentError::TransferNotAccepted),
        }
        if self.manifest.file_size > self.staging_limit {
            return Err(AttachmentError::StagingQuotaExceeded {
                file_size: self.manifest.file_size,
                limit: self.staging_limit,
            });
        }
        Ok(())
    }

    fn ensure_accepted(&self) -> Result<(), AttachmentError> {
        match self.state {
            ReceiverState::Rejected => Err(AttachmentError::TransferRejected),
            ReceiverState::IntegrityFailed => Err(AttachmentError::TransferIntegrityFailure),
            ReceiverState::Pending => Err(AttachmentError::TransferNotAccepted),
            ReceiverState::Accepted | ReceiverState::Complete => Ok(()),
        }
    }

    fn is_present(&self, index: usize) -> bool {
        self.presence[index / 8] & (1 << (index % 8)) != 0
    }

    fn all_present(&self) -> bool {
        self.presence.iter().enumerate().all(|(byte_index, byte)| {
            let remaining = self.manifest.chunk_hashes.len() - byte_index * 8;
            let mask = if remaining >= 8 {
                u8::MAX
            } else {
                (1_u8 << remaining) - 1
            };
            byte & mask == mask
        })
    }
}

/// Streamed receiver backed by a caller-owned seekable staging store.
///
/// Only one fixed-size chunk and the bounded presence bitmap are held in
/// memory. The store is not opened, truncated, named, or exported by this
/// type; callers choose a private staging destination and enforce its
/// persistence and retention policy. After restart, construct a new receiver
/// with the same store and call `accept` to rebuild the bitmap from verified
/// chunk contents. Chunk integrity is checked before writes, and the whole-file
/// digest is checked before completion and again before copying to an output.
pub struct StreamedAttachmentReceiver<S> {
    manifest: AttachmentManifest,
    presence: Vec<u8>,
    staging_limit: u64,
    state: ReceiverState,
    storage: S,
}

impl<S: Read + Write + Seek> StreamedAttachmentReceiver<S> {
    /// Create a pending receiver around caller-owned staging storage.
    ///
    /// `storage` should be a private temporary store, not a chosen export
    /// destination. The store is not modified until `accept` or
    /// `submit_chunk`; its existing contents can be verified for resumption.
    ///
    /// # Errors
    ///
    /// Returns `AttachmentError` for invalid metadata, quota excess, or a
    /// checked-size or bitmap-allocation failure.
    pub fn new(
        manifest: AttachmentManifest,
        staging_limit: u64,
        storage: S,
    ) -> Result<Self, AttachmentError> {
        manifest.validate()?;
        if manifest.file_size > staging_limit {
            return Err(AttachmentError::StagingQuotaExceeded {
                file_size: manifest.file_size,
                limit: staging_limit,
            });
        }
        let bitmap_length = manifest
            .chunk_hashes
            .len()
            .checked_add(7)
            .ok_or(AttachmentError::ArithmeticOverflow)?
            / 8;
        let mut presence = Vec::new();
        presence
            .try_reserve_exact(bitmap_length)
            .map_err(|_| AttachmentError::StagingAllocationFailed)?;
        presence.resize(bitmap_length, 0);
        Ok(Self {
            manifest,
            presence,
            staging_limit,
            state: ReceiverState::Pending,
            storage,
        })
    }

    /// Return the validated manifest for the caller's pre-transfer consent UI.
    #[must_use]
    pub fn manifest(&self) -> &AttachmentManifest {
        &self.manifest
    }

    /// Accept the transfer and reconstruct verified presence from staging.
    ///
    /// Existing chunks are checked individually, so corrupted or incomplete
    /// chunks remain missing and may be replaced. This allows callers to
    /// reopen a persistent staging store and resume without trusting a saved
    /// bitmap.
    ///
    /// # Errors
    ///
    /// Returns `AttachmentError` for a state/quota violation, an oversized
    /// staging store, I/O failure, allocation failure, or a whole-file digest
    /// mismatch.
    pub fn accept(&mut self) -> Result<(), AttachmentError> {
        self.ensure_pending()?;
        let stored_length = self.storage.seek(SeekFrom::End(0))?;
        if stored_length > self.manifest.file_size {
            return Err(AttachmentError::StagingStoreTooLarge {
                actual: stored_length,
                maximum: self.manifest.file_size,
            });
        }

        self.presence.fill(0);
        let mut buffer = allocate_chunk_buffer()?;
        for index in 0..self.manifest.chunk_hashes.len() {
            let chunk_length = self.manifest.expected_chunk_size(index)?;
            let offset = chunk_offset(index)?;
            let end = offset
                .checked_add(
                    u64::try_from(chunk_length).map_err(|_| AttachmentError::ArithmeticOverflow)?,
                )
                .ok_or(AttachmentError::ArithmeticOverflow)?;
            if end > stored_length {
                continue;
            }
            self.storage.seek(SeekFrom::Start(offset))?;
            self.storage.read_exact(&mut buffer[..chunk_length])?;
            match self
                .manifest
                .verify_chunk_validated(index, &buffer[..chunk_length])
            {
                Ok(()) => self.set_present(index),
                Err(AttachmentError::ChunkHashMismatch) => {}
                Err(error) => return Err(error),
            }
        }

        if self.all_present() {
            let file_hash = hash_seekable(&mut self.storage, self.manifest.file_size, &mut buffer)?;
            if file_hash != self.manifest.file_hash {
                self.state = ReceiverState::IntegrityFailed;
                return Err(AttachmentError::FileHashMismatch);
            }
            self.state = ReceiverState::Complete;
        } else {
            self.state = ReceiverState::Accepted;
        }
        Ok(())
    }

    /// Decline a pending transfer without deleting caller-owned staging.
    ///
    /// The caller retains responsibility for cleanup or retention of the
    /// staging store; this method never removes a path or file.
    ///
    /// # Errors
    ///
    /// Returns `TransferNotAccepted` if the transfer has already been decided.
    pub fn reject(&mut self) -> Result<(), AttachmentError> {
        self.ensure_pending()?;
        self.state = ReceiverState::Rejected;
        Ok(())
    }

    /// Verify and write one chunk at its deterministic offset.
    ///
    /// Only the chunk-sized input is buffered. A write or flush failure leaves
    /// the chunk marked missing so the caller can retry it.
    ///
    /// # Errors
    ///
    /// Returns `AttachmentError` if the transfer is not accepted, chunk
    /// metadata or digest is invalid, the chunk is already present, storage
    /// I/O fails, or the completed whole-file digest does not match.
    pub fn submit_chunk(&mut self, index: usize, bytes: &[u8]) -> Result<(), AttachmentError> {
        self.ensure_accepted()?;
        self.manifest.verify_chunk_validated(index, bytes)?;
        if self.is_present(index) {
            return Err(AttachmentError::ChunkAlreadyPresent);
        }

        let offset = chunk_offset(index)?;
        self.storage.seek(SeekFrom::Start(offset))?;
        self.storage.write_all(bytes)?;
        self.storage.flush()?;
        self.set_present(index);

        if self.all_present() {
            let mut buffer = match allocate_chunk_buffer() {
                Ok(buffer) => buffer,
                Err(error) => {
                    self.clear_present(index);
                    return Err(error);
                }
            };
            let file_hash =
                match hash_seekable(&mut self.storage, self.manifest.file_size, &mut buffer) {
                    Ok(hash) => hash,
                    Err(error) => {
                        self.clear_present(index);
                        return Err(error);
                    }
                };
            if file_hash != self.manifest.file_hash {
                self.state = ReceiverState::IntegrityFailed;
                return Err(AttachmentError::FileHashMismatch);
            }
            self.state = ReceiverState::Complete;
        }
        Ok(())
    }

    /// Return missing ranges suitable for resume requests.
    ///
    /// # Errors
    ///
    /// Returns `AttachmentError` if the manifest or bitmap is invalid.
    pub fn missing_ranges(&self) -> Result<Vec<ChunkRange>, AttachmentError> {
        self.manifest.missing_chunk_ranges(&self.presence)
    }

    /// Whether every chunk and the whole-file digest have passed verification.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(self.state, ReceiverState::Complete)
    }

    /// Copy verified content to a caller-selected writer using a chunk buffer.
    ///
    /// The source digest is rechecked immediately before copying. If the
    /// destination writer fails, it may contain a partial file; callers should
    /// use a private temporary output and only commit it after this method
    /// succeeds. No path is created or selected here.
    ///
    /// # Errors
    ///
    /// Returns `TransferRejected`, `TransferIntegrityFailure`,
    /// `TransferNotAccepted`, `TransferIncomplete`, `FileHashMismatch`,
    /// `StagingAllocationFailed`, or an I/O error.
    pub fn copy_verified_to<W: Write>(&mut self, output: &mut W) -> Result<(), AttachmentError> {
        match self.state {
            ReceiverState::Rejected => return Err(AttachmentError::TransferRejected),
            ReceiverState::IntegrityFailed => {
                return Err(AttachmentError::TransferIntegrityFailure);
            }
            ReceiverState::Pending => return Err(AttachmentError::TransferNotAccepted),
            ReceiverState::Accepted => return Err(AttachmentError::TransferIncomplete),
            ReceiverState::Complete => {}
        }

        let mut buffer = allocate_chunk_buffer()?;
        let file_hash = hash_seekable(&mut self.storage, self.manifest.file_size, &mut buffer)?;
        if file_hash != self.manifest.file_hash {
            self.state = ReceiverState::IntegrityFailed;
            return Err(AttachmentError::FileHashMismatch);
        }

        self.storage.seek(SeekFrom::Start(0))?;
        let mut remaining = self.manifest.file_size;
        while remaining != 0 {
            let chunk_length = usize::try_from(remaining.min(CHUNK_SIZE as u64))
                .map_err(|_| AttachmentError::ArithmeticOverflow)?;
            self.storage.read_exact(&mut buffer[..chunk_length])?;
            output.write_all(&buffer[..chunk_length])?;
            remaining -=
                u64::try_from(chunk_length).map_err(|_| AttachmentError::ArithmeticOverflow)?;
        }
        Ok(())
    }
    /// Return the caller-owned staging store without asserting transfer completion.
    #[must_use]
    pub fn into_storage(self) -> S {
        self.storage
    }

    fn ensure_pending(&self) -> Result<(), AttachmentError> {
        match self.state {
            ReceiverState::Rejected => return Err(AttachmentError::TransferRejected),
            ReceiverState::Pending => {}
            _ => return Err(AttachmentError::TransferNotAccepted),
        }
        if self.manifest.file_size > self.staging_limit {
            return Err(AttachmentError::StagingQuotaExceeded {
                file_size: self.manifest.file_size,
                limit: self.staging_limit,
            });
        }
        Ok(())
    }

    fn ensure_accepted(&self) -> Result<(), AttachmentError> {
        match self.state {
            ReceiverState::Rejected => Err(AttachmentError::TransferRejected),
            ReceiverState::IntegrityFailed => Err(AttachmentError::TransferIntegrityFailure),
            ReceiverState::Pending => Err(AttachmentError::TransferNotAccepted),
            ReceiverState::Accepted | ReceiverState::Complete => Ok(()),
        }
    }

    fn is_present(&self, index: usize) -> bool {
        self.presence[index / 8] & (1 << (index % 8)) != 0
    }

    fn set_present(&mut self, index: usize) {
        self.presence[index / 8] |= 1 << (index % 8);
    }

    fn clear_present(&mut self, index: usize) {
        self.presence[index / 8] &= !(1 << (index % 8));
    }

    fn all_present(&self) -> bool {
        self.presence.iter().enumerate().all(|(byte_index, byte)| {
            let remaining = self.manifest.chunk_hashes.len() - byte_index * 8;
            let mask = if remaining >= 8 {
                u8::MAX
            } else {
                (1_u8 << remaining) - 1
            };
            byte & mask == mask
        })
    }
}

fn allocate_chunk_buffer() -> Result<Vec<u8>, AttachmentError> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(CHUNK_SIZE)
        .map_err(|_| AttachmentError::StagingAllocationFailed)?;
    buffer.resize(CHUNK_SIZE, 0);
    Ok(buffer)
}

fn chunk_offset(index: usize) -> Result<u64, AttachmentError> {
    u64::try_from(index)
        .map_err(|_| AttachmentError::ArithmeticOverflow)?
        .checked_mul(CHUNK_SIZE as u64)
        .ok_or(AttachmentError::ArithmeticOverflow)
}

fn hash_seekable<S: Read + Seek>(
    storage: &mut S,
    file_size: u64,
    buffer: &mut [u8],
) -> Result<Sha256Hash, AttachmentError> {
    storage.seek(SeekFrom::Start(0))?;
    let mut remaining = file_size;
    let mut hasher = Sha256::new();
    while remaining != 0 {
        let chunk_length = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| AttachmentError::ArithmeticOverflow)?;
        storage.read_exact(&mut buffer[..chunk_length])?;
        hasher.update(&buffer[..chunk_length]);
        remaining -=
            u64::try_from(chunk_length).map_err(|_| AttachmentError::ArithmeticOverflow)?;
    }
    Ok(hasher.finalize().into())
}

/// Produce a display-only filename without path separators, controls, or
/// common platform filename metacharacters. This does not create an export
/// path and UI consumers must still render the returned text safely.
#[must_use]
pub fn sanitize_filename_for_display(filename: &str) -> String {
    let basename = filename
        .rsplit(['/', '\\'])
        .find(|component| !component.is_empty())
        .unwrap_or_default();
    let mut safe = String::with_capacity(basename.len().min(MAX_FILENAME_BYTES));

    for character in basename.chars() {
        if is_hidden_control(character) {
            continue;
        }
        let character = if matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*') {
            '_'
        } else {
            character
        };
        let character_size = character.len_utf8();
        if character_size > MAX_FILENAME_BYTES - safe.len() {
            break;
        }
        safe.push(character);
    }

    let trimmed =
        safe.trim_matches(|character: char| character.is_whitespace() || character == '.');
    let mut safe = if trimmed.is_empty() {
        String::from("attachment")
    } else {
        trimmed.to_owned()
    };
    if is_reserved_filename(&safe) {
        if safe.len() >= MAX_FILENAME_BYTES {
            safe.pop();
        }
        safe.insert(0, '_');
    }
    safe
}

fn is_hidden_control(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{200B}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
        )
}

fn is_reserved_filename(filename: &str) -> bool {
    let stem = filename.split('.').next().unwrap_or(filename);
    let stem_bytes = stem.as_bytes();
    stem.eq_ignore_ascii_case("CON")
        || stem.eq_ignore_ascii_case("PRN")
        || stem.eq_ignore_ascii_case("AUX")
        || stem.eq_ignore_ascii_case("NUL")
        || stem.eq_ignore_ascii_case("CLOCK$")
        || (stem_bytes.len() == 4
            && (stem_bytes[..3].eq_ignore_ascii_case(b"COM")
                || stem_bytes[..3].eq_ignore_ascii_case(b"LPT"))
            && matches!(stem_bytes[3], b'1'..=b'9'))
}

fn expected_chunk_count(file_size: u64) -> Result<usize, AttachmentError> {
    let chunk_size = CHUNK_SIZE as u64;
    let whole_chunks = file_size / chunk_size;
    let partial_chunk = u64::from(!file_size.is_multiple_of(chunk_size));
    let count = whole_chunks
        .checked_add(partial_chunk)
        .ok_or(AttachmentError::ArithmeticOverflow)?;
    usize::try_from(count).map_err(|_| AttachmentError::ArithmeticOverflow)
}

fn read_chunk<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<usize, AttachmentError> {
    let mut filled = 0;
    while filled < buffer.len() {
        let bytes_read = match reader.read(&mut buffer[filled..]) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if bytes_read == 0 {
            break;
        }
        filled = filled
            .checked_add(bytes_read)
            .ok_or(AttachmentError::ArithmeticOverflow)?;
    }
    Ok(filled)
}

fn sha256(bytes: &[u8]) -> Sha256Hash {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};

    struct InterruptedOnce<R> {
        inner: R,
        interrupted: bool,
    }

    impl<R: Read> Read for InterruptedOnce<R> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            self.inner.read(buffer)
        }
    }

    use super::{
        AttachmentError, AttachmentManifest, AttachmentReceiver, CHUNK_SIZE, ChunkRange,
        MAX_CHUNKS, MAX_FILE_SIZE, MAX_FILENAME_BYTES, StreamedAttachmentReceiver,
    };

    #[test]
    fn empty_stream_has_no_chunks_and_hashes_empty_content() {
        let manifest =
            AttachmentManifest::from_reader(&mut Cursor::new(Vec::<u8>::new()), "empty.bin", None)
                .expect("empty attachment should be valid");

        assert_eq!(manifest.file_size, 0);
        assert!(manifest.chunk_hashes.is_empty());
        assert_eq!(
            manifest.file_hash,
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55
            ]
        );
        assert!(manifest.missing_chunk_ranges(&[]).unwrap().is_empty());
    }

    #[test]
    fn source_stream_retries_interrupted_reads() {
        let content = b"streaming survives interruption";
        let mut reader = InterruptedOnce {
            inner: Cursor::new(content),
            interrupted: false,
        };

        let manifest = AttachmentManifest::from_reader(&mut reader, "retry.bin", None).unwrap();

        assert_eq!(manifest.file_size, content.len() as u64);
        assert_eq!(manifest.file_hash, super::sha256(content));
    }

    #[test]
    fn source_chunks_are_seeked_and_checked_against_manifest() {
        let mut content = vec![0x47; CHUNK_SIZE + 3];
        let manifest =
            AttachmentManifest::from_reader(&mut Cursor::new(&content), "source.bin", None)
                .unwrap();
        let mut source = Cursor::new(content.clone());
        let mut last_chunk = [0; 3];

        manifest
            .read_verified_chunk_into(&mut source, 1, &mut last_chunk)
            .unwrap();
        assert_eq!(last_chunk, [0x47; 3]);

        let mut wrong_size = [0; 2];
        assert!(matches!(
            manifest.read_verified_chunk_into(&mut source, 1, &mut wrong_size),
            Err(AttachmentError::ChunkLengthMismatch {
                expected: 3,
                actual: 2
            })
        ));

        content[0] ^= 0xff;
        source = Cursor::new(content);
        let mut first_chunk = vec![0; CHUNK_SIZE];
        assert!(matches!(
            manifest.read_verified_chunk_into(&mut source, 0, &mut first_chunk),
            Err(AttachmentError::ChunkHashMismatch)
        ));
    }

    #[test]
    fn exact_chunk_boundary_and_multichunk_stream_are_split_deterministically() {
        let exact = vec![0x31; CHUNK_SIZE];
        let exact_manifest =
            AttachmentManifest::from_reader(&mut Cursor::new(&exact), "one.bin", None).unwrap();
        assert_eq!(exact_manifest.chunk_hashes.len(), 1);
        exact_manifest.verify_chunk(0, &exact).unwrap();

        let content = vec![0x5a; CHUNK_SIZE * 2 + 17];
        let manifest =
            AttachmentManifest::from_reader(&mut Cursor::new(&content), "many.bin", None).unwrap();
        assert_eq!(manifest.file_size, content.len() as u64);
        assert_eq!(manifest.file_hash, super::sha256(&content));
        assert_eq!(manifest.chunk_hashes.len(), 3);
        manifest.verify_chunk(0, &content[..CHUNK_SIZE]).unwrap();
        manifest
            .verify_chunk(1, &content[CHUNK_SIZE..CHUNK_SIZE * 2])
            .unwrap();
        manifest
            .verify_chunk(2, &content[CHUNK_SIZE * 2..])
            .unwrap();
        assert_eq!(
            manifest.missing_chunk_ranges(&[0b0000_0101]).unwrap(),
            vec![ChunkRange {
                start: 1,
                end_exclusive: 2
            }]
        );
    }

    #[test]
    fn altered_chunk_is_rejected_by_its_digest() {
        let content = vec![0x44; CHUNK_SIZE + 1];
        let manifest =
            AttachmentManifest::from_reader(&mut Cursor::new(&content), "data.bin", None).unwrap();
        let mut altered = content[..CHUNK_SIZE].to_vec();
        altered[0] ^= 1;

        assert!(matches!(
            manifest.verify_chunk(0, &altered),
            Err(AttachmentError::ChunkHashMismatch)
        ));
    }

    #[test]
    fn oversized_manifest_and_invalid_bitmap_are_rejected() {
        let mut manifest =
            AttachmentManifest::from_reader(&mut Cursor::new(vec![0; 1]), "data.bin", None)
                .unwrap();
        manifest.file_size = MAX_FILE_SIZE + 1;
        assert!(matches!(
            manifest.validate(),
            Err(AttachmentError::FileTooLarge)
        ));

        let valid = AttachmentManifest::from_reader(
            &mut Cursor::new(vec![0; CHUNK_SIZE]),
            "data.bin",
            None,
        )
        .unwrap();
        assert!(matches!(
            valid.missing_chunk_ranges(&[]),
            Err(AttachmentError::InvalidBitmapLength {
                expected: 1,
                actual: 0
            })
        ));

        let too_many = AttachmentManifest {
            filename: "bounded.bin".to_owned(),
            mime_type: None,
            file_size: MAX_FILE_SIZE,
            file_hash: [0; 32],
            chunk_hashes: vec![[0; 32]; MAX_CHUNKS + 1],
        };
        assert!(matches!(
            too_many.validate(),
            Err(AttachmentError::TooManyChunks)
        ));
    }

    #[test]
    fn filename_display_removes_traversal_and_bounds_utf8_bytes() {
        let manifest = AttachmentManifest::from_reader(
            &mut Cursor::new(b"payload".to_vec()),
            "../folder\\report.txt",
            Some("application/octet-stream"),
        )
        .unwrap();
        assert_eq!(manifest.filename, "report.txt");
        assert!(!manifest.filename.contains('/'));
        assert!(!manifest.filename.contains('\\'));
        assert_eq!(super::sanitize_filename_for_display(".."), "attachment");
        let long_unicode = "é".repeat(MAX_FILENAME_BYTES);
        let safe = super::sanitize_filename_for_display(&long_unicode);
        assert!(safe.len() <= MAX_FILENAME_BYTES);
        assert!(std::str::from_utf8(safe.as_bytes()).is_ok());
    }

    #[test]
    fn unsafe_incoming_filename_hint_is_rejected_before_receiver_acceptance() {
        let mut manifest = AttachmentManifest::from_reader(
            &mut Cursor::new(b"payload".to_vec()),
            "safe.txt",
            None,
        )
        .unwrap();
        manifest.filename = "../outside.txt".to_owned();
        assert!(matches!(
            manifest.validate(),
            Err(AttachmentError::InvalidFilenameHint)
        ));
        assert!(matches!(
            AttachmentReceiver::new(manifest, 1024),
            Err(AttachmentError::InvalidFilenameHint)
        ));
    }
    #[test]
    fn rejected_chunk_does_not_advance_resume_state_and_digest_gates_completion() {
        let content = vec![0x27; CHUNK_SIZE + 9];
        let manifest =
            AttachmentManifest::from_reader(&mut Cursor::new(&content), "data.bin", None).unwrap();
        let mut receiver = AttachmentReceiver::new(manifest, content.len() as u64).unwrap();
        assert!(matches!(
            receiver.submit_chunk(0, &content[..CHUNK_SIZE]),
            Err(AttachmentError::TransferNotAccepted)
        ));
        receiver.accept().unwrap();

        let mut corrupt = content[..CHUNK_SIZE].to_vec();
        corrupt[0] ^= 1;
        assert!(matches!(
            receiver.submit_chunk(0, &corrupt),
            Err(AttachmentError::ChunkHashMismatch)
        ));
        assert_eq!(
            receiver.missing_ranges().unwrap(),
            vec![ChunkRange {
                start: 0,
                end_exclusive: 2
            }]
        );
        assert!(!receiver.is_complete());
        assert!(matches!(
            receiver.verified_bytes(),
            Err(AttachmentError::TransferIncomplete)
        ));

        receiver.submit_chunk(1, &content[CHUNK_SIZE..]).unwrap();
        assert!(!receiver.is_complete());
        assert_eq!(
            receiver.missing_ranges().unwrap(),
            vec![ChunkRange {
                start: 0,
                end_exclusive: 1
            }]
        );
        receiver.submit_chunk(0, &content[..CHUNK_SIZE]).unwrap();
        assert!(receiver.is_complete());
        assert_eq!(receiver.verified_bytes().unwrap(), content);
    }

    #[test]
    fn whole_file_digest_failure_never_exposes_complete_bytes() {
        let content = b"valid chunk, invalid whole-file digest";
        let mut manifest =
            AttachmentManifest::from_reader(&mut Cursor::new(content), "data.bin", None).unwrap();
        manifest.file_hash[0] ^= 1;
        let mut receiver = AttachmentReceiver::new(manifest, content.len() as u64).unwrap();
        receiver.accept().unwrap();

        assert!(matches!(
            receiver.submit_chunk(0, content),
            Err(AttachmentError::FileHashMismatch)
        ));
        assert!(!receiver.is_complete());
        assert!(matches!(
            receiver.verified_bytes(),
            Err(AttachmentError::TransferIntegrityFailure)
        ));
    }
    #[test]
    fn streamed_receiver_rechecks_persisted_chunks_before_resuming() {
        let content = vec![0x63; CHUNK_SIZE + 9];
        let manifest =
            AttachmentManifest::from_reader(&mut Cursor::new(&content), "resume.bin", None)
                .unwrap();
        let mut receiver = StreamedAttachmentReceiver::new(
            manifest.clone(),
            content.len() as u64,
            Cursor::new(Vec::new()),
        )
        .unwrap();
        receiver.accept().unwrap();
        assert_eq!(
            receiver.missing_ranges().unwrap(),
            vec![ChunkRange {
                start: 0,
                end_exclusive: 2
            }]
        );
        receiver.submit_chunk(0, &content[..CHUNK_SIZE]).unwrap();
        let mut staging = receiver.into_storage();
        staging.get_mut()[0] ^= 1;

        let mut resumed =
            StreamedAttachmentReceiver::new(manifest, content.len() as u64, staging).unwrap();
        resumed.accept().unwrap();
        assert_eq!(
            resumed.missing_ranges().unwrap(),
            vec![ChunkRange {
                start: 0,
                end_exclusive: 2
            }]
        );
        let invalid_chunk = vec![0; CHUNK_SIZE];
        assert!(matches!(
            resumed.submit_chunk(0, &invalid_chunk),
            Err(AttachmentError::ChunkHashMismatch)
        ));
        resumed.submit_chunk(1, &content[CHUNK_SIZE..]).unwrap();
        resumed.submit_chunk(0, &content[..CHUNK_SIZE]).unwrap();
        assert!(resumed.is_complete());
        let mut output = Vec::new();
        resumed.copy_verified_to(&mut output).unwrap();
        assert_eq!(output, content);
    }

    #[test]
    fn streamed_receiver_rejects_staging_beyond_manifest_size() {
        let content = b"bounded";
        let manifest =
            AttachmentManifest::from_reader(&mut Cursor::new(content), "small.bin", None).unwrap();
        let mut receiver = StreamedAttachmentReceiver::new(
            manifest,
            content.len() as u64,
            Cursor::new(vec![0; content.len() + 1]),
        )
        .unwrap();
        assert!(matches!(
            receiver.accept(),
            Err(AttachmentError::StagingStoreTooLarge {
                actual,
                maximum
            }) if actual == content.len() as u64 + 1 && maximum == content.len() as u64
        ));
        assert!(!receiver.is_complete());
    }
}
