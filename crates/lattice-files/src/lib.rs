//! Lattice attachment manifests and transfer state.

use std::fmt;
use std::io::{self, Read};

use sha2::{Digest as Sha2Digest, Sha256};

/// SHA-256 digest bytes.
pub type Sha256Hash = [u8; 32];

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
    /// A checked size or offset calculation could not be represented.
    ArithmeticOverflow,
}

impl fmt::Display for AttachmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "attachment stream read failed: {error}"),
            Self::FileTooLarge => write!(formatter, "attachment exceeds the maximum file size"),
            Self::TooManyChunks => write!(formatter, "attachment exceeds the maximum chunk count"),
            Self::FilenameTooLong => write!(formatter, "filename hint exceeds the maximum length"),
            Self::MimeTypeTooLong => write!(formatter, "MIME type hint exceeds the maximum length"),
            Self::ChunkCountMismatch { expected, actual } => {
                write!(
                    formatter,
                    "manifest has {actual} chunk hashes; expected {expected}"
                )
            }
            Self::InvalidChunkIndex => write!(formatter, "chunk index is outside the manifest"),
            Self::ChunkLengthMismatch { expected, actual } => {
                write!(formatter, "chunk has {actual} bytes; expected {expected}")
            }
            Self::ChunkHashMismatch => write!(formatter, "chunk SHA-256 digest does not match"),
            Self::InvalidBitmapLength { expected, actual } => {
                write!(formatter, "bitmap has {actual} bytes; expected {expected}")
            }
            Self::InvalidBitmapPadding => {
                write!(formatter, "unused bits in the chunk bitmap must be zero")
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
    /// Hash a reader incrementally and construct a bounded manifest.
    ///
    /// At most one fixed-size chunk is held in memory at a time. The filename
    /// is reduced to a sanitized display hint; this function performs no
    /// filesystem access or persistence.
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
        let mut buffer = [0_u8; CHUNK_SIZE];
        let mut file_size = 0_u64;
        let mut chunk_hashes = Vec::new();

        loop {
            if file_size == MAX_FILE_SIZE {
                let mut probe = [0_u8; 1];
                if reader.read(&mut probe)? != 0 {
                    return Err(AttachmentError::FileTooLarge);
                }
                break;
            }

            let bytes_read = read_chunk(reader, &mut buffer)?;
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

    /// Verify a chunk's expected index, exact length, and SHA-256 digest.
    pub fn verify_chunk(&self, index: usize, bytes: &[u8]) -> Result<(), AttachmentError> {
        self.validate()?;
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

/// Produce a display-only filename without path separators, controls, or
/// common platform filename metacharacters. This does not create an export
/// path and UI consumers must still render the returned text safely.
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
    let partial_chunk = if file_size % chunk_size == 0 {
        0_u64
    } else {
        1_u64
    };
    let count = whole_chunks
        .checked_add(partial_chunk)
        .ok_or(AttachmentError::ArithmeticOverflow)?;
    usize::try_from(count).map_err(|_| AttachmentError::ArithmeticOverflow)
}

fn read_chunk<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<usize, AttachmentError> {
    let mut filled = 0;
    while filled < buffer.len() {
        let bytes_read = reader.read(&mut buffer[filled..])?;
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
    use std::io::Cursor;

    use super::{
        AttachmentError, AttachmentManifest, CHUNK_SIZE, ChunkRange, MAX_CHUNKS, MAX_FILE_SIZE,
        MAX_FILENAME_BYTES,
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
}
