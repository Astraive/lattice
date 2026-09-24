//! Authenticated encryption and scoped key access for `OpenMLS` `SQLite` records.

use std::{cell::RefCell, error::Error, fmt, io};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::Codec;
use openmls_traits::OpenMlsProvider;
use rusqlite::Connection;
use serde::{Serialize, de::DeserializeOwned};
use zeroize::{Zeroize, Zeroizing};

const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const VERSION: u8 = 1;
const MAX_PLAINTEXT_BYTES: usize = 1024 * 1024;
const HEADER_BYTES: usize = 1 + NONCE_BYTES;
const MAX_CIPHERTEXT_BYTES: usize = MAX_PLAINTEXT_BYTES + TAG_BYTES;
const MAX_RECORD_BYTES: usize = HEADER_BYTES + MAX_CIPHERTEXT_BYTES;
const AAD: &[u8] = b"lattice-mls-storage-json\x01";

thread_local! {
    static STORAGE_KEY: RefCell<Option<Zeroizing<[u8; KEY_BYTES]>>> = const { RefCell::new(None) };
}

/// Errors from the protected persistence codec. Messages intentionally omit
/// serialized values, keys, and cryptographic-library details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedCodecError {
    InvalidKeyLength,
    MissingKey,
    Serialization,
    Deserialization,
    Randomness,
    Encryption,
    Decryption,
    UnsupportedVersion,
    MalformedRecord,
    TooLarge,
}

impl fmt::Display for ProtectedCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidKeyLength => "MLS storage key must be exactly 32 bytes",
            Self::MissingKey => "MLS storage key scope is not active",
            Self::Serialization => "MLS storage record serialization failed",
            Self::Deserialization => "MLS storage record deserialization failed",
            Self::Randomness => "MLS storage nonce generation failed",
            Self::Encryption => "MLS storage record encryption failed",
            Self::Decryption => "MLS storage record authentication failed",
            Self::UnsupportedVersion => "MLS storage record version is unsupported",
            Self::MalformedRecord => "MLS storage record is malformed",
            Self::TooLarge => "MLS storage record exceeds the size limit",
        };
        f.write_str(message)
    }
}

impl Error for ProtectedCodecError {}

/// Runs `action` with an explicit per-thread MLS storage key.
///
/// Nested scopes restore their predecessor on normal return and unwinding. The
/// key is copied into zeroizing storage and is never retained process-wide.
///
/// # Errors
///
/// Returns [`ProtectedCodecError::InvalidKeyLength`] unless `key` contains
/// exactly 32 bytes.
pub fn with_mls_storage_key<T>(
    key: &[u8],
    action: impl FnOnce() -> T,
) -> Result<T, ProtectedCodecError> {
    let key: [u8; KEY_BYTES] = key
        .try_into()
        .map_err(|_| ProtectedCodecError::InvalidKeyLength)?;
    let previous = STORAGE_KEY.with(|slot| slot.replace(Some(Zeroizing::new(key))));
    let _scope = KeyScope { previous };
    Ok(action())
}

struct KeyScope {
    previous: Option<Zeroizing<[u8; KEY_BYTES]>>,
}

impl Drop for KeyScope {
    fn drop(&mut self) {
        STORAGE_KEY.with(|slot| {
            let current = slot.replace(self.previous.take());
            drop(current);
        });
    }
}

fn with_current_key<T>(
    action: impl FnOnce(&[u8; KEY_BYTES]) -> Result<T, ProtectedCodecError>,
) -> Result<T, ProtectedCodecError> {
    let key = STORAGE_KEY.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|key| Zeroizing::new(**key))
            .ok_or(ProtectedCodecError::MissingKey)
    })?;
    action(&key)
}

const LOCAL_RECORD_AAD: &[u8] = b"lattice-mls-local-record-v1\0";
const MAX_LOCAL_CONTEXT_BYTES: usize = 256;

/// Encrypts one bounded application-owned local record under the active storage key.
///
/// `context` is authenticated but not encrypted; callers must include stable
/// record identity and a domain separator. The key never leaves its scoped slot.
///
/// # Errors
///
/// Returns `MissingKey` without an active key scope, `MalformedRecord` for an
/// empty/oversized context, `TooLarge` for oversized plaintext, or an encryption
/// and randomness error.
pub fn protect_local_record(
    context: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, ProtectedCodecError> {
    if context.is_empty() || context.len() > MAX_LOCAL_CONTEXT_BYTES {
        return Err(ProtectedCodecError::MalformedRecord);
    }
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(ProtectedCodecError::TooLarge);
    }
    let context_length =
        u32::try_from(context.len()).map_err(|_| ProtectedCodecError::MalformedRecord)?;
    with_current_key(|key| {
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ProtectedCodecError::Encryption)?;
        let mut associated_data = Vec::with_capacity(LOCAL_RECORD_AAD.len() + 4 + context.len());
        associated_data.extend_from_slice(LOCAL_RECORD_AAD);
        associated_data.extend_from_slice(&context_length.to_be_bytes());
        associated_data.extend_from_slice(context);
        let mut nonce = [0_u8; NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| ProtectedCodecError::Randomness)?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &associated_data,
                },
            )
            .map_err(|_| ProtectedCodecError::Encryption)?;
        let mut record = Vec::with_capacity(HEADER_BYTES + ciphertext.len());
        record.push(VERSION);
        record.extend_from_slice(&nonce);
        record.extend_from_slice(&ciphertext);
        nonce.zeroize();
        Ok(record)
    })
}

/// Decrypts one bounded application-owned local record under the active key.
///
/// The caller must supply the same authenticated context used by
/// [`protect_local_record`].
///
/// # Errors
///
/// Returns `MissingKey` without an active key scope, `MalformedRecord` for an
/// invalid context or truncated record, `UnsupportedVersion` for another format,
/// `TooLarge` for oversized input, or `Decryption` when authentication fails.
pub fn unprotect_local_record(
    context: &[u8],
    record: &[u8],
) -> Result<Vec<u8>, ProtectedCodecError> {
    if context.is_empty() || context.len() > MAX_LOCAL_CONTEXT_BYTES {
        return Err(ProtectedCodecError::MalformedRecord);
    }
    if record.len() > MAX_RECORD_BYTES {
        return Err(ProtectedCodecError::TooLarge);
    }
    if record.len() < HEADER_BYTES + TAG_BYTES {
        return Err(ProtectedCodecError::MalformedRecord);
    }
    if record[0] != VERSION {
        return Err(ProtectedCodecError::UnsupportedVersion);
    }
    let context_length =
        u32::try_from(context.len()).map_err(|_| ProtectedCodecError::MalformedRecord)?;
    with_current_key(|key| {
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ProtectedCodecError::Decryption)?;
        let mut associated_data = Vec::with_capacity(LOCAL_RECORD_AAD.len() + 4 + context.len());
        associated_data.extend_from_slice(LOCAL_RECORD_AAD);
        associated_data.extend_from_slice(&context_length.to_be_bytes());
        associated_data.extend_from_slice(context);
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&record[1..HEADER_BYTES]),
                Payload {
                    msg: &record[HEADER_BYTES..],
                    aad: &associated_data,
                },
            )
            .map_err(|_| ProtectedCodecError::Decryption)?;
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            let mut plaintext = Zeroizing::new(plaintext);
            plaintext.zeroize();
            return Err(ProtectedCodecError::TooLarge);
        }
        let plaintext = Zeroizing::new(plaintext);
        Ok(plaintext.to_vec())
    })
}

/// Production `OpenMLS` JSON codec. The type is not reachable outside this
/// crate's storage module.
#[derive(Default)]
pub struct ProtectedJsonCodec;

struct LimitedBuffer(Zeroizing<Vec<u8>>);

impl io::Write for LimitedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next_len = self
            .0
            .len()
            .checked_add(bytes.len())
            .filter(|length| *length <= MAX_PLAINTEXT_BYTES)
            .ok_or_else(|| io::Error::new(io::ErrorKind::FileTooLarge, "record limit"))?;
        let additional = next_len - self.0.len();
        self.0
            .try_reserve(additional)
            .map_err(|_| io::Error::other("record allocation failed"))?;
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Codec for ProtectedJsonCodec {
    type Error = ProtectedCodecError;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        // OpenMLS also runs its codec over SQLite primary keys. Group IDs and
        // epochs are public lookup metadata and must have stable bytes;
        // randomized AEAD would make later lookups miss. Secret-bearing group
        // records still use the authenticated encrypted path below.
        if matches!(
            std::any::type_name::<T>(),
            "&openmls::group::GroupId" | "&openmls::group::GroupEpoch"
        ) {
            let mut encoded = LimitedBuffer(Zeroizing::new(vec![0]));
            serde_json::to_writer(&mut encoded, value)
                .map_err(|_| ProtectedCodecError::Serialization)?;
            return Ok(encoded.0.to_vec());
        }
        with_current_key(|key| {
            let mut plaintext = LimitedBuffer(Zeroizing::new(Vec::new()));
            if let Err(error) = serde_json::to_writer(&mut plaintext, value) {
                return if error.io_error_kind() == Some(io::ErrorKind::FileTooLarge) {
                    Err(ProtectedCodecError::TooLarge)
                } else {
                    Err(ProtectedCodecError::Serialization)
                };
            }

            let cipher =
                Aes256Gcm::new_from_slice(key).map_err(|_| ProtectedCodecError::Encryption)?;
            let mut nonce_bytes = [0u8; NONCE_BYTES];
            getrandom::fill(&mut nonce_bytes).map_err(|_| ProtectedCodecError::Randomness)?;
            let ciphertext = cipher
                .encrypt(
                    Nonce::from_slice(&nonce_bytes),
                    Payload {
                        msg: plaintext.0.as_slice(),
                        aad: AAD,
                    },
                )
                .map_err(|_| ProtectedCodecError::Encryption)?;

            let mut record = Vec::with_capacity(HEADER_BYTES + ciphertext.len());
            record.push(VERSION);
            record.extend_from_slice(&nonce_bytes);
            record.extend_from_slice(&ciphertext);
            nonce_bytes.zeroize();
            Ok(record)
        })
    }

    fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Self::Error> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(ProtectedCodecError::TooLarge);
        }
        if bytes.len() < HEADER_BYTES + TAG_BYTES {
            return Err(ProtectedCodecError::MalformedRecord);
        }
        if bytes[0] != VERSION {
            return Err(ProtectedCodecError::UnsupportedVersion);
        }
        if bytes.len() - HEADER_BYTES > MAX_CIPHERTEXT_BYTES {
            return Err(ProtectedCodecError::TooLarge);
        }

        with_current_key(|key| {
            let cipher =
                Aes256Gcm::new_from_slice(key).map_err(|_| ProtectedCodecError::Decryption)?;
            let plaintext = cipher
                .decrypt(
                    Nonce::from_slice(&bytes[1..HEADER_BYTES]),
                    Payload {
                        msg: &bytes[HEADER_BYTES..],
                        aad: AAD,
                    },
                )
                .map_err(|_| ProtectedCodecError::Decryption)?;
            if plaintext.len() > MAX_PLAINTEXT_BYTES {
                let mut plaintext = Zeroizing::new(plaintext);
                plaintext.zeroize();
                return Err(ProtectedCodecError::TooLarge);
            }
            let plaintext = Zeroizing::new(plaintext);
            serde_json::from_slice(plaintext.as_slice())
                .map_err(|_| ProtectedCodecError::Deserialization)
        })
    }
}

/// `OpenMLS` provider backed by a borrowed `SQLite` connection and authenticated
/// record codec. Each storage operation requires an active key scope.
pub struct ProtectedSqliteProvider<'a> {
    crypto: RustCrypto,
    storage: openmls_sqlite_storage::SqliteStorageProvider<ProtectedJsonCodec, &'a Connection>,
}

impl<'a> ProtectedSqliteProvider<'a> {
    /// Creates a provider over an existing connection without taking ownership.
    pub fn new(connection: &'a Connection) -> Self {
        Self {
            crypto: RustCrypto::default(),
            storage: openmls_sqlite_storage::SqliteStorageProvider::new(connection),
        }
    }
}

impl<'a> OpenMlsProvider for ProtectedSqliteProvider<'a> {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider =
        openmls_sqlite_storage::SqliteStorageProvider<ProtectedJsonCodec, &'a Connection>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

/// Runs the `OpenMLS` `SQLite` schema migrations on a caller-owned connection.
///
/// # Errors
///
/// Returns an error if an `OpenMLS` `SQLite` migration fails.
pub fn migrate_protected_sqlite(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
    let mut storage = openmls_sqlite_storage::SqliteStorageProvider::<
        ProtectedJsonCodec,
        &mut Connection,
    >::new(connection);
    storage.run_migrations()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: [u8; KEY_BYTES] = [0x31; KEY_BYTES];
    const KEY_B: [u8; KEY_BYTES] = [0x92; KEY_BYTES];

    fn encode(value: &str) -> Vec<u8> {
        with_mls_storage_key(&KEY_A, || ProtectedJsonCodec::to_vec(&value).unwrap()).unwrap()
    }

    #[test]
    fn round_trip_and_randomized_nonces() {
        let first = encode("protected record");
        let second = encode("protected record");
        assert_ne!(&first[1..HEADER_BYTES], &second[1..HEADER_BYTES]);
        assert_eq!(
            with_mls_storage_key(&KEY_A, || {
                ProtectedJsonCodec::from_slice::<String>(&first).unwrap()
            })
            .unwrap(),
            "protected record"
        );
    }

    #[test]
    fn local_record_encryption_binds_key_context_and_scope() {
        let context = b"space-genesis/v1\\0record-id";
        let record = with_mls_storage_key(&KEY_A, || {
            protect_local_record(context, b"encrypted local snapshot")
        })
        .unwrap()
        .unwrap();
        assert_eq!(
            with_mls_storage_key(&KEY_A, || unprotect_local_record(context, &record))
                .unwrap()
                .unwrap(),
            b"encrypted local snapshot"
        );
        assert_eq!(
            with_mls_storage_key(&KEY_A, || unprotect_local_record(b"wrong-context", &record))
                .unwrap(),
            Err(ProtectedCodecError::Decryption)
        );
        assert_eq!(
            unprotect_local_record(context, &record),
            Err(ProtectedCodecError::MissingKey)
        );
    }

    #[test]
    fn rejects_wrong_key_and_tampering() {
        let mut record = encode("value");
        assert_eq!(
            with_mls_storage_key(&KEY_B, || {
                ProtectedJsonCodec::from_slice::<String>(&record)
            })
            .unwrap()
            .unwrap_err(),
            ProtectedCodecError::Decryption
        );

        record[HEADER_BYTES] ^= 1;
        assert_eq!(
            with_mls_storage_key(&KEY_A, || {
                ProtectedJsonCodec::from_slice::<String>(&record)
            })
            .unwrap()
            .unwrap_err(),
            ProtectedCodecError::Decryption
        );
    }

    #[test]
    fn rejects_version_truncation_and_bounds() {
        let record = encode("value");
        let mut wrong_version = record.clone();
        wrong_version[0] = VERSION + 1;
        assert_eq!(
            with_mls_storage_key(&KEY_A, || {
                ProtectedJsonCodec::from_slice::<String>(&wrong_version)
            })
            .unwrap()
            .unwrap_err(),
            ProtectedCodecError::UnsupportedVersion
        );
        assert_eq!(
            with_mls_storage_key(&KEY_A, || {
                ProtectedJsonCodec::from_slice::<String>(&record[..record.len() - 1])
            })
            .unwrap()
            .unwrap_err(),
            ProtectedCodecError::Decryption
        );
        assert_eq!(
            with_mls_storage_key(&KEY_A, || {
                ProtectedJsonCodec::to_vec(&"x".repeat(MAX_PLAINTEXT_BYTES + 1))
            })
            .unwrap()
            .unwrap_err(),
            ProtectedCodecError::TooLarge
        );
        assert_eq!(
            with_mls_storage_key(&KEY_A, || {
                ProtectedJsonCodec::from_slice::<String>(&vec![0; MAX_RECORD_BYTES + 1])
            })
            .unwrap()
            .unwrap_err(),
            ProtectedCodecError::TooLarge
        );
    }

    #[test]
    fn rejects_invalid_key_length_without_replacing_scope() {
        let result = with_mls_storage_key(&[1; KEY_BYTES - 1], || ());
        assert_eq!(result, Err(ProtectedCodecError::InvalidKeyLength));
        assert_eq!(
            ProtectedJsonCodec::to_vec(&"outside"),
            Err(ProtectedCodecError::MissingKey)
        );
    }
    #[test]
    fn requires_scope_and_restores_nested_scope() {
        assert_eq!(
            ProtectedJsonCodec::to_vec(&"outside"),
            Err(ProtectedCodecError::MissingKey)
        );
        let outer_record = with_mls_storage_key(&KEY_A, || {
            let outer_record = ProtectedJsonCodec::to_vec(&"outer").unwrap();
            with_mls_storage_key(&KEY_B, || {
                assert_eq!(
                    ProtectedJsonCodec::from_slice::<String>(&outer_record),
                    Err(ProtectedCodecError::Decryption)
                );
            })
            .unwrap();
            assert_eq!(
                ProtectedJsonCodec::from_slice::<String>(&outer_record).unwrap(),
                "outer"
            );
            outer_record
        })
        .unwrap();
        assert_eq!(
            ProtectedJsonCodec::from_slice::<String>(&outer_record),
            Err(ProtectedCodecError::MissingKey)
        );
    }

    #[test]
    fn restores_scope_during_unwind() {
        with_mls_storage_key(&KEY_A, || {
            let outer_record = ProtectedJsonCodec::to_vec(&"outer").unwrap();
            let result = std::panic::catch_unwind(|| {
                with_mls_storage_key(&KEY_B, || panic!("test unwind")).unwrap();
            });
            assert!(result.is_err());
            assert_eq!(
                ProtectedJsonCodec::from_slice::<String>(&outer_record).unwrap(),
                "outer"
            );
        })
        .unwrap();
        assert_eq!(
            ProtectedJsonCodec::to_vec(&"outside"),
            Err(ProtectedCodecError::MissingKey)
        );
    }
}
