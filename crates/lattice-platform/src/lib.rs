//! Platform adapter ports shared by Android, desktop, and CLI integrations.
//!
//! This crate defines shared contracts for platform adapters and includes an
//! OS-keyring-backed identity protector for desktop and CLI targets.

use core::fmt;
use core::future::Future;
use core::pin::Pin;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use directories::BaseDirs;
use fs4::fs_std::FileExt;
use lattice_identity::{PrivateKeyProtectionError, PrivateKeyProtector};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Maximum UTF-8 byte length for a platform adapter name.
pub const MAX_ADAPTER_NAME_BYTES: usize = 64;
/// Maximum key material accepted by the secure-storage boundary.
pub const MAX_KEY_MATERIAL_BYTES: usize = 4 * 1024;
/// Maximum protected-key ciphertext size.
pub const MAX_PROTECTED_KEY_BYTES: usize = 16 * 1024;
/// Maximum opaque transport envelope size.
pub const MAX_ENVELOPE_BYTES: usize = 256 * 1024;
/// Maximum immutable canonical event size.
pub const MAX_EVENT_BYTES: usize = 1024 * 1024;
/// Maximum number of envelopes committed with one authored event.
pub const MAX_OUTBOX_ITEMS: usize = 64;
/// Maximum combined envelope bytes in one outbox transaction.
pub const MAX_OUTBOX_BYTES: usize = 1024 * 1024;
/// Event identifiers are fixed-width protocol hashes.
pub const EVENT_ID_BYTES: usize = 32;

/// Object-safe async method return type used by platform ports.
pub type PortFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Failure to construct a bounded byte value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ByteBoundsError {
    /// The value must contain at least one byte.
    Empty,
    /// The value exceeds the bound for its type.
    TooLarge,
}

fn check_bytes(bytes: &[u8], limit: usize) -> Result<(), ByteBoundsError> {
    if bytes.is_empty() {
        Err(ByteBoundsError::Empty)
    } else if bytes.len() > limit {
        Err(ByteBoundsError::TooLarge)
    } else {
        Ok(())
    }
}

/// Key material passed to or returned from a secure-storage adapter.
///
/// It intentionally has no `Clone` implementation and its debug output never
/// includes the bytes. Callers should keep its lifetime as short as practical.
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Returns the key material as a shared view.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<Vec<u8>> for SecretBytes {
    type Error = ByteBoundsError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let bytes = Zeroizing::new(bytes);
        check_bytes(&bytes, MAX_KEY_MATERIAL_BYTES)?;
        Ok(Self(bytes))
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}

/// Opaque, bounded bytes returned by a key-protection adapter.
///
/// The ciphertext is portable data, not a platform key handle. Its debug
/// representation omits the ciphertext contents.
pub struct ProtectedKeyCiphertext(Vec<u8>);

impl ProtectedKeyCiphertext {
    /// Returns a shared view of the protected ciphertext.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Transfers the ciphertext bytes to the caller for persistence.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl TryFrom<Vec<u8>> for ProtectedKeyCiphertext {
    type Error = ByteBoundsError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        check_bytes(&bytes, MAX_PROTECTED_KEY_BYTES)?;
        Ok(Self(bytes))
    }
}

impl fmt::Debug for ProtectedKeyCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProtectedKeyCiphertext([REDACTED; {} bytes])",
            self.0.len()
        )
    }
}

/// Stable outcome of an operation at the key-protection boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyProtectionError {
    /// Device or user authentication is required before access can proceed.
    Locked,
    /// The OS protection class currently prevents access to protected data.
    Protected,
    /// The platform key-protection service or requested key is unavailable.
    Unavailable,
    /// Input is invalid for the selected protection operation.
    InvalidInput,
    /// An operation exceeded a platform or port byte bound.
    TooLarge,
    /// The platform operation failed for another reason.
    OperationFailed,
}

/// Securely wraps or unwraps bounded key material without exposing native
/// handles. Success from `protect` is ciphertext; OS states remain typed errors.
pub trait KeyProtector: Send + Sync {
    /// Protects key material and returns only opaque ciphertext on success.
    fn protect(
        &self,
        key_material: SecretBytes,
    ) -> PortFuture<'_, Result<ProtectedKeyCiphertext, KeyProtectionError>>;

    /// Unprotects ciphertext for use by the Rust cryptographic caller.
    fn unprotect(
        &self,
        ciphertext: ProtectedKeyCiphertext,
    ) -> PortFuture<'_, Result<SecretBytes, KeyProtectionError>>;
}

/// Maximum input or output size for the OS-backed identity protector.
pub const MAX_OS_PROTECTED_KEY_BYTES: usize = 4096;
/// Maximum UTF-8 byte length accepted for an exact profile identifier.
pub const MAX_PROFILE_ID_BYTES: usize = 128;

const WRAPPING_KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const PROTECTED_OVERHEAD_BYTES: usize = 1 + NONCE_BYTES + TAG_BYTES;
const HEX: &[u8; 16] = b"0123456789abcdef";
const KEY_FORMAT_VERSION: u8 = 1;
#[cfg(any(
    target_os = "windows",
    target_os = "macos",
    all(unix, not(any(target_os = "android", target_os = "ios")))
))]
const KEYRING_SERVICE: &str = "lattice.identity.wrapping-key.v1";
const AAD_DOMAIN: &[u8] = b"lattice.private-key-wrap\0";

/// Stable, typed failures from the OS-backed identity key protector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OsKeyringProtectionError {
    /// The caller supplied an empty, oversized, or control-containing profile ID.
    InvalidProfileId,
    /// This target does not have a supported OS credential-store backend.
    UnsupportedPlatform,
    /// The key material is empty.
    InvalidInput,
    /// Protected or clear key material exceeded the 4096-byte bound.
    TooLarge,
    /// The ciphertext is shorter than the version, nonce, and authentication tag.
    InvalidFormat,
    /// The ciphertext uses a version this implementation does not support.
    UnsupportedVersion,
    /// No wrapping key exists for this profile.
    MissingKey,
    /// The OS credential store is locked or requires authentication.
    Locked,
    /// The OS credential store is unavailable.
    StoreUnavailable,
    /// The OS credential store failed for another reason.
    StoreFailure,
    /// The operating-system CSPRNG failed.
    RandomSource,
    /// AES-GCM authentication failed.
    AuthenticationFailed,
    /// The cryptographic operation could not be initialized or completed.
    CryptographicFailure,
    /// A process lock was poisoned or the profile file lock could not be acquired.
    SynchronizationFailure,
    /// The stored wrapping key is not exactly 32 bytes.
    InvalidStoredKey,
}

impl fmt::Display for OsKeyringProtectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidProfileId => "invalid keyring profile identifier",
            Self::UnsupportedPlatform => "OS keyring is unavailable on this platform",
            Self::InvalidInput => "invalid key material",
            Self::TooLarge => "key material exceeds its size limit",
            Self::InvalidFormat => "protected key ciphertext is malformed",
            Self::UnsupportedVersion => "protected key version is unsupported",
            Self::MissingKey => "keyring wrapping key is missing",
            Self::Locked => "OS keyring is locked",
            Self::StoreUnavailable => "OS keyring or profile storage is unavailable",
            Self::StoreFailure => "OS keyring operation failed",
            Self::RandomSource => "operating-system random source failed",
            Self::AuthenticationFailed => "protected key authentication failed",
            Self::CryptographicFailure => "protected key operation failed",
            Self::SynchronizationFailure => "keyring profile synchronization failed",
            Self::InvalidStoredKey => "stored keyring wrapping key is malformed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for OsKeyringProtectionError {}

/// Wraps identity private material with a per-profile key held in the OS store.
///
/// Cross-process profile initialization is serialized with a per-user lock
/// file before reading or creating the wrapping key.
pub struct OsKeyringProtector {
    profile_id: String,
    lock_root: Option<PathBuf>,
    store: Option<Arc<dyn CredentialStore>>,
}

impl OsKeyringProtector {
    /// Creates a protector for an exact, bounded profile identifier.
    ///
    /// On Android and unsupported targets construction succeeds for a valid
    /// profile, while protection operations return `UnsupportedPlatform`.
    ///
    /// # Errors
    ///
    /// Returns [`OsKeyringProtectionError::InvalidProfileId`] for an invalid
    /// profile identifier, or a storage error if the profile lock location
    /// cannot be prepared.
    pub fn new(profile_id: &str) -> Result<Self, OsKeyringProtectionError> {
        validate_profile_id(profile_id)?;
        #[cfg(any(
            target_os = "windows",
            target_os = "macos",
            all(unix, not(any(target_os = "android", target_os = "ios")))
        ))]
        let store = Some(platform_credential_store());
        #[cfg(not(any(
            target_os = "windows",
            target_os = "macos",
            all(unix, not(any(target_os = "android", target_os = "ios")))
        )))]
        let store = None;
        let lock_root = store.as_ref().map(|_| default_lock_root()).transpose()?;
        Ok(Self {
            profile_id: profile_id.to_owned(),
            lock_root,
            store,
        })
    }

    /// Wraps private bytes and preserves the precise protection error.
    ///
    /// # Errors
    ///
    /// Returns an error if the platform is unsupported, the input is invalid
    /// or oversized, the wrapping key cannot be accessed, randomness fails,
    /// or encryption fails.
    pub fn wrap_detailed(
        &self,
        private_material: &[u8],
    ) -> Result<Vec<u8>, OsKeyringProtectionError> {
        if self.store.is_none() {
            return Err(OsKeyringProtectionError::UnsupportedPlatform);
        }
        if private_material.is_empty() {
            return Err(OsKeyringProtectionError::InvalidInput);
        }
        if private_material.len() > MAX_OS_PROTECTED_KEY_BYTES {
            return Err(OsKeyringProtectionError::TooLarge);
        }
        let output_len = private_material
            .len()
            .checked_add(PROTECTED_OVERHEAD_BYTES)
            .ok_or(OsKeyringProtectionError::TooLarge)?;
        if output_len > MAX_OS_PROTECTED_KEY_BYTES {
            return Err(OsKeyringProtectionError::TooLarge);
        }

        let key = self.wrapping_key(true)?;
        let mut nonce = Zeroizing::new([0_u8; NONCE_BYTES]);
        getrandom::fill(&mut *nonce).map_err(|_| OsKeyringProtectionError::RandomSource)?;
        let aad = self.associated_data();
        let cipher = Aes256Gcm::new_from_slice(&key[..])
            .map_err(|_| OsKeyringProtectionError::CryptographicFailure)?;
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce[..]),
                Payload {
                    msg: private_material,
                    aad: &aad,
                },
            )
            .map_err(|_| OsKeyringProtectionError::CryptographicFailure)?;

        let mut protected = Vec::with_capacity(output_len);
        protected.push(KEY_FORMAT_VERSION);
        protected.extend_from_slice(&nonce[..]);
        protected.extend_from_slice(&encrypted);
        if protected.len() > MAX_OS_PROTECTED_KEY_BYTES {
            return Err(OsKeyringProtectionError::TooLarge);
        }
        Ok(protected)
    }

    /// Unwraps ciphertext into zeroizing memory with a precise protection error.
    ///
    /// # Errors
    ///
    /// Returns an error if the platform is unsupported, the ciphertext is
    /// malformed or oversized, its version is unsupported, the wrapping key
    /// cannot be accessed, or authentication/decryption fails.
    pub fn unwrap_detailed(
        &self,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, OsKeyringProtectionError> {
        if self.store.is_none() {
            return Err(OsKeyringProtectionError::UnsupportedPlatform);
        }
        if ciphertext.len() > MAX_OS_PROTECTED_KEY_BYTES {
            return Err(OsKeyringProtectionError::TooLarge);
        }
        if ciphertext.len() < PROTECTED_OVERHEAD_BYTES {
            return Err(OsKeyringProtectionError::InvalidFormat);
        }
        if ciphertext[0] != KEY_FORMAT_VERSION {
            return Err(OsKeyringProtectionError::UnsupportedVersion);
        }

        let key = self.wrapping_key(false)?;
        let aad = self.associated_data();
        let cipher = Aes256Gcm::new_from_slice(&key[..])
            .map_err(|_| OsKeyringProtectionError::CryptographicFailure)?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&ciphertext[1..=NONCE_BYTES]),
                Payload {
                    msg: &ciphertext[1 + NONCE_BYTES..],
                    aad: &aad,
                },
            )
            .map_err(|_| OsKeyringProtectionError::AuthenticationFailed)?;
        if plaintext.len() > MAX_OS_PROTECTED_KEY_BYTES {
            return Err(OsKeyringProtectionError::TooLarge);
        }
        Ok(Zeroizing::new(plaintext))
    }
    fn profile_lock(&self) -> Result<File, OsKeyringProtectionError> {
        let path = self.profile_lock_path()?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)
            .map_err(|_| OsKeyringProtectionError::StoreUnavailable)?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match file.try_lock_exclusive() {
                Ok(true) => return Ok(file),
                Ok(false) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                Ok(false) | Err(_) => {
                    return Err(OsKeyringProtectionError::SynchronizationFailure);
                }
            }
        }
    }

    fn profile_lock_path(&self) -> Result<PathBuf, OsKeyringProtectionError> {
        let lock_root = self
            .lock_root
            .as_ref()
            .ok_or(OsKeyringProtectionError::StoreUnavailable)?;
        std::fs::create_dir_all(lock_root)
            .map_err(|_| OsKeyringProtectionError::StoreUnavailable)?;
        let digest = Sha256::digest(self.profile_id.as_bytes());
        let mut file_name = String::with_capacity(4 + 64 + 5);
        file_name.push_str("key-");
        for byte in digest {
            file_name.push(char::from(HEX[usize::from(byte >> 4)]));
            file_name.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        file_name.push_str(".lock");
        Ok(lock_root.join(file_name))
    }

    fn associated_data(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + 1 + self.profile_id.len());
        aad.extend_from_slice(AAD_DOMAIN);
        aad.push(KEY_FORMAT_VERSION);
        aad.extend_from_slice(self.profile_id.as_bytes());
        aad
    }

    fn wrapping_key(
        &self,
        create_if_missing: bool,
    ) -> Result<Zeroizing<[u8; WRAPPING_KEY_BYTES]>, OsKeyringProtectionError> {
        let store = self
            .store
            .as_ref()
            .ok_or(OsKeyringProtectionError::UnsupportedPlatform)?;
        let _guard = KEYRING_OPERATION_LOCK
            .lock()
            .map_err(|_| OsKeyringProtectionError::SynchronizationFailure)?;
        let _file_lock = self.profile_lock()?;
        match store.get_secret(&self.profile_id) {
            Ok(stored_key) => {
                let stored_key = Zeroizing::new(stored_key);
                if stored_key.len() != WRAPPING_KEY_BYTES {
                    return Err(OsKeyringProtectionError::InvalidStoredKey);
                }
                let mut key = Zeroizing::new([0_u8; WRAPPING_KEY_BYTES]);
                key[..].copy_from_slice(stored_key.as_slice());
                Ok(key)
            }
            Err(CredentialStoreError::Missing) if create_if_missing => {
                let mut key = Zeroizing::new([0_u8; WRAPPING_KEY_BYTES]);
                getrandom::fill(&mut *key).map_err(|_| OsKeyringProtectionError::RandomSource)?;
                store
                    .set_secret(&self.profile_id, &key[..])
                    .map_err(map_store_error)?;
                Ok(key)
            }
            Err(error) => Err(map_store_error(error)),
        }
    }

    #[cfg(test)]
    fn with_store(
        profile_id: impl Into<String>,
        store: Arc<dyn CredentialStore>,
    ) -> Result<Self, OsKeyringProtectionError> {
        let profile_id = profile_id.into();
        validate_profile_id(&profile_id)?;
        Ok(Self {
            profile_id,
            lock_root: Some(
                std::env::temp_dir()
                    .join("lattice-keyring-lock-tests")
                    .join(std::process::id().to_string()),
            ),
            store: Some(store),
        })
    }
}

impl PrivateKeyProtector for OsKeyringProtector {
    fn wrap(&self, private_material: &[u8]) -> Result<Vec<u8>, PrivateKeyProtectionError> {
        self.wrap_detailed(private_material)
            .map_err(|_| PrivateKeyProtectionError)
    }

    fn unwrap(&self, ciphertext: &[u8]) -> Result<Vec<u8>, PrivateKeyProtectionError> {
        let private_material = self
            .unwrap_detailed(ciphertext)
            .map_err(|_| PrivateKeyProtectionError)?;
        Ok(private_material.to_vec())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CredentialStoreError {
    Missing,
    Locked,
    Unavailable,
    Failure,
}

trait CredentialStore: Send + Sync {
    fn get_secret(&self, profile_id: &str) -> Result<Vec<u8>, CredentialStoreError>;
    fn set_secret(&self, profile_id: &str, secret: &[u8]) -> Result<(), CredentialStoreError>;
}

static KEYRING_OPERATION_LOCK: Mutex<()> = Mutex::new(());

fn validate_profile_id(profile_id: &str) -> Result<(), OsKeyringProtectionError> {
    if profile_id.is_empty()
        || profile_id.len() > MAX_PROFILE_ID_BYTES
        || profile_id.chars().any(char::is_control)
    {
        return Err(OsKeyringProtectionError::InvalidProfileId);
    }
    Ok(())
}

fn default_lock_root() -> Result<PathBuf, OsKeyringProtectionError> {
    BaseDirs::new()
        .map(|directories| {
            directories
                .data_local_dir()
                .join("Astraive")
                .join("Lattice")
                .join("keyring-locks")
        })
        .ok_or(OsKeyringProtectionError::StoreUnavailable)
}

fn map_store_error(error: CredentialStoreError) -> OsKeyringProtectionError {
    match error {
        CredentialStoreError::Missing => OsKeyringProtectionError::MissingKey,
        CredentialStoreError::Locked => OsKeyringProtectionError::Locked,
        CredentialStoreError::Unavailable => OsKeyringProtectionError::StoreUnavailable,
        CredentialStoreError::Failure => OsKeyringProtectionError::StoreFailure,
    }
}

#[cfg(any(
    target_os = "windows",
    target_os = "macos",
    all(unix, not(any(target_os = "android", target_os = "ios")))
))]
fn platform_credential_store() -> Arc<dyn CredentialStore> {
    Arc::new(KeyringCredentialStore)
}

#[cfg(any(
    target_os = "windows",
    target_os = "macos",
    all(unix, not(any(target_os = "android", target_os = "ios")))
))]
struct KeyringCredentialStore;

#[cfg(any(
    target_os = "windows",
    target_os = "macos",
    all(unix, not(any(target_os = "android", target_os = "ios")))
))]
impl CredentialStore for KeyringCredentialStore {
    fn get_secret(&self, profile_id: &str) -> Result<Vec<u8>, CredentialStoreError> {
        use keyring::v1::Entry;

        let entry =
            Entry::new(KEYRING_SERVICE, profile_id).map_err(|error| map_keyring_error(&error))?;
        entry
            .get_secret()
            .map_err(|error| map_keyring_error(&error))
    }

    fn set_secret(&self, profile_id: &str, secret: &[u8]) -> Result<(), CredentialStoreError> {
        use keyring::v1::Entry;

        let entry =
            Entry::new(KEYRING_SERVICE, profile_id).map_err(|error| map_keyring_error(&error))?;
        entry
            .set_secret(secret)
            .map_err(|error| map_keyring_error(&error))
    }
}

#[cfg(any(
    target_os = "windows",
    target_os = "macos",
    all(unix, not(any(target_os = "android", target_os = "ios")))
))]
fn map_keyring_error(error: &keyring::v1::Error) -> CredentialStoreError {
    use keyring::v1::Error as KeyringError;

    match error {
        KeyringError::NoEntry => CredentialStoreError::Missing,
        KeyringError::NoStorageAccess(_) => CredentialStoreError::Locked,
        KeyringError::NoDefaultStore | KeyringError::NotSupportedByStore(_) => {
            CredentialStoreError::Unavailable
        }
        _ => CredentialStoreError::Failure,
    }
}

/// Monotonic milliseconds measured from an adapter-defined runtime origin.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MonotonicMillis(u64);

impl MonotonicMillis {
    /// Constructs a monotonic reading in milliseconds.
    #[must_use]
    pub const fn from_millis(value: u64) -> Self {
        Self(value)
    }

    /// Returns the milliseconds since the adapter-defined runtime origin.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// Computes elapsed milliseconds, returning `None` for a regressing sample.
    #[must_use]
    pub const fn elapsed_since(self, earlier: Self) -> Option<u64> {
        self.0.checked_sub(earlier.0)
    }
}

/// A UTC Unix-millisecond hint for display only; it is not an ordering source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WallTimeHint(i64);

impl WallTimeHint {
    /// Constructs a wall-time hint in signed Unix milliseconds.
    #[must_use]
    pub const fn from_unix_millis(value: i64) -> Self {
        Self(value)
    }

    /// Returns signed Unix milliseconds.
    #[must_use]
    pub const fn as_unix_millis(self) -> i64 {
        self.0
    }
}

/// Coherent pair of a monotonic reading and optional untrusted wall-time hint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockReading {
    monotonic: MonotonicMillis,
    wall_time_hint: Option<WallTimeHint>,
}

impl ClockReading {
    /// Creates a clock reading; wall time may be absent or inaccurate.
    #[must_use]
    pub const fn new(monotonic: MonotonicMillis, wall_time_hint: Option<WallTimeHint>) -> Self {
        Self {
            monotonic,
            wall_time_hint,
        }
    }

    /// Returns the monotonic runtime reading.
    #[must_use]
    pub const fn monotonic(self) -> MonotonicMillis {
        self.monotonic
    }

    /// Returns the optional wall-time display hint.
    #[must_use]
    pub const fn wall_time_hint(self) -> Option<WallTimeHint> {
        self.wall_time_hint
    }
}

/// Injected source of monotonic elapsed time and an untrusted wall-time hint.
///
/// Implementations MUST return monotonic readings that do not decrease over
/// the lifetime of the same clock instance. Wall time may jump in either
/// direction and MUST NOT be used for elapsed-time or authorization ordering.
pub trait Clock: Send + Sync {
    /// Returns a reading; only its monotonic component is suitable for elapsed time.
    fn reading(&self) -> ClockReading;
}

/// A bounded adapter identifier containing only ASCII letters, digits, `-`,
/// `_`, or `.`; it must begin with an ASCII letter or digit.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AdapterName(String);

impl AdapterName {
    /// Returns the validated adapter name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Failure to construct an adapter name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterNameError {
    /// Names cannot be empty.
    Empty,
    /// Name is longer than `MAX_ADAPTER_NAME_BYTES`.
    TooLong,
    /// Name contains characters outside the documented portable set.
    InvalidCharacter,
}

impl TryFrom<String> for AdapterName {
    type Error = AdapterNameError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        if name.is_empty() {
            return Err(AdapterNameError::Empty);
        }
        if name.len() > MAX_ADAPTER_NAME_BYTES {
            return Err(AdapterNameError::TooLong);
        }
        let mut bytes = name.bytes();
        let first = bytes.next().ok_or(AdapterNameError::Empty)?;
        if !first.is_ascii_alphanumeric()
            || !bytes.all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
        {
            return Err(AdapterNameError::InvalidCharacter);
        }
        Ok(Self(name))
    }
}

/// Opaque bounded bytes passed to a transport adapter.
pub struct EnvelopeBytes(Vec<u8>);

impl EnvelopeBytes {
    /// Returns the opaque envelope as a shared byte view.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Transfers ownership of the opaque envelope bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl TryFrom<Vec<u8>> for EnvelopeBytes {
    type Error = ByteBoundsError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        check_bytes(&bytes, MAX_ENVELOPE_BYTES)?;
        Ok(Self(bytes))
    }
}

impl fmt::Debug for EnvelopeBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EnvelopeBytes([OPAQUE; {} bytes])", self.0.len())
    }
}

/// Owned maximum envelope size and identity snapshot for a transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportCapabilities {
    name: AdapterName,
    max_envelope_bytes: usize,
}

impl TransportCapabilities {
    /// Constructs a capability snapshot with a nonzero supported envelope cap.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityError::ZeroEnvelopeLimit`] for a zero limit or
    /// [`CapabilityError::LimitExceedsPortMaximum`] when the limit exceeds
    /// [`MAX_ENVELOPE_BYTES`].
    pub fn new(name: AdapterName, max_envelope_bytes: usize) -> Result<Self, CapabilityError> {
        if max_envelope_bytes == 0 {
            return Err(CapabilityError::ZeroEnvelopeLimit);
        }
        if max_envelope_bytes > MAX_ENVELOPE_BYTES {
            return Err(CapabilityError::LimitExceedsPortMaximum);
        }
        Ok(Self {
            name,
            max_envelope_bytes,
        })
    }

    /// Returns the validated adapter name.
    #[must_use]
    pub fn name(&self) -> &AdapterName {
        &self.name
    }

    /// Returns the largest envelope this adapter accepts.
    #[must_use]
    pub const fn max_envelope_bytes(&self) -> usize {
        self.max_envelope_bytes
    }
}

/// Failure to define an adapter capability snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityError {
    /// An adapter must accept at least one byte to advertise send capability.
    ZeroEnvelopeLimit,
    /// The adapter limit exceeds the shared port's maximum buffer bound.
    LimitExceedsPortMaximum,
}

/// Observable transport adapter lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportLifecycle {
    /// Adapter is not started.
    Stopped,
    /// Adapter is acquiring its platform resources.
    Starting,
    /// Adapter can attempt sends.
    Running,
    /// Adapter is releasing its platform resources.
    Stopping,
    /// Adapter encountered a failure that prevents normal operation.
    Faulted,
}

/// Exact-hop result of submitting one opaque envelope.
///
/// Neither value means that the destination received or delivered the event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportReceipt {
    /// The operating system accepted the envelope into its local send queue.
    QueuedToOs,
    /// The immediate next hop accepted the envelope.
    AcceptedByNextHop,
}

/// Stable transport operation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportError {
    /// The adapter is not in the running state.
    NotRunning,
    /// The envelope exceeds this adapter's advertised limit.
    EnvelopeTooLarge,
    /// The platform denied required permission.
    PermissionDenied,
    /// The platform transport is unavailable.
    Unavailable,
    /// The platform rejected the envelope or its framing.
    InvalidEnvelope,
    /// The operation failed for another reason.
    OperationFailed,
}

/// Lifecycle and bounded opaque send/receive boundary for one platform
/// transport.
///
/// A successful send returns only exact-hop acceptance. Destination delivery,
/// event validity, retries, and delivery policy belong to higher layers.
pub trait TransportAdapter: Send + Sync {
    /// Returns an owned snapshot of this adapter's bounded capabilities.
    fn capabilities(&self) -> TransportCapabilities;

    /// Returns the adapter's current lifecycle state.
    fn lifecycle(&self) -> TransportLifecycle;

    /// Starts the adapter and acquires its platform resources.
    fn start(&self) -> PortFuture<'_, Result<(), TransportError>>;

    /// Stops the adapter and releases its platform resources.
    fn stop(&self) -> PortFuture<'_, Result<(), TransportError>>;

    /// Sends one opaque envelope and returns the exact-hop receipt only.
    fn send(
        &self,
        envelope: EnvelopeBytes,
    ) -> PortFuture<'_, Result<TransportReceipt, TransportError>>;

    /// Receives one complete bounded opaque envelope, if one is available.
    ///
    /// Adapters must inspect framing lengths before allocation and return only
    /// values constructed through the shared `EnvelopeBytes` bound.
    fn receive(&self) -> PortFuture<'_, Result<Option<EnvelopeBytes>, TransportError>>;
}

/// Fixed-width event identifier for immutable canonical event bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EventId([u8; EVENT_ID_BYTES]);

impl EventId {
    /// Constructs an event identifier from its fixed-width bytes.
    #[must_use]
    pub const fn new(bytes: [u8; EVENT_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; EVENT_ID_BYTES] {
        &self.0
    }
}

/// Immutable bounded canonical event bytes.
pub struct EventBytes(Vec<u8>);

impl EventBytes {
    /// Returns canonical event bytes as a shared view.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Transfers ownership of the canonical bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl TryFrom<Vec<u8>> for EventBytes {
    type Error = ByteBoundsError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        check_bytes(&bytes, MAX_EVENT_BYTES)?;
        Ok(Self(bytes))
    }
}

impl fmt::Debug for EventBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EventBytes([IMMUTABLE; {} bytes])", self.0.len())
    }
}

/// Locally authored immutable event record.
pub struct AuthoredEvent {
    id: EventId,
    canonical_bytes: EventBytes,
}

impl AuthoredEvent {
    /// Creates an event record from an identifier and bounded canonical bytes.
    #[must_use]
    pub fn new(id: EventId, canonical_bytes: EventBytes) -> Self {
        Self {
            id,
            canonical_bytes,
        }
    }

    /// Returns the stable event identifier.
    #[must_use]
    pub const fn id(&self) -> EventId {
        self.id
    }

    /// Returns canonical bytes without granting mutable access.
    #[must_use]
    pub fn canonical_bytes(&self) -> &EventBytes {
        &self.canonical_bytes
    }
}

impl fmt::Debug for AuthoredEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthoredEvent")
            .field("id", &self.id)
            .field("canonical_bytes", &self.canonical_bytes)
            .finish()
    }
}

/// Envelopes to atomically add to the local outbox with an authored event.
pub struct OutboxBatch {
    envelopes: Vec<EnvelopeBytes>,
    total_bytes: usize,
}

impl OutboxBatch {
    /// Validates entry-count and aggregate byte bounds before a transaction.
    ///
    /// # Errors
    ///
    /// Returns [`OutboxBatchError::TooManyEntries`] if the entry-count bound
    /// is exceeded, or [`OutboxBatchError::TotalBytesExceeded`] if the
    /// aggregate byte bound is exceeded.
    pub fn try_new(envelopes: Vec<EnvelopeBytes>) -> Result<Self, OutboxBatchError> {
        if envelopes.len() > MAX_OUTBOX_ITEMS {
            return Err(OutboxBatchError::TooManyEntries);
        }
        let mut total_bytes = 0usize;
        for envelope in &envelopes {
            total_bytes = total_bytes
                .checked_add(envelope.as_bytes().len())
                .ok_or(OutboxBatchError::TotalBytesExceeded)?;
        }
        if total_bytes > MAX_OUTBOX_BYTES {
            return Err(OutboxBatchError::TotalBytesExceeded);
        }
        Ok(Self {
            envelopes,
            total_bytes,
        })
    }

    /// Returns the number of queued envelopes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.envelopes.len()
    }

    /// Returns whether the batch has no envelopes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.envelopes.is_empty()
    }

    /// Returns the combined opaque envelope byte count.
    #[must_use]
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Transfers the validated envelopes to a repository implementation.
    #[must_use]
    pub fn into_envelopes(self) -> Vec<EnvelopeBytes> {
        self.envelopes
    }
}

impl fmt::Debug for OutboxBatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboxBatch")
            .field("entries", &self.envelopes.len())
            .field("total_bytes", &self.total_bytes)
            .finish()
    }
}

/// Failure to construct a bounded outbox transaction batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboxBatchError {
    /// More than `MAX_OUTBOX_ITEMS` envelopes were supplied.
    TooManyEntries,
    /// The combined envelope bytes exceed `MAX_OUTBOX_BYTES`.
    TotalBytesExceeded,
}

/// Stable local event-repository failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventRepositoryError {
    /// The immutable event identifier already exists.
    EventAlreadyExists,
    /// Local storage is unavailable.
    Unavailable,
    /// The transaction violates a repository boundary.
    InvalidTransaction,
    /// The operation failed for another reason.
    OperationFailed,
}

/// Atomic local authored-event/outbox transaction and immutable event loader.
pub trait EventRepository: Send + Sync {
    /// Atomically persists the event and all outbox entries, or persists none.
    ///
    /// Success reports only local commit; it does not imply transport or
    /// destination delivery.
    fn commit_authored_event(
        &self,
        event: AuthoredEvent,
        outbox: OutboxBatch,
    ) -> PortFuture<'_, Result<(), EventRepositoryError>>;

    /// Loads immutable canonical event bytes by identifier.
    fn load_event(
        &self,
        id: EventId,
    ) -> PortFuture<'_, Result<Option<AuthoredEvent>, EventRepositoryError>>;
}

#[cfg(test)]
mod os_keyring_protector_tests {
    use super::{
        CredentialStore, CredentialStoreError, MAX_OS_PROTECTED_KEY_BYTES, MAX_PROFILE_ID_BYTES,
        OsKeyringProtectionError, OsKeyringProtector, PROTECTED_OVERHEAD_BYTES,
        PrivateKeyProtector,
    };
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, MutexGuard};

    fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[derive(Default)]
    struct MemoryStore {
        entries: Mutex<HashMap<String, Vec<u8>>>,
        get_error: Mutex<Option<CredentialStoreError>>,
        set_error: Mutex<Option<CredentialStoreError>>,
    }

    impl CredentialStore for MemoryStore {
        fn get_secret(&self, profile_id: &str) -> Result<Vec<u8>, CredentialStoreError> {
            if let Some(error) = *locked(&self.get_error) {
                return Err(error);
            }
            locked(&self.entries)
                .get(profile_id)
                .cloned()
                .ok_or(CredentialStoreError::Missing)
        }

        fn set_secret(&self, profile_id: &str, secret: &[u8]) -> Result<(), CredentialStoreError> {
            if let Some(error) = *locked(&self.set_error) {
                return Err(error);
            }
            locked(&self.entries).insert(profile_id.to_owned(), secret.to_vec());
            Ok(())
        }
    }

    fn protector(profile_id: &str, store: &Arc<MemoryStore>) -> OsKeyringProtector {
        match OsKeyringProtector::with_store(profile_id, store.clone()) {
            Ok(protector) => protector,
            Err(error) => panic!("test profile rejected: {error:?}"),
        }
    }

    #[test]
    fn wraps_and_unwraps_identity_bytes_through_the_identity_trait() {
        let store = Arc::new(MemoryStore::default());
        let protector = protector("profile-primary", &store);
        let private_material = b"identity private material";

        let ciphertext = PrivateKeyProtector::wrap(&protector, private_material).unwrap();
        assert_eq!(ciphertext[0], 1);
        assert_eq!(
            ciphertext.len(),
            private_material.len() + PROTECTED_OVERHEAD_BYTES
        );
        assert_ne!(ciphertext.as_slice(), &private_material[..]);
        let wrapping_key = locked(&store.entries)
            .get("profile-primary")
            .unwrap()
            .clone();
        assert_eq!(wrapping_key.len(), 32);

        let reopened = PrivateKeyProtector::unwrap(&protector, &ciphertext).unwrap();
        assert_eq!(reopened.as_slice(), &private_material[..]);
    }

    #[test]
    fn rejects_tampering_and_ciphertext_copied_to_another_profile() {
        let store = Arc::new(MemoryStore::default());
        let first_profile = protector("profile-one", &store);
        let ciphertext = first_profile.wrap_detailed(b"private key").unwrap();

        let mut tampered = ciphertext.clone();
        let last_byte = tampered.len() - 1;
        tampered[last_byte] ^= 1;
        assert_eq!(
            first_profile.unwrap_detailed(&tampered).unwrap_err(),
            OsKeyringProtectionError::AuthenticationFailed
        );

        let wrapping_key = locked(&store.entries).get("profile-one").unwrap().clone();
        locked(&store.entries).insert("profile-two".to_owned(), wrapping_key);
        let second_profile = protector("profile-two", &store);
        assert_eq!(
            second_profile.unwrap_detailed(&ciphertext).unwrap_err(),
            OsKeyringProtectionError::AuthenticationFailed
        );
    }

    #[test]
    fn rejects_unsupported_versions_invalid_lengths_and_oversized_data() {
        let store = Arc::new(MemoryStore::default());
        let protector = protector("profile-bounds", &store);
        assert_eq!(
            protector.wrap_detailed(&[]),
            Err(OsKeyringProtectionError::InvalidInput)
        );

        let mut unknown_version = vec![0; PROTECTED_OVERHEAD_BYTES];
        unknown_version[0] = 2;
        assert_eq!(
            protector.unwrap_detailed(&unknown_version).unwrap_err(),
            OsKeyringProtectionError::UnsupportedVersion
        );
        assert_eq!(
            protector
                .unwrap_detailed(&[1; PROTECTED_OVERHEAD_BYTES - 1])
                .unwrap_err(),
            OsKeyringProtectionError::InvalidFormat
        );
        assert_eq!(
            protector
                .unwrap_detailed(&vec![1; MAX_OS_PROTECTED_KEY_BYTES + 1])
                .unwrap_err(),
            OsKeyringProtectionError::TooLarge
        );
        assert_eq!(
            protector.wrap_detailed(&vec![1; MAX_OS_PROTECTED_KEY_BYTES + 1]),
            Err(OsKeyringProtectionError::TooLarge)
        );

        let max_plaintext = vec![0x23; MAX_OS_PROTECTED_KEY_BYTES - PROTECTED_OVERHEAD_BYTES];
        let max_ciphertext = protector.wrap_detailed(&max_plaintext).unwrap();
        assert_eq!(max_ciphertext.len(), MAX_OS_PROTECTED_KEY_BYTES);
        assert_eq!(
            &*protector.unwrap_detailed(&max_ciphertext).unwrap(),
            max_plaintext.as_slice()
        );
        assert_eq!(
            protector.wrap_detailed(&vec![
                1;
                MAX_OS_PROTECTED_KEY_BYTES - PROTECTED_OVERHEAD_BYTES
                    + 1
            ]),
            Err(OsKeyringProtectionError::TooLarge)
        );
    }

    #[test]
    fn profile_identifiers_are_byte_bounded_and_reject_controls() {
        assert_eq!(
            OsKeyringProtector::new("").err(),
            Some(OsKeyringProtectionError::InvalidProfileId)
        );
        assert_eq!(
            OsKeyringProtector::new("profile\nname").err(),
            Some(OsKeyringProtectionError::InvalidProfileId)
        );
        let oversized_ascii = "x".repeat(MAX_PROFILE_ID_BYTES + 1);
        assert_eq!(
            OsKeyringProtector::new(&oversized_ascii).err(),
            Some(OsKeyringProtectionError::InvalidProfileId)
        );
        let oversized_utf8 = "é".repeat(MAX_PROFILE_ID_BYTES / 2 + 1);
        assert_eq!(
            OsKeyringProtector::new(&oversized_utf8).err(),
            Some(OsKeyringProtectionError::InvalidProfileId)
        );
    }

    #[test]
    fn distinguishes_missing_locked_and_failed_credential_store_operations() {
        let store = Arc::new(MemoryStore::default());
        let protector = protector("profile-errors", &store);
        let valid_shape = vec![1; PROTECTED_OVERHEAD_BYTES];
        assert_eq!(
            protector.unwrap_detailed(&valid_shape).unwrap_err(),
            OsKeyringProtectionError::MissingKey
        );

        *locked(&store.get_error) = Some(CredentialStoreError::Locked);
        assert_eq!(
            protector.unwrap_detailed(&valid_shape).unwrap_err(),
            OsKeyringProtectionError::Locked
        );

        *locked(&store.get_error) = Some(CredentialStoreError::Unavailable);
        assert_eq!(
            protector.unwrap_detailed(&valid_shape).unwrap_err(),
            OsKeyringProtectionError::StoreUnavailable
        );

        *locked(&store.get_error) = Some(CredentialStoreError::Failure);
        assert_eq!(
            protector.unwrap_detailed(&valid_shape).unwrap_err(),
            OsKeyringProtectionError::StoreFailure
        );

        *locked(&store.get_error) = None;
        *locked(&store.set_error) = Some(CredentialStoreError::Failure);
        assert_eq!(
            protector.wrap_detailed(b"private key"),
            Err(OsKeyringProtectionError::StoreFailure)
        );
    }

    #[test]
    fn profile_key_lock_is_exclusive_across_independent_file_handles() {
        use super::FileExt;

        let store = Arc::new(MemoryStore::default());
        let protector = protector("profile-lock", &store);
        let held_lock = protector.profile_lock().expect("acquire profile lock");
        let second_handle = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(protector.profile_lock_path().expect("lock path"))
            .expect("open second lock handle");
        assert!(
            !second_handle
                .try_lock_exclusive()
                .expect("probe competing lock")
        );

        drop(held_lock);
        assert!(
            second_handle
                .try_lock_exclusive()
                .expect("acquire released lock")
        );
        second_handle.unlock().expect("release second lock");
    }

    #[test]
    fn unavailable_credential_store_fails_closed() {
        let protector = OsKeyringProtector {
            profile_id: "profile-no-store".to_owned(),
            lock_root: None,
            store: None,
        };
        assert_eq!(
            protector.wrap_detailed(b"private key"),
            Err(OsKeyringProtectionError::UnsupportedPlatform)
        );
        assert_eq!(
            protector
                .unwrap_detailed(&[1; PROTECTED_OVERHEAD_BYTES])
                .err(),
            Some(OsKeyringProtectionError::UnsupportedPlatform)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_traits_are_object_safe() {
        fn accepts_ports(
            _: &dyn KeyProtector,
            _: &dyn Clock,
            _: &dyn TransportAdapter,
            _: &dyn EventRepository,
        ) {
        }

        let _ = accepts_ports;
    }

    #[test]
    fn transport_receipts_describe_only_the_exact_hop() {
        fn receipt_name(receipt: TransportReceipt) -> &'static str {
            match receipt {
                TransportReceipt::QueuedToOs => "queued to OS",
                TransportReceipt::AcceptedByNextHop => "accepted by next hop",
            }
        }

        assert_eq!(receipt_name(TransportReceipt::QueuedToOs), "queued to OS");
        assert_eq!(
            receipt_name(TransportReceipt::AcceptedByNextHop),
            "accepted by next hop"
        );
    }

    #[test]
    fn byte_types_reject_oversized_buffers_and_redact_secrets() {
        assert_eq!(
            EnvelopeBytes::try_from(vec![0; MAX_ENVELOPE_BYTES + 1]).unwrap_err(),
            ByteBoundsError::TooLarge
        );
        assert_eq!(
            EventBytes::try_from(vec![0; MAX_EVENT_BYTES + 1]).unwrap_err(),
            ByteBoundsError::TooLarge
        );
        assert_eq!(
            ProtectedKeyCiphertext::try_from(vec![0; MAX_PROTECTED_KEY_BYTES + 1]).unwrap_err(),
            ByteBoundsError::TooLarge
        );
        assert_eq!(
            SecretBytes::try_from(vec![0; MAX_KEY_MATERIAL_BYTES + 1]).unwrap_err(),
            ByteBoundsError::TooLarge
        );

        let secret = SecretBytes::try_from(b"private-key-material".to_vec()).unwrap();
        let debug = format!("{secret:?}");
        assert!(!debug.contains("private-key-material"));
        assert!(debug.contains("REDACTED"));
        let ciphertext = ProtectedKeyCiphertext::try_from(b"ciphertext-secret".to_vec()).unwrap();
        let debug = format!("{ciphertext:?}");
        assert!(!debug.contains("ciphertext-secret"));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn key_protection_errors_distinguish_lock_from_unavailability() {
        assert_ne!(KeyProtectionError::Locked, KeyProtectionError::Unavailable);
        assert_ne!(
            KeyProtectionError::Protected,
            KeyProtectionError::Unavailable
        );
    }

    #[test]
    fn elapsed_time_uses_monotonic_reading_not_wall_time() {
        let earlier = ClockReading::new(
            MonotonicMillis::from_millis(10_000),
            Some(WallTimeHint::from_unix_millis(1_800_000_000_000)),
        );
        let later = ClockReading::new(
            MonotonicMillis::from_millis(10_125),
            Some(WallTimeHint::from_unix_millis(1_700_000_000_000)),
        );

        assert_eq!(
            later.monotonic().elapsed_since(earlier.monotonic()),
            Some(125)
        );
        assert_eq!(earlier.monotonic().elapsed_since(later.monotonic()), None);
        assert_ne!(earlier.wall_time_hint(), later.wall_time_hint());
    }

    #[test]
    fn adapter_names_and_outbox_batches_are_bounded() {
        assert_eq!(
            AdapterName::try_from("nearby transport".to_owned()).unwrap_err(),
            AdapterNameError::InvalidCharacter
        );
        assert_eq!(
            AdapterName::try_from("a".repeat(MAX_ADAPTER_NAME_BYTES + 1)).unwrap_err(),
            AdapterNameError::TooLong
        );

        let entries = (0..=MAX_OUTBOX_ITEMS)
            .map(|_| EnvelopeBytes::try_from(vec![1]).unwrap())
            .collect();
        assert_eq!(
            OutboxBatch::try_new(entries).unwrap_err(),
            OutboxBatchError::TooManyEntries
        );
        let entries = (0..5)
            .map(|_| EnvelopeBytes::try_from(vec![1; MAX_ENVELOPE_BYTES]).unwrap())
            .collect();
        assert_eq!(
            OutboxBatch::try_new(entries).unwrap_err(),
            OutboxBatchError::TotalBytesExceeded
        );
    }
}
