//! UniFFI-owned mobile boundary for the local Rust profile.

use std::sync::{Arc, Mutex, MutexGuard};

use lattice_core::{Client, CoreError, DeviceIdentityInfo as CoreIdentityInfo};
use lattice_identity::{IdentityError, PrivateKeyProtectionError, PrivateKeyProtector};
use thiserror::Error;

uniffi::setup_scaffolding!();

/// OS keystore bridge. Implementations must wrap bytes with a non-exportable,
/// profile-bound platform key and must fail closed when that key is unavailable.
#[derive(Debug, Error, uniffi::Error)]
pub enum ProtectorError {
    /// The native keystore denied access or could not protect the bytes.
    #[error("platform key protection failed")]
    Failure,
}

#[uniffi::export(with_foreign)]
pub trait PlatformKeyProtector: Send + Sync {
    /// Wraps private material for the exact profile identifier.
    ///
    /// # Errors
    ///
    /// Returns `ProtectorError` when the native keystore refuses protection.
    fn wrap(&self, profile_id: String, clear_material: Vec<u8>) -> Result<Vec<u8>, ProtectorError>;

    /// Unwraps ciphertext only for the exact profile identifier.
    ///
    /// # Errors
    ///
    /// Returns `ProtectorError` when the native keystore refuses or cannot
    /// authenticate the ciphertext.
    fn unwrap(&self, profile_id: String, ciphertext: Vec<u8>) -> Result<Vec<u8>, ProtectorError>;
}

/// Public, non-secret identity snapshot for native UI presentation.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MobileIdentityInfo {
    /// Versioned public identity bundle.
    pub public_bundle: Vec<u8>,
    /// Domain-separated fingerprint of the exact public bundle.
    pub fingerprint: Vec<u8>,
}

impl From<CoreIdentityInfo> for MobileIdentityInfo {
    fn from(info: CoreIdentityInfo) -> Self {
        Self {
            public_bundle: info.public_bundle.to_vec(),
            fingerprint: info.fingerprint.to_vec(),
        }
    }
}

/// Stable mobile-safe failures that do not disclose key material or SQL details.
#[derive(Debug, Error, uniffi::Error)]
pub enum MobileError {
    /// Profile identifiers must be 1–128 printable ASCII characters.
    #[error("invalid profile identifier")]
    InvalidProfileId,
    /// The local profile could not be opened with its OS-protected keys.
    #[error("profile could not be opened")]
    ProfileOpenFailed,
    /// The native key protector failed or denied access.
    #[error("platform key protection failed")]
    KeyProtectionFailed,
    /// The profile lock was poisoned by a prior Rust panic.
    #[error("profile is unavailable")]
    ProfileUnavailable,
}

struct ProfileProtector {
    profile_id: String,
    platform: Arc<dyn PlatformKeyProtector>,
}

impl PrivateKeyProtector for ProfileProtector {
    fn wrap(&self, clear_material: &[u8]) -> Result<Vec<u8>, PrivateKeyProtectionError> {
        self.platform
            .wrap(self.profile_id.clone(), clear_material.to_vec())
            .map_err(|_| PrivateKeyProtectionError)
    }

    fn unwrap(&self, ciphertext: &[u8]) -> Result<Vec<u8>, PrivateKeyProtectionError> {
        self.platform
            .unwrap(self.profile_id.clone(), ciphertext.to_vec())
            .map_err(|_| PrivateKeyProtectionError)
    }
}

/// Thread-safe handle to one durable local profile.
#[derive(uniffi::Object)]
pub struct MobileClient {
    client: Mutex<Client>,
}

#[uniffi::export]
impl MobileClient {
    /// Opens a durable profile using a caller-provided OS keystore bridge.
    ///
    /// This API has no software-key fallback. The profile identifier is passed
    /// to the native protector for key binding and must remain stable.
    ///
    /// # Errors
    ///
    /// Returns `InvalidProfileId` for a malformed identifier,
    /// `KeyProtectionFailed` when the OS keystore refuses access, or
    /// `ProfileOpenFailed` for storage or profile initialization failures.
    #[uniffi::constructor]
    pub fn open_or_create(
        database_path: String,
        profile_id: String,
        protector: Arc<dyn PlatformKeyProtector>,
    ) -> Result<Arc<Self>, MobileError> {
        if profile_id.is_empty()
            || profile_id.len() > 128
            || !profile_id.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        {
            return Err(MobileError::InvalidProfileId);
        }

        let platform = ProfileProtector {
            profile_id,
            platform: protector,
        };
        let client = Client::open_or_create(database_path, &platform)
            .map_err(|error| map_open_error(&error))?;
        Ok(Arc::new(Self {
            client: Mutex::new(client),
        }))
    }

    /// Returns the non-secret public identity information for native UI.
    ///
    /// # Errors
    ///
    /// Returns `ProfileUnavailable` if the local profile lock is poisoned.
    pub fn identity_info(&self) -> Result<MobileIdentityInfo, MobileError> {
        let client = self.lock_client()?;
        Ok(client.identity_info().into())
    }

    /// Returns the next durable author sequence for this identity.
    ///
    /// # Errors
    ///
    /// Returns `ProfileUnavailable` if the profile lock or sequence lookup fails.
    pub fn next_author_sequence(&self) -> Result<u64, MobileError> {
        self.lock_client()?
            .next_author_sequence()
            .map_err(|_| MobileError::ProfileUnavailable)
    }
}

impl MobileClient {
    fn lock_client(&self) -> Result<MutexGuard<'_, Client>, MobileError> {
        self.client
            .lock()
            .map_err(|_| MobileError::ProfileUnavailable)
    }
}

fn map_open_error(error: &CoreError) -> MobileError {
    if matches!(error, CoreError::Identity(IdentityError::Protection(_))) {
        MobileError::KeyProtectionFailed
    } else {
        MobileError::ProfileOpenFailed
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::{MobileClient, MobileError, PlatformKeyProtector};

    #[derive(Default)]
    struct TestProtector {
        key: Mutex<Option<[u8; 32]>>,
    }

    impl PlatformKeyProtector for TestProtector {
        fn wrap(
            &self,
            _profile_id: String,
            clear_material: Vec<u8>,
        ) -> Result<Vec<u8>, super::ProtectorError> {
            let mut key = self
                .key
                .lock()
                .map_err(|_| super::ProtectorError::Failure)?;
            let key = key.get_or_insert([0xD3; 32]);
            let mut output = Vec::with_capacity(clear_material.len());
            output.extend(
                clear_material
                    .iter()
                    .zip(key.iter().cycle())
                    .map(|(byte, mask)| *byte ^ *mask),
            );
            Ok(output)
        }

        fn unwrap(
            &self,
            profile_id: String,
            ciphertext: Vec<u8>,
        ) -> Result<Vec<u8>, super::ProtectorError> {
            self.wrap(profile_id, ciphertext)
        }
    }

    struct DenyProtector;

    impl PlatformKeyProtector for DenyProtector {
        fn wrap(
            &self,
            _profile_id: String,
            _clear_material: Vec<u8>,
        ) -> Result<Vec<u8>, super::ProtectorError> {
            Err(super::ProtectorError::Failure)
        }

        fn unwrap(
            &self,
            _profile_id: String,
            _ciphertext: Vec<u8>,
        ) -> Result<Vec<u8>, super::ProtectorError> {
            Err(super::ProtectorError::Failure)
        }
    }

    #[test]
    fn reports_keystore_denial_without_software_fallback() {
        let directory = tempfile::tempdir().expect("temporary profile directory");
        let result = MobileClient::open_or_create(
            directory
                .path()
                .join("profile.sqlite")
                .to_string_lossy()
                .into_owned(),
            "android-test-profile".to_owned(),
            std::sync::Arc::new(DenyProtector),
        );
        assert!(matches!(result, Err(MobileError::KeyProtectionFailed)));
    }

    #[test]
    fn opens_and_reopens_profile_with_same_platform_identity() {
        let directory = tempfile::tempdir().expect("temporary profile directory");
        let database_path = directory
            .path()
            .join("profile.sqlite")
            .to_string_lossy()
            .into_owned();
        let protector = std::sync::Arc::new(TestProtector::default());
        let client = MobileClient::open_or_create(
            database_path.clone(),
            "android-test-profile".to_owned(),
            protector.clone(),
        )
        .expect("open local profile");

        let identity = client.identity_info().expect("public identity");
        assert_eq!(identity.public_bundle.len(), 65);
        assert_eq!(identity.fingerprint.len(), 32);
        assert_eq!(client.next_author_sequence().expect("first sequence"), 1);
        drop(client);

        let reopened = MobileClient::open_or_create(
            database_path,
            "android-test-profile".to_owned(),
            protector,
        )
        .expect("reopen local profile");
        assert_eq!(
            reopened.identity_info().expect("restored identity"),
            identity
        );
    }

    #[test]
    fn rejects_profile_identifier_before_calling_the_platform_protector() {
        let result = MobileClient::open_or_create(
            "unused.sqlite".to_owned(),
            "bad\nprofile".to_owned(),
            std::sync::Arc::new(TestProtector::default()),
        );
        assert!(matches!(result, Err(MobileError::InvalidProfileId)));
    }
}
