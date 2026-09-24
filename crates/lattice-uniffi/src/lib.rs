//! UniFFI-owned mobile boundary for the local Rust profile.

use std::sync::{Arc, Mutex, MutexGuard};

use lattice_core::{Client, CoreError, DeviceIdentityInfo as CoreIdentityInfo, SpaceGenesisCursor};
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

/// Stable cursor for paginating locally recoverable Space generations.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MobileSpaceCursor {
    /// Space identifier bytes.
    pub space_id: Vec<u8>,
    /// MLS group reference bytes.
    pub group_reference: Vec<u8>,
}

impl TryFrom<MobileSpaceCursor> for SpaceGenesisCursor {
    type Error = MobileError;

    fn try_from(cursor: MobileSpaceCursor) -> Result<Self, Self::Error> {
        Ok(Self {
            space_id: cursor
                .space_id
                .as_slice()
                .try_into()
                .map_err(|_| MobileError::InvalidSpaceCursor)?,
            group_reference: cursor
                .group_reference
                .as_slice()
                .try_into()
                .map_err(|_| MobileError::InvalidSpaceCursor)?,
        })
    }
}

impl From<SpaceGenesisCursor> for MobileSpaceCursor {
    fn from(cursor: SpaceGenesisCursor) -> Self {
        Self {
            space_id: cursor.space_id.to_vec(),
            group_reference: cursor.group_reference.to_vec(),
        }
    }
}

/// Non-secret identifier summary for one locally restored Space generation.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MobileSpaceSummary {
    /// Space identifier bytes.
    pub space_id: Vec<u8>,
    /// MLS group reference bytes.
    pub group_reference: Vec<u8>,
}

/// Bounded page of locally verified Space Genesis snapshots.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MobileSpacePage {
    /// Restored generations in this page.
    pub spaces: Vec<MobileSpaceSummary>,
    /// Exclusive cursor to request the next page.
    pub next_cursor: Option<MobileSpaceCursor>,
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
    /// The caller supplied a Space cursor with an invalid identifier length.
    #[error("invalid Space page cursor")]
    InvalidSpaceCursor,
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

    /// Restores one bounded page of local Genesis snapshots.
    ///
    /// This lists locally created candidate generations only. It does not
    /// establish current membership or restore later policy events.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSpaceCursor` for malformed cursor byte lengths or
    /// `ProfileUnavailable` when a snapshot or profile cannot be restored.
    pub fn list_local_spaces(
        &self,
        after: Option<MobileSpaceCursor>,
    ) -> Result<MobileSpacePage, MobileError> {
        let after = after.map(SpaceGenesisCursor::try_from).transpose()?;
        let mut client = self.lock_client()?;
        let page = client
            .restore_space_page(after)
            .map_err(|_| MobileError::ProfileUnavailable)?;
        let spaces = page
            .spaces()
            .iter()
            .map(|space| MobileSpaceSummary {
                space_id: space.space_id().to_vec(),
                group_reference: space.group_reference().to_vec(),
            })
            .collect();
        Ok(MobileSpacePage {
            spaces,
            next_cursor: page.next_cursor().map(Into::into),
        })
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
    fn lists_empty_local_space_pages_and_rejects_malformed_cursor() {
        let directory = tempfile::tempdir().expect("temporary profile directory");
        let database_path = directory
            .path()
            .join("profile.sqlite")
            .to_string_lossy()
            .into_owned();
        let client = MobileClient::open_or_create(
            database_path,
            "android-test-profile".to_owned(),
            std::sync::Arc::new(TestProtector::default()),
        )
        .expect("open local profile");

        assert_eq!(
            client
                .list_local_spaces(None)
                .expect("list empty local page"),
            super::MobileSpacePage {
                spaces: Vec::new(),
                next_cursor: None,
            }
        );
        assert!(matches!(
            client.list_local_spaces(Some(super::MobileSpaceCursor {
                space_id: vec![0; 15],
                group_reference: vec![0; 32],
            })),
            Err(MobileError::InvalidSpaceCursor)
        ));
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
