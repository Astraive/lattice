use std::path::{Path, PathBuf};

use directories::BaseDirs;
use lattice_mls::api::CredentialTrustPolicy;
use lattice_platform::OsKeyringProtector;
const PROFILE_ID: &str = "default";
const DATABASE_NAME: &str = "lattice.sqlite";
/// Debug builds only: isolate Desktop app data and keyring entries for local
/// acceptance runs without touching the current user's normal profile.
const DEBUG_PROFILE_DIR_ENV: &str = "LATTICE_DESKTOP_PROFILE_DIR";
const DEBUG_TRUST_ROOT_DER_ENV: &str = "LATTICE_DESKTOP_DEBUG_TRUST_ROOT_DER";
const DEBUG_TRUST_ROOT_SHA256_ENV: &str = "LATTICE_DESKTOP_DEBUG_TRUST_ROOT_SHA256";

pub(crate) fn data_dir() -> Result<PathBuf, String> {
    #[cfg(debug_assertions)]
    if let Some(data_dir) = std::env::var_os(DEBUG_PROFILE_DIR_ENV) {
        let data_dir = PathBuf::from(data_dir);
        if !data_dir.is_absolute() {
            return Err(format!("{DEBUG_PROFILE_DIR_ENV} must be an absolute path"));
        }
        std::fs::create_dir_all(&data_dir)
            .map_err(|error| format!("create isolated profile directory: {error}"))?;
        return data_dir
            .canonicalize()
            .map_err(|error| format!("resolve isolated profile directory: {error}"));
    }

    let data_dir = BaseDirs::new()
        .map(|directories| {
            directories
                .data_local_dir()
                .join("Astraive")
                .join("Lattice")
        })
        .ok_or_else(|| "user data directory is unavailable".to_owned())?;
    std::fs::create_dir_all(&data_dir)
        .map_err(|error| format!("create app data directory: {error}"))?;
    Ok(data_dir)
}

fn keyring_profile_id(data_dir: &Path, isolated: bool) -> String {
    #[cfg(not(debug_assertions))]
    let _ = data_dir;
    if isolated {
        #[cfg(debug_assertions)]
        {
            // Stable FNV-1a keeps the per-directory keyring slot across builds.
            let hash = data_dir
                .to_string_lossy()
                .bytes()
                .fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
                    (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
                });
            return format!("desktop-debug-{hash:016x}");
        }
        #[cfg(not(debug_assertions))]
        unreachable!("release builds cannot select an isolated profile");
    }

    PROFILE_ID.to_owned()
}

pub(crate) fn open_profile() -> Result<(PathBuf, OsKeyringProtector), String> {
    let isolated = cfg!(debug_assertions) && std::env::var_os(DEBUG_PROFILE_DIR_ENV).is_some();
    let data_dir = data_dir()?;
    let protector = OsKeyringProtector::new(&keyring_profile_id(&data_dir, isolated))
        .map_err(|error| error.to_string())?;
    Ok((data_dir.join(DATABASE_NAME), protector))
}

pub(crate) fn credential_trust_policy() -> Result<CredentialTrustPolicy, String> {
    #[cfg(debug_assertions)]
    {
        trust_policy_from_settings(
            std::env::var_os(DEBUG_PROFILE_DIR_ENV).is_some(),
            std::env::var_os(DEBUG_TRUST_ROOT_DER_ENV),
            std::env::var_os(DEBUG_TRUST_ROOT_SHA256_ENV),
        )
    }
    #[cfg(not(debug_assertions))]
    {
        if std::env::var_os(DEBUG_TRUST_ROOT_DER_ENV).is_some()
            || std::env::var_os(DEBUG_TRUST_ROOT_SHA256_ENV).is_some()
        {
            return Err("debug trust-root settings are unavailable in release builds".to_owned());
        }
        Ok(CredentialTrustPolicy::native_system())
    }
}

#[cfg(debug_assertions)]
fn trust_policy_from_settings(
    isolated_profile: bool,
    root_path: Option<std::ffi::OsString>,
    expected_sha256: Option<std::ffi::OsString>,
) -> Result<CredentialTrustPolicy, String> {
    let (root_path, expected_sha256) = match (root_path, expected_sha256) {
        (None, None) => return Ok(CredentialTrustPolicy::native_system()),
        (Some(root_path), Some(expected_sha256)) => (root_path, expected_sha256),
        _ => {
            return Err(format!(
                "{DEBUG_TRUST_ROOT_DER_ENV} and {DEBUG_TRUST_ROOT_SHA256_ENV} must be set together"
            ));
        }
    };
    if !isolated_profile {
        return Err(format!(
            "pinned trust roots require {DEBUG_PROFILE_DIR_ENV} to select an isolated profile"
        ));
    }

    let root_path = PathBuf::from(root_path);
    if !root_path.is_absolute() {
        return Err(format!(
            "{DEBUG_TRUST_ROOT_DER_ENV} must be an absolute path"
        ));
    }
    let expected_sha256 = expected_sha256
        .into_string()
        .map_err(|_| format!("{DEBUG_TRUST_ROOT_SHA256_ENV} must be hexadecimal"))?;
    let expected_sha256 =
        super::encoding::parse_fixed_hex::<32>(&expected_sha256, "trust-root SHA-256")?;
    let metadata = std::fs::metadata(&root_path)
        .map_err(|error| format!("read pinned trust root metadata: {error}"))?;
    if metadata.len() > lattice_mls::api::MAX_CREDENTIAL_BYTES as u64 {
        return Err("pinned trust root exceeds the certificate size limit".to_owned());
    }
    let root_der =
        std::fs::read(&root_path).map_err(|error| format!("read pinned trust root: {error}"))?;
    CredentialTrustPolicy::pinned_root_der(&root_der, &expected_sha256)
        .map_err(|error| format!("invalid pinned trust root: {error}"))
}

pub(crate) fn open_existing_client(
    database_path: impl AsRef<Path>,
    protector: &OsKeyringProtector,
) -> Result<lattice_core::Client, String> {
    lattice_core::Client::open_existing_with_trust_policy(
        database_path,
        protector,
        credential_trust_policy()?,
    )
    .map_err(|error| error.to_string())
}

pub(crate) fn open_or_create_client(
    database_path: impl AsRef<Path>,
    protector: &OsKeyringProtector,
) -> Result<lattice_core::Client, String> {
    lattice_core::Client::open_or_create_with_trust_policy(
        database_path,
        protector,
        credential_trust_policy()?,
    )
    .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::keyring_profile_id;
    use std::path::Path;

    #[test]
    fn isolated_profile_ids_are_stable_and_path_specific() {
        let first = Path::new(r"C:\lattice-test\one");
        let second = Path::new(r"C:\lattice-test\two");
        assert_eq!(
            keyring_profile_id(first, true),
            keyring_profile_id(first, true)
        );
        assert_ne!(
            keyring_profile_id(first, true),
            keyring_profile_id(second, true)
        );
        assert_eq!(keyring_profile_id(first, false), "default");
    }

    #[cfg(debug_assertions)]
    #[test]
    fn pinned_root_settings_require_isolation_and_complete_exact_pin() {
        use super::trust_policy_from_settings;
        use std::ffi::OsString;

        assert!(trust_policy_from_settings(true, None, None).is_ok());
        assert!(trust_policy_from_settings(true, Some(OsString::from("root.der")), None).is_err());
        assert!(
            trust_policy_from_settings(
                false,
                Some(OsString::from("root.der")),
                Some(OsString::from("00".repeat(32))),
            )
            .is_err()
        );
        assert!(
            trust_policy_from_settings(
                true,
                Some(
                    std::env::temp_dir()
                        .join("lattice-missing-root.der")
                        .into_os_string()
                ),
                Some(OsString::from("not-a-fingerprint")),
            )
            .is_err()
        );
    }
}
