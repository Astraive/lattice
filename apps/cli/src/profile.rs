use std::path::{Path, PathBuf};

use lattice_core::{Client, CoreError};
use lattice_mls::api::CredentialTrustPolicy;
use lattice_platform::OsKeyringProtector;
use sha2::{Digest, Sha256};

const DEBUG_TRUST_ROOT_DER_ENV: &str = "LATTICE_CLI_DEBUG_TRUST_ROOT_DER";
const DEBUG_TRUST_ROOT_SHA256_ENV: &str = "LATTICE_CLI_DEBUG_TRUST_ROOT_SHA256";

pub(crate) fn open_existing_client(
    database_path: impl AsRef<Path>,
    protector: &OsKeyringProtector,
) -> Result<Client, CoreError> {
    let policy = credential_trust_policy(explicit_data_directory())
        .map_err(|_| CoreError::Mls(lattice_mls::api::MlsError::CredentialValidationFailed))?;
    Client::open_existing_with_trust_policy(database_path, protector, policy)
}

pub(crate) fn open_or_create_client(
    database_path: impl AsRef<Path>,
    protector: &OsKeyringProtector,
) -> Result<Client, CoreError> {
    let policy = credential_trust_policy(explicit_data_directory())
        .map_err(|_| CoreError::Mls(lattice_mls::api::MlsError::CredentialValidationFailed))?;
    Client::open_or_create_with_trust_policy(database_path, protector, policy)
}

fn explicit_data_directory() -> Option<PathBuf> {
    let mut args = std::env::args_os().skip(1);
    while let Some(argument) = args.next() {
        if argument == "--data-dir" {
            return args.next().map(PathBuf::from);
        }
        if let Some(value) = argument
            .to_str()
            .and_then(|arg| arg.strip_prefix("--data-dir="))
        {
            return Some(PathBuf::from(value));
        }
    }
    None
}

fn credential_trust_policy(data_dir: Option<PathBuf>) -> Result<CredentialTrustPolicy, String> {
    let root_path = std::env::var_os(DEBUG_TRUST_ROOT_DER_ENV);
    let expected_sha256 = std::env::var_os(DEBUG_TRUST_ROOT_SHA256_ENV);
    trust_policy_from_settings(data_dir.as_deref(), root_path, expected_sha256)
}

fn trust_policy_from_settings(
    data_dir: Option<&Path>,
    root_path: Option<std::ffi::OsString>,
    expected_sha256: Option<std::ffi::OsString>,
) -> Result<CredentialTrustPolicy, String> {
    #[cfg(not(debug_assertions))]
    {
        if root_path.is_some() || expected_sha256.is_some() {
            return Err("debug trust settings are unavailable in release builds".into());
        }
        let _ = data_dir;
        return Ok(CredentialTrustPolicy::native_system());
    }
    #[cfg(debug_assertions)]
    {
        let (root_path, expected_sha256) = match (root_path, expected_sha256) {
            (None, None) => return Ok(CredentialTrustPolicy::native_system()),
            (Some(path), Some(digest)) => (PathBuf::from(path), digest),
            _ => return Err("both debug trust-root settings are required".into()),
        };
        if !root_path.is_absolute() {
            return Err("debug trust-root DER path must be absolute".into());
        }
        let Some(data_dir) = data_dir else {
            return Err("pinned debug trust requires an explicit absolute --data-dir".into());
        };
        if !data_dir.is_absolute() {
            return Err("pinned debug trust requires an explicit absolute --data-dir".into());
        }
        let digest = expected_sha256
            .into_string()
            .map_err(|_| "trust-root SHA-256 must be ASCII hex")?;
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("trust-root SHA-256 must contain exactly 64 hexadecimal characters".into());
        }
        let mut expected = [0_u8; 32];
        for (index, pair) in digest.as_bytes().chunks_exact(2).enumerate() {
            expected[index] = (hex(pair[0]).ok_or("invalid SHA-256 hex")? << 4)
                | hex(pair[1]).ok_or("invalid SHA-256 hex")?;
        }
        let root_der = std::fs::read(&root_path)
            .map_err(|error| format!("read pinned trust root: {error}"))?;
        let actual: [u8; 32] = Sha256::digest(&root_der).into();
        if actual != expected {
            return Err("trust-root SHA-256 does not match DER".into());
        }
        CredentialTrustPolicy::pinned_root_der(&root_der, &expected)
            .map_err(|error| format!("invalid pinned trust root: {error}"))
    }
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn debug_trust_policy_native_default_and_partial_settings() {
        assert!(
            trust_policy_from_settings(None, None, None)
                .unwrap()
                .root_der()
                .is_none()
        );
        assert!(trust_policy_from_settings(None, Some(OsString::from("root")), None).is_err());
        assert!(trust_policy_from_settings(None, None, Some(OsString::from("00"))).is_err());
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn release_rejects_debug_trust_settings() {
        assert!(trust_policy_from_settings(None, None, None).is_ok());
        assert!(trust_policy_from_settings(None, Some(OsString::from("root.der")), None).is_err());
        assert!(
            trust_policy_from_settings(None, None, Some(OsString::from("00".repeat(32)))).is_err()
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    fn debug_trust_policy_pinned_root_requires_absolute_isolated_profile_and_matching_sha256() {
        let root =
            std::env::temp_dir().join(format!("lattice-cli-root-{}.der", std::process::id()));
        let root_key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let cert = params.self_signed(&root_key).unwrap();
        std::fs::write(&root, cert.der()).unwrap();
        let digest = Sha256::digest(cert.der())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let profile = std::env::temp_dir();
        let result = trust_policy_from_settings(
            Some(&profile),
            Some(root.clone().into_os_string()),
            Some(digest.clone().into()),
        )
        .unwrap();
        assert_eq!(result.root_der(), Some(cert.der().as_ref()));
        assert!(
            trust_policy_from_settings(
                None,
                Some(root.clone().into_os_string()),
                Some(digest.clone().into())
            )
            .is_err()
        );
        assert!(
            trust_policy_from_settings(
                Some(Path::new("relative")),
                Some(root.clone().into_os_string()),
                Some(digest.clone().into())
            )
            .is_err()
        );
        assert!(
            trust_policy_from_settings(
                Some(&profile),
                Some("relative.der".into()),
                Some(digest.clone().into())
            )
            .is_err()
        );
        assert!(
            trust_policy_from_settings(
                Some(&profile),
                Some(root.clone().into_os_string()),
                Some("x".into())
            )
            .is_err()
        );
        assert!(
            trust_policy_from_settings(
                Some(&profile),
                Some(root.clone().into_os_string()),
                Some("00".repeat(32).into())
            )
            .is_err()
        );
        let _ = std::fs::remove_file(root);
    }
}
