use std::{
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use url::Url;

/// Maximum number of relay URLs stored for one local profile.
pub const MAX_RELAY_SETTINGS: usize = 64;
const MAX_RELAY_URL_BYTES: usize = 2_048;

/// Failure while validating or accessing local relay settings.
#[derive(Debug)]
pub enum RelaySettingsError {
    /// Relay URL is not a bounded secure WebSocket URL.
    InvalidUrl,
    /// Existing settings do not match the content-addressed format.
    InvalidSettings,
    /// The profile already contains the maximum number of relay settings.
    SettingsLimit,
    /// A content-addressed filename contains different URL bytes.
    HashCollision,
    /// Local filesystem access failed.
    Io(io::Error),
}

impl fmt::Display for RelaySettingsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidUrl => {
                "relay URL must be a secure wss:// URL without credentials or a fragment"
            }
            Self::InvalidSettings => "local relay settings are malformed or inconsistent",
            Self::SettingsLimit => "local relay settings limit reached",
            Self::HashCollision => "relay settings filename conflicts with different URL bytes",
            Self::Io(error) => return write!(formatter, "{error}"),
        };
        formatter.write_str(message)
    }
}

impl Error for RelaySettingsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for RelaySettingsError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Accept only bounded `wss://` URLs without credentials or fragments.
///
/// # Errors
///
/// Returns [`RelaySettingsError::InvalidUrl`] when the URL violates the supported
/// scheme, authority, length, credential, or fragment rules.
pub fn validate_relay_url(value: &str) -> Result<(), RelaySettingsError> {
    if value.is_empty() || value.len() > MAX_RELAY_URL_BYTES || value.trim() != value {
        return Err(RelaySettingsError::InvalidUrl);
    }
    let url = Url::parse(value).map_err(|_| RelaySettingsError::InvalidUrl)?;
    let raw_authority = value.split_once("://").map_or("", |(_, remainder)| {
        remainder.split(['/', '?', '#']).next().unwrap_or("")
    });
    if url.scheme() != "wss"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || raw_authority.contains('@')
        || url.fragment().is_some()
    {
        return Err(RelaySettingsError::InvalidUrl);
    }
    Ok(())
}

/// Add a relay URL to one profile's settings. Duplicate additions are no-ops.
///
/// # Errors
///
/// Returns a settings, limit, collision, or filesystem error when the URL cannot
/// be persisted safely.
pub fn add_relay(settings_dir: &Path, url: &str) -> Result<bool, RelaySettingsError> {
    validate_relay_url(url)?;
    let path = settings_path(settings_dir, url);
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || read_setting(&path)? != url {
                return Err(RelaySettingsError::HashCollision);
            }
            return Ok(false);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    if list_relays(settings_dir)?.len() >= MAX_RELAY_SETTINGS {
        return Err(RelaySettingsError::SettingsLimit);
    }
    fs::create_dir_all(settings_dir)?;
    let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if read_setting(&path)? == url {
                return Ok(false);
            }
            return Err(RelaySettingsError::HashCollision);
        }
        Err(error) => return Err(error.into()),
    };
    if let Err(error) = file
        .write_all(url.as_bytes())
        .and_then(|()| file.sync_all())
    {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error.into());
    }
    Ok(true)
}

/// Return the lexically sorted configured relay URLs for one local profile.
///
/// # Errors
///
/// Returns a settings, limit, or filesystem error when stored settings are invalid
/// or cannot be read.
pub fn list_relays(settings_dir: &Path) -> Result<Vec<String>, RelaySettingsError> {
    let entries = match fs::read_dir(settings_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut urls = Vec::new();
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path
            .extension()
            .is_none_or(|extension| extension != "relay")
        {
            continue;
        }
        if !entry.file_type()?.is_file() {
            return Err(RelaySettingsError::InvalidSettings);
        }
        let url = read_setting(&path)?;
        if validate_relay_url(&url).is_err()
            || settings_path(settings_dir, &url).file_name() != path.file_name()
        {
            return Err(RelaySettingsError::InvalidSettings);
        }
        urls.push(url);
        if urls.len() > MAX_RELAY_SETTINGS {
            return Err(RelaySettingsError::SettingsLimit);
        }
    }
    urls.sort_unstable();
    Ok(urls)
}

/// Remove one exact configured relay URL. Missing URLs are no-ops.
///
/// # Errors
///
/// Returns a URL, collision, or filesystem error when the removal cannot be
/// completed safely.
pub fn remove_relay(settings_dir: &Path, url: &str) -> Result<bool, RelaySettingsError> {
    validate_relay_url(url)?;
    let path = settings_path(settings_dir, url);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file() || read_setting(&path)? != url {
        return Err(RelaySettingsError::HashCollision);
    }
    fs::remove_file(path)?;
    Ok(true)
}

fn read_setting(path: &Path) -> Result<String, RelaySettingsError> {
    let mut file = File::open(path)?;
    let mut bytes = Vec::with_capacity(MAX_RELAY_URL_BYTES.min(256));
    Read::take(&mut file, (MAX_RELAY_URL_BYTES + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > MAX_RELAY_URL_BYTES {
        return Err(RelaySettingsError::InvalidSettings);
    }
    String::from_utf8(bytes).map_err(|_| RelaySettingsError::InvalidSettings)
}

fn settings_path(settings_dir: &Path, url: &str) -> PathBuf {
    let digest = Sha256::digest(url.as_bytes());
    let mut name = String::with_capacity(digest.len() * 2 + 6);
    for byte in digest {
        use fmt::Write as _;
        write!(name, "{byte:02x}").expect("writing to a String cannot fail");
    }
    name.push_str(".relay");
    settings_dir.join(name)
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{RelaySettingsError, add_relay, list_relays, remove_relay, validate_relay_url};

    fn settings_dir(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "lattice-relay-settings-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn local_relay_settings_add_list_remove_and_persist_exact_secure_urls() {
        let directory = settings_dir("crud");
        let primary = "wss://relay.example/path?mode=mailbox";
        let secondary = "wss://backup.example";
        assert!(add_relay(&directory, primary).expect("add primary relay"));
        assert!(add_relay(&directory, secondary).expect("add secondary relay"));
        assert!(!add_relay(&directory, primary).expect("duplicate is a no-op"));
        assert_eq!(
            list_relays(&directory).expect("list relays"),
            vec![secondary.to_owned(), primary.to_owned()]
        );
        assert!(remove_relay(&directory, primary).expect("remove primary relay"));
        assert!(!remove_relay(&directory, primary).expect("missing relay is a no-op"));
        assert_eq!(
            list_relays(&directory).expect("list remaining"),
            vec![secondary.to_owned()]
        );
        fs_remove_dir_all(&directory);
    }

    #[test]
    fn relay_settings_reject_insecure_urls_and_credentials() {
        for url in [
            "ws://relay.example",
            "https://relay.example",
            "wss://user@relay.example",
            "wss://user:password@relay.example",
            "wss://relay.example/#fragment",
            " wss://relay.example",
        ] {
            assert!(matches!(
                validate_relay_url(url),
                Err(RelaySettingsError::InvalidUrl)
            ));
        }
    }

    fn fs_remove_dir_all(path: &std::path::Path) {
        std::fs::remove_dir_all(path).expect("remove test settings");
    }
}
