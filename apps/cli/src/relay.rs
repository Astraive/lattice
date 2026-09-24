use std::{
    error::Error,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use clap::Subcommand;
use sha2::{Digest, Sha256};
use url::Url;

const MAX_RELAY_URL_BYTES: usize = 2_048;
const MAX_RELAY_SETTINGS: usize = 64;
const RELAY_TEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Subcommand)]
pub(super) enum RelayCommand {
    /// Add a secure relay URL to this local profile's settings.
    Add {
        /// Relay URL. Only wss:// URLs without user information or fragments are accepted.
        #[arg(long)]
        url: String,
    },
    /// List relay URLs configured in this local profile.
    List,
    /// Remove a relay URL from this local profile's settings.
    Remove {
        /// Exact relay URL previously added to this profile.
        #[arg(long)]
        url: String,
    },
    /// Fetch NIP-11 metadata and report candidate-profile compatibility.
    Test {
        /// Secure relay URL to probe. This checks HTTPS NIP-11 only, not WebSocket publishing.
        #[arg(long)]
        url: String,
    },
}

#[derive(Debug)]
pub(super) enum RelayConfigError {
    InvalidUrl,
    InvalidSettings,
    SettingsLimit,
    HashCollision,
}

impl std::fmt::Display for RelayConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidUrl => {
                "relay URL must be a secure wss:// URL without credentials or a fragment"
            }
            Self::InvalidSettings => "local relay settings are malformed or inconsistent",
            Self::SettingsLimit => "local relay settings limit reached",
            Self::HashCollision => "relay settings filename conflicts with different URL bytes",
        };
        formatter.write_str(message)
    }
}

impl Error for RelayConfigError {}

pub(super) fn validate_input_url(value: &str) -> Result<(), RelayConfigError> {
    if value.is_empty() || value.len() > MAX_RELAY_URL_BYTES || value.trim() != value {
        return Err(RelayConfigError::InvalidUrl);
    }
    let url = Url::parse(value).map_err(|_| RelayConfigError::InvalidUrl)?;
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
        return Err(RelayConfigError::InvalidUrl);
    }
    Ok(())
}

pub(super) fn execute(
    command: RelayCommand,
    data_dir: &Path,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    let settings_dir = data_dir.join("relays");
    match command {
        RelayCommand::Add { url } => {
            let added = add_relay(&settings_dir, &url)?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "schema_version": 1,
                        "command": "relay_add",
                        "relay_url": url,
                        "added": added,
                        "scope": "local_profile_only",
                    })
                );
            } else if added {
                println!("Added relay {url} to this local profile.");
            } else {
                println!("Relay {url} was already configured for this local profile.");
            }
        }
        RelayCommand::List => {
            let urls = list_relays(&settings_dir)?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "schema_version": 1,
                        "command": "relay_list",
                        "relays": urls,
                        "scope": "local_profile_only",
                    })
                );
            } else if urls.is_empty() {
                println!("No relays are configured for this local profile.");
            } else {
                for url in urls {
                    println!("{url}");
                }
            }
        }
        RelayCommand::Remove { url } => {
            let removed = remove_relay(&settings_dir, &url)?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "schema_version": 1,
                        "command": "relay_remove",
                        "relay_url": url,
                        "removed": removed,
                        "scope": "local_profile_only",
                    })
                );
            } else if removed {
                println!("Removed relay {url} from this local profile.");
            } else {
                println!("Relay {url} was not configured for this local profile.");
            }
        }
        RelayCommand::Test { url } => test_relay(&url, json)?,
    }
    Ok(())
}

fn add_relay(settings_dir: &Path, url: &str) -> Result<bool, Box<dyn Error>> {
    validate_input_url(url)?;
    let settings_file = settings_path(settings_dir, url);
    match fs::symlink_metadata(&settings_file) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || read_setting(&settings_file)? != url {
                return Err(Box::new(RelayConfigError::HashCollision));
            }
            return Ok(false);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(Box::new(error)),
    }

    if list_relays(settings_dir)?.len() >= MAX_RELAY_SETTINGS {
        return Err(Box::new(RelayConfigError::SettingsLimit));
    }
    fs::create_dir_all(settings_dir)?;
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&settings_file)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if read_setting(&settings_file)? == url {
                return Ok(false);
            }
            return Err(Box::new(RelayConfigError::HashCollision));
        }
        Err(error) => return Err(Box::new(error)),
    };
    if let Err(error) = file
        .write_all(url.as_bytes())
        .and_then(|()| file.sync_all())
    {
        drop(file);
        let _ = fs::remove_file(settings_file);
        return Err(Box::new(error));
    }
    Ok(true)
}

fn remove_relay(settings_dir: &Path, url: &str) -> Result<bool, Box<dyn Error>> {
    validate_input_url(url)?;
    let settings_file = settings_path(settings_dir, url);
    let metadata = match fs::symlink_metadata(&settings_file) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(Box::new(error)),
    };
    if !metadata.file_type().is_file() || read_setting(&settings_file)? != url {
        return Err(Box::new(RelayConfigError::HashCollision));
    }
    fs::remove_file(settings_file)?;
    Ok(true)
}

fn list_relays(settings_dir: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let entries = match fs::read_dir(settings_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(Box::new(error)),
    };
    let mut urls = Vec::new();
    for entry in entries {
        let entry = entry?;
        if entry
            .path()
            .extension()
            .is_none_or(|extension| extension != "relay")
        {
            continue;
        }
        if !entry.file_type()?.is_file() {
            return Err(Box::new(RelayConfigError::InvalidSettings));
        }
        let url = read_setting(&entry.path())?;
        if validate_input_url(&url).is_err() {
            return Err(Box::new(RelayConfigError::InvalidSettings));
        }
        if settings_path(settings_dir, &url).file_name() != entry.path().file_name() {
            return Err(Box::new(RelayConfigError::InvalidSettings));
        }
        urls.push(url);
        if urls.len() > MAX_RELAY_SETTINGS {
            return Err(Box::new(RelayConfigError::SettingsLimit));
        }
    }
    urls.sort_unstable();
    Ok(urls)
}

fn read_setting(path: &Path) -> Result<String, Box<dyn Error>> {
    let mut file = File::open(path)?;
    let mut bytes = Vec::with_capacity(MAX_RELAY_URL_BYTES.min(256));
    Read::take(&mut file, (MAX_RELAY_URL_BYTES + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > MAX_RELAY_URL_BYTES {
        return Err(Box::new(RelayConfigError::InvalidSettings));
    }
    String::from_utf8(bytes).map_err(|_| Box::new(RelayConfigError::InvalidSettings) as _)
}

fn settings_path(settings_dir: &Path, url: &str) -> PathBuf {
    let digest = Sha256::digest(url.as_bytes());
    let mut name = String::with_capacity(digest.len() * 2 + 6);
    for byte in digest {
        use std::fmt::Write as _;
        write!(name, "{byte:02x}").expect("writing to a String cannot fail");
    }
    name.push_str(".relay");
    settings_dir.join(name)
}

fn test_relay(url: &str, json: bool) -> Result<(), Box<dyn Error>> {
    validate_input_url(url)?;
    let client = lattice_relay::network::RelayClient::new(RELAY_TEST_TIMEOUT)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let capabilities = runtime.block_on(client.relay_capabilities(url))?;
    let profile_compatible = capabilities.supports_lattice_profile();
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "command": "relay_test",
                "relay_url": url,
                "nip11_reachable": true,
                "supported_nips": capabilities.supported_nips,
                "max_message_length": capabilities.max_message_length,
                "profile_compatible": profile_compatible,
                "websocket_tested": false,
                "recipient_delivery_claimed": false,
            })
        );
    } else {
        println!("NIP-11 HTTPS metadata is reachable for {url}.");
        println!(
            "Lattice relay profile: {}.",
            if profile_compatible {
                "compatible"
            } else {
                "not advertised as compatible"
            }
        );
        println!("WebSocket publishing and recipient delivery were not tested.");
    }
    Ok(())
}
