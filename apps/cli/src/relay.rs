use std::{error::Error, path::Path, time::Duration};

use clap::Subcommand;
pub(super) use lattice_relay::settings::RelaySettingsError as RelayConfigError;
use lattice_relay::settings::{add_relay, list_relays, remove_relay, validate_relay_url};

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

pub(super) fn validate_input_url(value: &str) -> Result<(), RelayConfigError> {
    validate_relay_url(value)
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

fn test_relay(url: &str, json: bool) -> Result<(), Box<dyn Error>> {
    validate_relay_url(url)?;
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
