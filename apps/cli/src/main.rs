use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use directories::BaseDirs;
use lattice_core::{Client, CoreError, DeviceIdentityInfo, SpaceGenesisCursor};
use lattice_platform::OsKeyringProtector;

const PROFILE_ID: &str = "default";
const DATABASE_NAME: &str = "lattice.sqlite";

#[derive(Debug, Parser)]
#[command(
    name = "lattice",
    version,
    about = "Local-first community communication"
)]
struct Cli {
    /// Use a specific local data directory instead of the default profile.
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    /// Emit versioned machine-readable JSON.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show the implemented local capabilities and disabled product boundaries.
    About,
    /// Inspect or initialize this device's protected local identity.
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    /// List locally recoverable Space generations.
    Space {
        #[command(subcommand)]
        command: SpaceCommand,
    },
    /// Report local identity and event-sequence readiness without creating keys.
    Status,
}

#[derive(Debug, Subcommand)]
enum SpaceCommand {
    /// Show one bounded page; use --after with the returned cursor to continue.
    List {
        /// Exclusive cursor encoded as 96 hexadecimal characters.
        #[arg(long)]
        after: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum IdentityCommand {
    /// Create a device identity once, or reopen the existing one.
    Init,
    /// Show public identity data for an initialized profile.
    Show,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let json = cli.json;
    match execute(cli, json) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if json {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "schema_version": 1,
                        "error": {
                            "code": "COMMAND_FAILED",
                            "message": error.to_string(),
                        }
                    })
                );
            } else {
                eprintln!("lattice: {error}");
            }
            ExitCode::FAILURE
        }
    }
}

fn execute(cli: Cli, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    if matches!(&cli.command, Command::About) {
        print_about(json);
        return Ok(());
    }

    let data_dir = match cli.data_dir {
        Some(path) => path,
        None => default_data_directory()?,
    };
    std::fs::create_dir_all(&data_dir)?;
    let database_path = data_dir.join(DATABASE_NAME);
    let protector = OsKeyringProtector::new(PROFILE_ID)?;

    match cli.command {
        Command::About => return Ok(()),
        Command::Identity {
            command: IdentityCommand::Init,
        } => {
            let client = Client::open_or_create(&database_path, &protector)?;
            if !json {
                println!("Device identity is ready.");
            }
            print_identity(client.identity_info(), json);
        }
        Command::Identity {
            command: IdentityCommand::Show,
        } => match Client::open_existing(&database_path, &protector) {
            Ok(client) => print_identity(client.identity_info(), json),
            Err(CoreError::MissingIdentity) => {
                return Err(
                    "No device identity is initialized; run `lattice identity init`.".into(),
                );
            }
            Err(error) => return Err(Box::new(error)),
        },
        Command::Space {
            command: SpaceCommand::List { after },
        } => {
            let mut client = match Client::open_existing(&database_path, &protector) {
                Ok(client) => client,
                Err(CoreError::MissingIdentity) => {
                    return Err(
                        "No device identity is initialized; run `lattice identity init`.".into(),
                    );
                }
                Err(error) => return Err(Box::new(error)),
            };
            let after = after
                .as_deref()
                .map(parse_space_cursor)
                .transpose()
                .map_err(|error| format!("invalid --after cursor: {error}"))?;
            let page = client.restore_space_page(after)?;
            print_space_page(&page, json);
        }
        Command::Status => match Client::open_existing(&database_path, &protector) {
            Ok(client) => {
                let sequence = client.next_author_sequence()?;
                if json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "schema_version": 1,
                            "command": "status",
                            "identity": "initialized",
                            "next_local_event_sequence": sequence,
                            "authenticated_spaces": false,
                            "message_authoring": false,
                            "network_delivery": false,
                        })
                    );
                } else {
                    println!("Device identity: initialized");
                    println!("Next local event sequence: {sequence}");
                }
            }
            Err(CoreError::MissingIdentity) => {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "schema_version": 1,
                            "command": "status",
                            "identity": "not_initialized",
                            "authenticated_spaces": false,
                            "message_authoring": false,
                            "network_delivery": false,
                        })
                    );
                } else {
                    println!("Device identity: not initialized");
                    println!("Authenticated Spaces and messages: unavailable");
                }
            }
            Err(error) => return Err(Box::new(error)),
        },
    }
    Ok(())
}

fn print_about(json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "command": "about",
                "available": [
                    "protected_device_identity",
                    "local_event_storage",
                    "local_space_genesis_listing",
                    "candidate_wire_codecs"
                ],
                "unavailable": [
                    "authenticated_spaces",
                    "message_authoring",
                    "network_delivery",
                    "voice_media"
                ],
            })
        );
    } else {
        println!("Lattice local-first communication");
        println!(
            "Available: protected device identity, local event storage, candidate wire codecs, and local Space Genesis listing."
        );
        println!(
            "Unavailable: authenticated Spaces, message authoring, network delivery, and voice media."
        );
    }
}
fn print_space_page(page: &lattice_core::RestoredSpacePage, json: bool) {
    let spaces = page
        .spaces()
        .iter()
        .map(|space| {
            serde_json::json!({
                "space_id": hex(space.space_id()),
                "group_reference": hex(space.group_reference()),
            })
        })
        .collect::<Vec<_>>();
    let next_cursor = space_cursor_hex(page.next_cursor());
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "command": "space_list",
                "spaces": spaces,
                "next_cursor": next_cursor,
            })
        );
    } else if page.spaces().is_empty() {
        println!("No locally recoverable Spaces.");
    } else {
        for space in page.spaces() {
            println!(
                "Space {} (MLS group {})",
                hex(space.space_id()),
                hex(space.group_reference())
            );
        }
        if let Some(cursor) = next_cursor {
            println!("Next page cursor: {cursor}");
        }
    }
}

fn parse_space_cursor(value: &str) -> Result<SpaceGenesisCursor, &'static str> {
    if value.len() != 96 {
        return Err("cursor must contain exactly 96 hexadecimal characters");
    }
    let input = value.as_bytes();
    let mut bytes = [0_u8; 48];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let high =
            hex_value(input[index * 2]).ok_or("cursor contains a non-hexadecimal character")?;
        let low =
            hex_value(input[index * 2 + 1]).ok_or("cursor contains a non-hexadecimal character")?;
        *byte = (high << 4) | low;
    }
    let mut space_id = [0_u8; 16];
    space_id.copy_from_slice(&bytes[..16]);
    let mut group_reference = [0_u8; 32];
    group_reference.copy_from_slice(&bytes[16..]);
    Ok(SpaceGenesisCursor {
        space_id,
        group_reference,
    })
}

fn space_cursor_hex(cursor: Option<SpaceGenesisCursor>) -> Option<String> {
    cursor.map(|cursor| {
        let mut bytes = [0_u8; 48];
        bytes[..16].copy_from_slice(&cursor.space_id);
        bytes[16..].copy_from_slice(&cursor.group_reference);
        hex(&bytes)
    })
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn print_identity(info: DeviceIdentityInfo, json: bool) {
    let fingerprint = hex(&info.fingerprint);
    let public_bundle = hex(&info.public_bundle);
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "command": "identity",
                "fingerprint": fingerprint,
                "public_bundle": public_bundle,
                "private_key_exposed": false,
            })
        );
    } else {
        println!("Fingerprint: {fingerprint}");
        println!("Public bundle: {public_bundle}");
    }
}

fn default_data_directory() -> Result<PathBuf, std::io::Error> {
    BaseDirs::new()
        .map(|directories| {
            directories
                .data_local_dir()
                .join("Astraive")
                .join("Lattice")
        })
        .ok_or_else(|| std::io::Error::other("user data directory is unavailable"))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}
#[cfg(test)]
mod tests {
    use super::{parse_space_cursor, space_cursor_hex};
    use lattice_core::SpaceGenesisCursor;

    #[test]
    fn space_cursor_round_trips_and_rejects_malformed_input() {
        let cursor = SpaceGenesisCursor {
            space_id: [0x01; 16],
            group_reference: [0xAB; 32],
        };
        let encoded = space_cursor_hex(Some(cursor)).expect("cursor encodes");
        assert_eq!(parse_space_cursor(&encoded), Ok(cursor));
        assert_eq!(
            parse_space_cursor(&encoded.to_ascii_uppercase()),
            Ok(cursor)
        );
        assert!(parse_space_cursor("01").is_err());
        assert!(parse_space_cursor(&format!("{}z", &encoded[..95])).is_err());
    }
}
