mod identity;
mod space;

use identity::{IdentityCommand, print_pinned_identity};
use space::{SpaceCommand, print_space_page};

use std::path::{Path, PathBuf};
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

    // Parse before creating directories or opening storage so malformed input
    // cannot have filesystem side effects.
    let pin_input = match &cli.command {
        Command::Identity {
            command:
                IdentityCommand::Pin {
                    bundle_hex,
                    fingerprint_hex,
                },
        } => Some((
            parse_fixed_hex::<65>(bundle_hex, "bundle")?,
            parse_fixed_hex::<32>(fingerprint_hex, "fingerprint")?,
        )),
        _ => None,
    };
    let lookup_fingerprint = match &cli.command {
        Command::Identity {
            command: IdentityCommand::Pinned { fingerprint_hex },
        } => Some(parse_fixed_hex::<32>(fingerprint_hex, "fingerprint")?),
        _ => None,
    };

    let data_dir = match cli.data_dir {
        Some(path) => path,
        None => default_data_directory()?,
    };
    std::fs::create_dir_all(&data_dir)?;
    let database_path = data_dir.join(DATABASE_NAME);
    let protector = OsKeyringProtector::new(PROFILE_ID)?;

    match cli.command {
        Command::About => Ok(()),
        Command::Identity { command } => execute_identity(
            &command,
            &database_path,
            &protector,
            json,
            pin_input,
            lookup_fingerprint,
        ),
        Command::Space { command } => execute_space(command, &database_path, &protector, json),
        Command::Status => execute_status(&database_path, &protector, json),
    }
}

fn execute_identity(
    command: &IdentityCommand,
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
    pin_input: Option<([u8; 65], [u8; 32])>,
    lookup_fingerprint: Option<[u8; 32]>,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        IdentityCommand::Init => {
            let client = Client::open_or_create(database_path, protector)?;
            if !json {
                println!("Device identity is ready.");
            }
            print_identity(client.identity_info(), json);
        }
        IdentityCommand::Show => match Client::open_existing(database_path, protector) {
            Ok(client) => print_identity(client.identity_info(), json),
            Err(CoreError::MissingIdentity) => {
                return Err(
                    "No device identity is initialized; run `lattice identity init`.".into(),
                );
            }
            Err(error) => return Err(Box::new(error)),
        },
        IdentityCommand::Pin { .. } => {
            let (bundle, fingerprint) = pin_input.expect("pin input was parsed before storage");
            let mut client = match Client::open_existing(database_path, protector) {
                Ok(client) => client,
                Err(CoreError::MissingIdentity) => {
                    return Err(
                        "No device identity is initialized; run `lattice identity init`.".into(),
                    );
                }
                Err(error) => return Err(Box::new(error)),
            };
            let pinned = client.pin_identity(&bundle, fingerprint)?;
            print_pinned_identity(
                Some((pinned.fingerprint(), pinned.bundle().to_bytes())),
                json,
                "identity_pin",
            );
        }
        IdentityCommand::Pinned { .. } => {
            let fingerprint = lookup_fingerprint.expect("lookup fingerprint was parsed");
            let client = match Client::open_existing(database_path, protector) {
                Ok(client) => client,
                Err(CoreError::MissingIdentity) => {
                    return Err(
                        "No device identity is initialized; run `lattice identity init`.".into(),
                    );
                }
                Err(error) => return Err(Box::new(error)),
            };
            let pinned = client.pinned_identity(&fingerprint)?;
            print_pinned_identity(
                pinned.map(|record| (record.fingerprint(), record.bundle().to_bytes())),
                json,
                "identity_pinned",
            );
        }
    }
    Ok(())
}

fn execute_space(
    command: SpaceCommand,
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        SpaceCommand::List { after } => {
            let after = after
                .as_deref()
                .map(parse_space_cursor)
                .transpose()
                .map_err(|error| format!("invalid --after cursor: {error}"))?;
            let mut client = match Client::open_existing(database_path, protector) {
                Ok(client) => client,
                Err(CoreError::MissingIdentity) => {
                    return Err(
                        "No device identity is initialized; run `lattice identity init`.".into(),
                    );
                }
                Err(error) => return Err(Box::new(error)),
            };
            let page = client.restore_space_page(after)?;
            print_space_page(&page, json);
        }
    }
    Ok(())
}

fn execute_status(
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match Client::open_existing(database_path, protector) {
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

fn parse_fixed_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    let expected_hex_len = N * 2;
    if value.len() != expected_hex_len {
        return Err(format!(
            "{label} must contain exactly {expected_hex_len} hexadecimal characters"
        ));
    }
    let input = value.as_bytes();
    let mut bytes = [0_u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let high = hex_value(input[index * 2])
            .ok_or_else(|| format!("{label} contains a non-hexadecimal character"))?;
        let low = hex_value(input[index * 2 + 1])
            .ok_or_else(|| format!("{label} contains a non-hexadecimal character"))?;
        *byte = (high << 4) | low;
    }
    Ok(bytes)
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
    use super::{
        Cli, Command, IdentityCommand, execute, parse_fixed_hex, parse_space_cursor,
        space_cursor_hex,
    };
    use clap::Parser;
    use lattice_core::SpaceGenesisCursor;

    #[test]
    fn malformed_pin_fails_before_creating_profile_storage() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock follows epoch")
            .as_nanos();
        let data_dir = std::env::temp_dir().join(format!(
            "lattice-cli-invalid-pin-{}-{nonce}",
            std::process::id(),
        ));
        assert!(!data_dir.exists());
        let result = execute(
            Cli {
                data_dir: Some(data_dir.clone()),
                json: true,
                command: Command::Identity {
                    command: IdentityCommand::Pin {
                        bundle_hex: "00".repeat(65),
                        fingerprint_hex: "zz".repeat(32),
                    },
                },
            },
            true,
        );
        assert!(result.is_err());
        assert!(!data_dir.exists());
    }

    #[test]
    fn identity_pin_and_lookup_parse_exact_cli_arguments() {
        let pin = Cli::try_parse_from([
            "lattice",
            "identity",
            "pin",
            "--bundle-hex",
            &"ab".repeat(65),
            "--fingerprint-hex",
            &"cd".repeat(32),
        ])
        .expect("pin arguments parse");
        assert!(matches!(
            pin.command,
            Command::Identity {
                command: IdentityCommand::Pin { .. }
            }
        ));

        let lookup = Cli::try_parse_from([
            "lattice",
            "identity",
            "pinned",
            "--fingerprint-hex",
            &"cd".repeat(32),
        ])
        .expect("lookup arguments parse");
        assert!(matches!(
            lookup.command,
            Command::Identity {
                command: IdentityCommand::Pinned { .. }
            }
        ));
    }

    #[test]
    fn fixed_hex_requires_exact_length_and_valid_hex() {
        assert_eq!(parse_fixed_hex::<2>("aB01", "value"), Ok([0xab, 1]));
        assert!(parse_fixed_hex::<2>("aB0", "value").is_err());
        assert!(parse_fixed_hex::<2>("aB0z", "value").is_err());
    }

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
