use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use directories::BaseDirs;
use lattice_core::{Client, CoreError, DeviceIdentityInfo};
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
    /// Report local identity and event-sequence readiness without creating keys.
    Status,
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
            "Available: protected device identity, local event storage, candidate wire codecs."
        );
        println!(
            "Unavailable: authenticated Spaces, message authoring, network delivery, and voice media."
        );
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
