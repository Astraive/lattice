mod doctor;
mod identity;
mod node;
mod peer;
mod relay;
mod space;
mod sync;

use identity::{
    IdentityCommand, certificate_request_pem, print_pinned_identity, write_certificate_request_pem,
};
use node::NodeCommand;
use relay::RelayCommand;
use space::{SpaceCommand, print_space_history, print_space_page, print_space_search};
use sync::SyncCommand;

use std::{
    error::Error,
    fmt,
    io::Read,
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Parser, Subcommand};
use directories::BaseDirs;
use lattice_core::{
    Client, CoreError, DeviceIdentityInfo, InitialChannel, MAX_SPACE_CREDENTIAL_BYTES,
    MAX_SPACE_WELCOME_BOOTSTRAP_BYTES, SpaceGenesisCursor, space::ChannelType,
};
use lattice_mls::api::DeviceCredentialInput;
use lattice_mls::api::MAX_MLS_WIRE_BYTES;
use lattice_platform::{OsKeyringProtectionError, OsKeyringProtector};
use openmls::credentials::{Credential, CredentialType};

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
    /// Queue an authorized text event locally without contacting the network.
    Send {
        /// Random 16-byte Space ID as exactly 32 hexadecimal characters.
        #[arg(long)]
        space_id: String,
        /// 32-byte MLS group reference as exactly 64 hexadecimal characters.
        #[arg(long)]
        group_reference: String,
        /// Path to the RFC 9420 TLS-encoded X.509 credential vector.
        #[arg(long)]
        credential: PathBuf,
        /// Random 16-byte channel ID as exactly 32 hexadecimal characters.
        #[arg(long)]
        channel_id: String,
        /// Text body to queue.
        #[arg(long)]
        text: String,
    },
    /// Create, import, list, restore, or recover local Space generations.
    Space {
        #[command(subcommand)]
        command: SpaceCommand,
    },
    /// Report local identity and event-sequence readiness without creating keys.
    Status,
    /// Inspect local profile, protected keys, storage schema, and unavailable transport/wire checks without applying migrations.
    Doctor,
    /// Inspect this host's current path capabilities without discovering peers.
    Peer {
        #[command(subcommand)]
        command: peer::PeerCommand,
    },
    /// Manage this profile's relay URLs and probe relay NIP-11 metadata.
    Relay {
        #[command(subcommand)]
        command: RelayCommand,
    },
    /// Inspect local synchronization queues without contacting peers.
    Sync {
        #[command(subcommand)]
        command: SyncCommand,
    },
    /// Run a bounded pinned-peer courier listener or inspect/forward queued envelopes.
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
}

type PinInput = ([u8; 65], [u8; 32]);
type SpaceEditInput = ([u8; 16], [u8; 32], [u8; 16], [u8; 32]);
type SpaceHistoryInput = ([u8; 16], [u8; 32], [u8; 16]);
type SpaceRestoreInput = ([u8; 16], [u8; 32]);
type SendInput = ([u8; 16], [u8; 32], [u8; 16]);
#[derive(Clone, Copy)]
enum SpaceCommandInput {
    None,
    Restore(SpaceRestoreInput),
    Recover(SpaceRestoreInput),
    Join([u8; 32]),
    Invite(SpaceRestoreInput),
    Leave(SpaceRestoreInput),
    Edit(SpaceEditInput),
    History(SpaceHistoryInput),
    Search(SpaceHistoryInput),
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let exit_code = if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) {
                0
            } else {
                2
            };
            let json = std::env::args().any(|argument| argument == "--json");
            if json
                && !matches!(
                    error.kind(),
                    clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
                )
            {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "schema_version": 1,
                        "error": {
                            "code": "INVALID_ARGUMENTS",
                            "message": error.to_string(),
                        }
                    })
                );
            } else {
                let _ = error.print();
            }
            return ExitCode::from(exit_code);
        }
    };
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
                            "code": error_code(error.as_ref()),
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

#[derive(Debug)]
struct CliError {
    code: &'static str,
    message: String,
}

impl CliError {
    fn invalid_input(message: impl Into<String>) -> Self {
        Self {
            code: "INVALID_INPUT",
            message: message.into(),
        }
    }

    fn missing_identity() -> Self {
        Self {
            code: "IDENTITY_NOT_INITIALIZED",
            message: "No device identity is initialized; run `lattice identity init`.".to_owned(),
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for CliError {}

fn error_code(error: &(dyn Error + 'static)) -> &'static str {
    if let Some(error) = error.downcast_ref::<CliError>() {
        return error.code;
    }
    if let Some(error) = error.downcast_ref::<CoreError>() {
        return match error {
            CoreError::MissingIdentity => "IDENTITY_NOT_INITIALIZED",
            CoreError::InvalidLocalTextMessageSearch => "INVALID_INPUT",
            CoreError::PinnedIdentityConflict => "PIN_CONFLICT",
            CoreError::Storage(_) => "STORAGE_ERROR",
            CoreError::Identity(_) => "IDENTITY_ERROR",
            CoreError::Mls(_) => "MLS_ERROR",
            CoreError::SpaceCredentialInvalid => "SPACE_CREDENTIAL_INVALID",
            CoreError::SpaceWelcomeBootstrapInvalid => "SPACE_WELCOME_PACKAGE_INVALID",
            CoreError::SpaceWelcomeBootstrapUntrustedInviter => "SPACE_INVITER_NOT_PINNED",
            CoreError::SpaceGenesisRejected(_) => "SPACE_REJECTED",
            CoreError::SpaceGenesisSnapshotNotFound => "SPACE_SNAPSHOT_NOT_FOUND",
            _ => "CORE_ERROR",
        };
    }
    if let Some(error) = error.downcast_ref::<relay::RelayConfigError>() {
        return match error {
            relay::RelayConfigError::InvalidUrl => "INVALID_INPUT",
            relay::RelayConfigError::InvalidSettings => "LOCAL_CONFIG_INVALID",
            relay::RelayConfigError::SettingsLimit => "LIMIT_EXCEEDED",
            relay::RelayConfigError::HashCollision => "LOCAL_CONFIG_CONFLICT",
            relay::RelayConfigError::Io(_) => "IO_ERROR",
        };
    }
    if error
        .downcast_ref::<lattice_relay::network::RelayNetworkError>()
        .is_some()
    {
        return "RELAY_NETWORK_ERROR";
    }
    if let Some(error) = error.downcast_ref::<OsKeyringProtectionError>() {
        return match error {
            OsKeyringProtectionError::Locked => "KEY_PROTECTION_LOCKED",
            OsKeyringProtectionError::UnsupportedPlatform => "KEY_PROTECTION_UNAVAILABLE",
            _ => "KEY_PROTECTION_ERROR",
        };
    }
    if error
        .downcast_ref::<lattice_storage::StoreError>()
        .is_some()
    {
        return "STORAGE_ERROR";
    }
    if let Some(error) = error.downcast_ref::<std::io::Error>() {
        return match error.kind() {
            std::io::ErrorKind::AlreadyExists => "OUTPUT_EXISTS",
            std::io::ErrorKind::PermissionDenied => "PERMISSION_DENIED",
            _ => "IO_ERROR",
        };
    }
    "COMMAND_FAILED"
}

fn execute(cli: Cli, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    if matches!(&cli.command, Command::About) {
        print_about(json);
        return Ok(());
    }

    // Validate values before creating profile directories or opening storage.
    let pin_input = parse_pin_input(&cli.command)?;
    let lookup_fingerprint = parse_lookup_fingerprint(&cli.command)?;
    validate_command_inputs(&cli.command)?;
    let space_input = parse_space_command_input(&cli.command)?;
    let send_input = parse_send_input(&cli.command)?;
    let space_credential = read_space_credential(&cli.command)?;
    let space_package = read_space_package(&cli.command)?;
    let data_dir = match cli.data_dir {
        Some(path) => path,
        None => default_data_directory()?,
    };
    let database_path = data_dir.join(DATABASE_NAME);
    match cli.command {
        Command::About => Ok(()),
        Command::Doctor => {
            doctor::execute_doctor(&database_path, json);
            Ok(())
        }
        Command::Peer { command } => peer::execute(command, json),
        Command::Relay { command } => relay::execute(command, &data_dir, json),
        Command::Identity { command } => {
            let (database_path, protector) = open_profile(&data_dir)?;
            execute_identity(
                &command,
                &database_path,
                &protector,
                json,
                pin_input,
                lookup_fingerprint,
            )
        }
        Command::Send { text, .. } => {
            let (database_path, protector) = open_profile(&data_dir)?;
            execute_send(
                send_input
                    .ok_or_else(|| CliError::invalid_input("send identifiers were not parsed"))?,
                space_credential
                    .ok_or_else(|| CliError::invalid_input("credential vector was not loaded"))?,
                &text,
                &database_path,
                &protector,
                json,
            )
        }
        Command::Space { command } => {
            let (database_path, protector) = open_profile(&data_dir)?;
            execute_space(
                command,
                &database_path,
                &protector,
                json,
                space_credential,
                space_package,
                space_input,
            )
        }
        Command::Status => {
            let (database_path, protector) = open_profile(&data_dir)?;
            execute_status(&database_path, &protector, json)
        }
        Command::Sync { command } => {
            let (database_path, protector) = open_profile(&data_dir)?;
            sync::execute(&command, &database_path, &protector, json)
        }
        Command::Node { command } => {
            let (database_path, protector) = open_profile(&data_dir)?;
            node::execute(&command, &database_path, &protector, json)
        }
    }
}

fn parse_pin_input(command: &Command) -> Result<Option<PinInput>, CliError> {
    match command {
        Command::Identity {
            command:
                IdentityCommand::Pin {
                    bundle_hex,
                    fingerprint_hex,
                },
        } => Ok(Some((
            parse_fixed_hex::<65>(bundle_hex, "bundle").map_err(CliError::invalid_input)?,
            parse_fixed_hex::<32>(fingerprint_hex, "fingerprint")
                .map_err(CliError::invalid_input)?,
        ))),
        _ => Ok(None),
    }
}

fn parse_lookup_fingerprint(command: &Command) -> Result<Option<[u8; 32]>, CliError> {
    match command {
        Command::Identity {
            command:
                IdentityCommand::Pinned { fingerprint_hex } | IdentityCommand::Unpin { fingerprint_hex },
        } => Ok(Some(
            parse_fixed_hex::<32>(fingerprint_hex, "fingerprint")
                .map_err(CliError::invalid_input)?,
        )),
        _ => Ok(None),
    }
}

fn validate_command_inputs(command: &Command) -> Result<(), Box<dyn Error>> {
    match command {
        Command::Sync { command } => {
            sync::validate_command(command).map_err(CliError::invalid_input)?;
        }
        Command::Node { command } => {
            node::validate_command(command).map_err(CliError::invalid_input)?;
        }
        Command::Relay { command } => match command {
            RelayCommand::Add { url }
            | RelayCommand::Remove { url }
            | RelayCommand::Test { url } => relay::validate_input_url(url)?,
            RelayCommand::List => {}
        },
        Command::Space {
            command: SpaceCommand::Create { channels, .. },
        } => {
            if channels.is_empty() || channels.len() > lattice_core::space::MAX_INITIAL_CHANNELS {
                return Err(
                    CliError::invalid_input("supply between 1 and 64 initial channels").into(),
                );
            }
            if channels
                .iter()
                .any(|name| name.is_empty() || name.len() > 128 || name.contains('\0'))
            {
                return Err(CliError::invalid_input(
                    "channel names must contain 1 to 128 UTF-8 bytes and no NUL",
                )
                .into());
            }
        }
        Command::Space {
            command: SpaceCommand::Search { query, .. },
        } if query.is_empty() || query.len() > lattice_core::MAX_LOCAL_TEXT_SEARCH_QUERY_BYTES => {
            return Err(CliError::invalid_input(format!(
                "search query must contain 1 to {} UTF-8 bytes",
                lattice_core::MAX_LOCAL_TEXT_SEARCH_QUERY_BYTES
            ))
            .into());
        }
        Command::Send { text, .. }
        | Command::Space {
            command: SpaceCommand::Edit { text, .. },
        } if text.len() > lattice_core::space::MAX_SPACE_PAYLOAD_BYTES => {
            return Err(CliError::invalid_input(format!(
                "text must contain at most {} UTF-8 bytes",
                lattice_core::space::MAX_SPACE_PAYLOAD_BYTES
            ))
            .into());
        }
        _ => {}
    }
    Ok(())
}

fn parse_send_input(command: &Command) -> Result<Option<SendInput>, CliError> {
    let Command::Send {
        space_id,
        group_reference,
        channel_id,
        ..
    } = command
    else {
        return Ok(None);
    };
    Ok(Some((
        parse_fixed_hex::<16>(space_id, "space ID").map_err(CliError::invalid_input)?,
        parse_fixed_hex::<32>(group_reference, "group reference")
            .map_err(CliError::invalid_input)?,
        parse_fixed_hex::<16>(channel_id, "channel ID").map_err(CliError::invalid_input)?,
    )))
}

fn parse_space_edit_input(command: &Command) -> Result<Option<SpaceEditInput>, CliError> {
    match command {
        Command::Space {
            command:
                SpaceCommand::Edit {
                    space_id,
                    group_reference,
                    channel_id,
                    target_message_id,
                    ..
                },
        } => Ok(Some((
            parse_fixed_hex::<16>(space_id, "space ID").map_err(CliError::invalid_input)?,
            parse_fixed_hex::<32>(group_reference, "group reference")
                .map_err(CliError::invalid_input)?,
            parse_fixed_hex::<16>(channel_id, "channel ID").map_err(CliError::invalid_input)?,
            parse_fixed_hex::<32>(target_message_id, "target message ID")
                .map_err(CliError::invalid_input)?,
        ))),
        _ => Ok(None),
    }
}
fn parse_space_restore_input(command: &Command) -> Result<Option<SpaceRestoreInput>, CliError> {
    match command {
        Command::Space {
            command:
                SpaceCommand::Restore {
                    space_id,
                    group_reference,
                }
                | SpaceCommand::Recover {
                    space_id,
                    group_reference,
                    ..
                }
                | SpaceCommand::Leave {
                    space_id,
                    group_reference,
                    ..
                }
                | SpaceCommand::Invite {
                    space_id,
                    group_reference,
                    ..
                },
        } => Ok(Some((
            parse_fixed_hex::<16>(space_id, "space ID").map_err(CliError::invalid_input)?,
            parse_fixed_hex::<32>(group_reference, "group reference")
                .map_err(CliError::invalid_input)?,
        ))),
        _ => Ok(None),
    }
}

fn parse_space_history_input(command: &Command) -> Result<Option<SpaceHistoryInput>, CliError> {
    match command {
        Command::Space {
            command:
                SpaceCommand::History {
                    space_id,
                    group_reference,
                    channel_id,
                }
                | SpaceCommand::Search {
                    space_id,
                    group_reference,
                    channel_id,
                    ..
                },
        } => Ok(Some((
            parse_fixed_hex::<16>(space_id, "space ID").map_err(CliError::invalid_input)?,
            parse_fixed_hex::<32>(group_reference, "group reference")
                .map_err(CliError::invalid_input)?,
            parse_fixed_hex::<16>(channel_id, "channel ID").map_err(CliError::invalid_input)?,
        ))),
        _ => Ok(None),
    }
}
fn parse_space_command_input(command: &Command) -> Result<SpaceCommandInput, CliError> {
    match command {
        Command::Space {
            command: SpaceCommand::Invite { .. },
        } => parse_space_restore_input(command)?
            .map(SpaceCommandInput::Invite)
            .ok_or_else(|| CliError::invalid_input("Space identifiers were not parsed")),
        Command::Space {
            command: SpaceCommand::Leave { .. },
        } => parse_space_restore_input(command)?
            .map(SpaceCommandInput::Leave)
            .ok_or_else(|| CliError::invalid_input("Space identifiers were not parsed")),
        Command::Space {
            command: SpaceCommand::Restore { .. } | SpaceCommand::Recover { .. },
        } => parse_space_restore_input(command)?
            .map(|input| match command {
                Command::Space {
                    command: SpaceCommand::Recover { .. },
                } => SpaceCommandInput::Recover(input),
                _ => SpaceCommandInput::Restore(input),
            })
            .ok_or_else(|| CliError::invalid_input("Space identifiers were not parsed")),
        Command::Space {
            command: SpaceCommand::Edit { .. },
        } => parse_space_edit_input(command)?
            .map(SpaceCommandInput::Edit)
            .ok_or_else(|| CliError::invalid_input("edit identifiers were not parsed")),
        Command::Space {
            command: SpaceCommand::History { .. },
        } => parse_space_history_input(command)?
            .map(SpaceCommandInput::History)
            .ok_or_else(|| CliError::invalid_input("history identifiers were not parsed")),
        Command::Space {
            command: SpaceCommand::Search { .. },
        } => parse_space_history_input(command)?
            .map(SpaceCommandInput::Search)
            .ok_or_else(|| CliError::invalid_input("search identifiers were not parsed")),
        Command::Space {
            command:
                SpaceCommand::Join {
                    inviter_fingerprint,
                    ..
                },
        } => Ok(SpaceCommandInput::Join(
            parse_fixed_hex::<32>(inviter_fingerprint, "inviter fingerprint")
                .map_err(CliError::invalid_input)?,
        )),
        _ => Ok(SpaceCommandInput::None),
    }
}
fn read_space_credential(command: &Command) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    let credential = match command {
        Command::Send { credential, .. }
        | Command::Space {
            command:
                SpaceCommand::Create { credential, .. }
                | SpaceCommand::Recover { credential, .. }
                | SpaceCommand::Edit { credential, .. }
                | SpaceCommand::KeyPackage { credential, .. }
                | SpaceCommand::Invite { credential, .. }
                | SpaceCommand::Join { credential, .. }
                | SpaceCommand::Leave { credential, .. },
        } => Some(credential),
        _ => None,
    };
    credential
        .map(|path| read_credential_vector(path))
        .transpose()
}

fn read_space_package(command: &Command) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    let (path, maximum, description) = match command {
        Command::Space {
            command: SpaceCommand::Join { package, .. },
        } => (
            package,
            MAX_SPACE_WELCOME_BOOTSTRAP_BYTES,
            "Welcome bootstrap package",
        ),
        Command::Space {
            command: SpaceCommand::Invite { key_package, .. },
        } => (key_package, MAX_MLS_WIRE_BYTES, "KeyPackage"),
        _ => return Ok(None),
    };
    let mut file = std::fs::File::open(path)?;
    let mut bytes = Vec::with_capacity(maximum.min(4096));
    Read::take(&mut file, (maximum + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(CliError::invalid_input(format!(
            "{description} must contain 1 to {maximum} bytes"
        ))
        .into());
    }
    Ok(Some(bytes))
}

fn open_profile(data_dir: &Path) -> Result<(PathBuf, OsKeyringProtector), Box<dyn Error>> {
    std::fs::create_dir_all(data_dir)?;
    Ok((
        data_dir.join(DATABASE_NAME),
        OsKeyringProtector::new(PROFILE_ID)?,
    ))
}

fn execute_identity(
    command: &IdentityCommand,
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
    pin_input: Option<PinInput>,
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
        IdentityCommand::Csr { output } => {
            let client = match Client::open_existing(database_path, protector) {
                Ok(client) => client,
                Err(CoreError::MissingIdentity) => {
                    return Err(CliError::missing_identity().into());
                }
                Err(error) => return Err(Box::new(error)),
            };
            let csr_pem = certificate_request_pem(&client.certificate_signing_request()?);
            if let Some(path) = output {
                write_certificate_request_pem(path, &csr_pem)?;
                if json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "schema_version": 1,
                            "command": "identity_csr",
                            "written": true,
                            "path": path.display().to_string(),
                        })
                    );
                } else {
                    println!("Certificate signing request written to {}.", path.display());
                }
            } else if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "schema_version": 1,
                        "command": "identity_csr",
                        "certificate_signing_request_pem": csr_pem,
                    })
                );
            } else {
                print!("{csr_pem}");
            }
        }
        IdentityCommand::Show => match Client::open_existing(database_path, protector) {
            Ok(client) => print_identity(client.identity_info(), json),
            Err(CoreError::MissingIdentity) => {
                return Err(CliError::missing_identity().into());
            }
            Err(error) => return Err(Box::new(error)),
        },
        IdentityCommand::Pin { .. } => {
            let (bundle, fingerprint) = pin_input.expect("pin input was parsed before storage");
            let mut client = match Client::open_existing(database_path, protector) {
                Ok(client) => client,
                Err(CoreError::MissingIdentity) => {
                    return Err(CliError::missing_identity().into());
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
                    return Err(CliError::missing_identity().into());
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
        IdentityCommand::Unpin { .. } => execute_unpin_identity(
            &lookup_fingerprint.expect("unpin fingerprint was parsed"),
            database_path,
            protector,
            json,
        )?,
    }
    Ok(())
}

fn execute_unpin_identity(
    fingerprint: &[u8; 32],
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    let mut client = match Client::open_existing(database_path, protector) {
        Ok(client) => client,
        Err(CoreError::MissingIdentity) => return Err(CliError::missing_identity().into()),
        Err(error) => return Err(Box::new(error)),
    };
    let removed = client.unpin_identity(fingerprint)?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "fingerprint": hex(fingerprint),
                "locally_removed": removed,
                "remote_identity_revoked": false,
            })
        );
    } else if removed {
        println!(
            "Removed local trust for peer {}; remote identity was not revoked.",
            hex(fingerprint)
        );
    } else {
        println!("No local trust pin exists for peer {}.", hex(fingerprint));
    }
    Ok(())
}

fn execute_space(
    command: SpaceCommand,
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
    credential_bytes: Option<Vec<u8>>,
    package_bytes: Option<Vec<u8>>,
    input: SpaceCommandInput,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        SpaceCommand::Create { channels, .. } => {
            let credential_bytes = credential_bytes
                .ok_or_else(|| CliError::invalid_input("credential vector was not loaded"))?;
            execute_space_create(credential_bytes, channels, database_path, protector, json)?;
        }
        SpaceCommand::KeyPackage { output, .. } => {
            let credential_bytes = credential_bytes
                .ok_or_else(|| CliError::invalid_input("credential vector was not loaded"))?;
            execute_space_key_package(credential_bytes, &output, database_path, protector, json)?;
        }
        command @ SpaceCommand::Invite { .. } => {
            execute_space_invite_command(
                command,
                credential_bytes,
                package_bytes,
                input,
                database_path,
                protector,
                json,
            )?;
        }
        SpaceCommand::Join { .. } => {
            execute_space_join(
                credential_bytes,
                package_bytes,
                input,
                database_path,
                protector,
                json,
            )?;
        }
        SpaceCommand::Restore { .. } => {
            execute_space_restore(input, database_path, protector, json)?;
        }
        SpaceCommand::Leave { .. } => {
            execute_space_leave(credential_bytes, input, database_path, protector, json)?;
        }
        SpaceCommand::Recover { .. } => {
            execute_space_recovery(credential_bytes, input, database_path, protector, json)?;
        }
        SpaceCommand::List { after } => {
            execute_space_list(after.as_deref(), database_path, protector, json)?;
        }
        SpaceCommand::Edit { text, .. } => {
            execute_space_edit(
                &text,
                credential_bytes,
                input,
                database_path,
                protector,
                json,
            )?;
        }
        SpaceCommand::History { .. } => {
            execute_space_history(input, database_path, protector, json)?;
        }
        SpaceCommand::Search { query, .. } => {
            execute_space_search(&query, input, database_path, protector, json)?;
        }
    }
    Ok(())
}
fn execute_space_invite_command(
    command: SpaceCommand,
    credential_bytes: Option<Vec<u8>>,
    package_bytes: Option<Vec<u8>>,
    input: SpaceCommandInput,
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let SpaceCommand::Invite {
        token_output,
        welcome_output,
        expires_at,
        expires_at_revision,
        max_uses,
        ..
    } = command
    else {
        return Err(CliError::invalid_input("Invite options were not parsed").into());
    };
    let credential_bytes = credential_bytes
        .ok_or_else(|| CliError::invalid_input("credential vector was not loaded"))?;
    let key_package_bytes =
        package_bytes.ok_or_else(|| CliError::invalid_input("KeyPackage was not loaded"))?;
    let SpaceCommandInput::Invite((space_id, group_reference)) = input else {
        return Err(CliError::invalid_input("Space identifiers were not parsed").into());
    };
    ensure_new_output_paths(&[&token_output, &welcome_output])?;
    if expires_at <= unix_time_now()? {
        return Err(CliError::invalid_input("invite expiry must be in the future").into());
    }
    execute_space_invite(
        credential_bytes,
        &key_package_bytes,
        space_id,
        group_reference,
        &token_output,
        &welcome_output,
        expires_at,
        expires_at_revision,
        max_uses,
        database_path,
        protector,
        json,
    )
}

fn execute_space_leave(
    credential_bytes: Option<Vec<u8>>,
    input: SpaceCommandInput,
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let credential_bytes = credential_bytes
        .ok_or_else(|| CliError::invalid_input("credential vector was not loaded"))?;
    let SpaceCommandInput::Leave((space_id, group_reference)) = input else {
        return Err(CliError::invalid_input("Leave identifiers were not parsed").into());
    };
    let mut client = match Client::open_existing(database_path, protector) {
        Ok(client) => client,
        Err(CoreError::MissingIdentity) => return Err(CliError::missing_identity().into()),
        Err(error) => return Err(Box::new(error)),
    };
    let event_id = client.request_space_leave_from_x509_credential(
        &space_id,
        &group_reference,
        credential_bytes,
    )?;
    print_queued_event(json, "space_leave", "Leave request queued", &event_id);
    Ok(())
}

fn execute_space_edit(
    text: &str,
    credential_bytes: Option<Vec<u8>>,
    input: SpaceCommandInput,
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let credential_bytes = credential_bytes
        .ok_or_else(|| CliError::invalid_input("credential vector was not loaded"))?;
    let SpaceCommandInput::Edit((space_id, group_reference, channel_id, target)) = input else {
        return Err(CliError::invalid_input("edit identifiers were not parsed").into());
    };
    let mut client = match Client::open_existing(database_path, protector) {
        Ok(client) => client,
        Err(CoreError::MissingIdentity) => return Err(CliError::missing_identity().into()),
        Err(error) => return Err(Box::new(error)),
    };
    let queued = client.queue_text_message_edit_from_x509_credential(
        &space_id,
        &group_reference,
        credential_bytes,
        channel_id,
        target,
        text,
    )?;
    print_queued_event(json, "space_edit", "Edit queued", queued.event_id());
    Ok(())
}

fn execute_space_history(
    input: SpaceCommandInput,
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let SpaceCommandInput::History((space_id, group_reference, channel_id)) = input else {
        return Err(CliError::invalid_input("history identifiers were not parsed").into());
    };
    let mut client = match Client::open_existing(database_path, protector) {
        Ok(client) => client,
        Err(CoreError::MissingIdentity) => return Err(CliError::missing_identity().into()),
        Err(error) => return Err(Box::new(error)),
    };
    let messages = client.local_text_message_history(&space_id, &group_reference, &channel_id)?;
    print_space_history(&space_id, &group_reference, &channel_id, &messages, json);
    Ok(())
}

fn execute_space_search(
    query: &str,
    input: SpaceCommandInput,
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let SpaceCommandInput::Search((space_id, group_reference, channel_id)) = input else {
        return Err(CliError::invalid_input("search identifiers were not parsed").into());
    };
    let mut client = match Client::open_existing(database_path, protector) {
        Ok(client) => client,
        Err(CoreError::MissingIdentity) => return Err(CliError::missing_identity().into()),
        Err(error) => return Err(Box::new(error)),
    };
    let result =
        client.search_local_text_messages(&space_id, &group_reference, &channel_id, query)?;
    print_space_search(
        &space_id,
        &group_reference,
        &channel_id,
        query,
        &result,
        json,
    );
    Ok(())
}

fn execute_send(
    input: SendInput,
    credential_bytes: Vec<u8>,
    text: &str,
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (space_id, group_reference, channel_id) = input;
    let mut client = match Client::open_existing(database_path, protector) {
        Ok(client) => client,
        Err(CoreError::MissingIdentity) => {
            return Err(CliError::missing_identity().into());
        }
        Err(error) => return Err(Box::new(error)),
    };
    let queued = client.queue_text_message_from_x509_credential(
        &space_id,
        &group_reference,
        credential_bytes,
        channel_id,
        text,
    )?;
    print_queued_event(json, "send", "Queued", queued.event_id());
    Ok(())
}

fn execute_space_list(
    after: Option<&str>,
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let after = after
        .map(parse_space_cursor)
        .transpose()
        .map_err(|error| CliError::invalid_input(format!("invalid --after cursor: {error}")))?;
    let mut client = match Client::open_existing(database_path, protector) {
        Ok(client) => client,
        Err(CoreError::MissingIdentity) => {
            return Err(CliError::missing_identity().into());
        }
        Err(error) => return Err(Box::new(error)),
    };
    let page = client.restore_space_page(after)?;
    print_space_page(&page, json);
    Ok(())
}

fn execute_space_join(
    credential_bytes: Option<Vec<u8>>,
    package_bytes: Option<Vec<u8>>,
    input: SpaceCommandInput,
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let credential_bytes = credential_bytes
        .ok_or_else(|| CliError::invalid_input("credential vector was not loaded"))?;
    let package_bytes = package_bytes
        .ok_or_else(|| CliError::invalid_input("Welcome bootstrap package was not loaded"))?;
    let SpaceCommandInput::Join(expected_inviter) = input else {
        return Err(CliError::invalid_input("inviter fingerprint was not parsed").into());
    };
    let mut client = match Client::open_existing(database_path, protector) {
        Ok(client) => client,
        Err(CoreError::MissingIdentity) => {
            return Err(CliError::missing_identity().into());
        }
        Err(error) => return Err(Box::new(error)),
    };
    let space = client.join_space_from_welcome_bootstrap_from_x509_credential(
        &package_bytes,
        expected_inviter,
        credential_bytes,
    )?;
    let space_id = hex(space.space_id());
    let group_reference = hex(space.group_reference());
    let root_event_id = hex(space.genesis_event().event_id().as_bytes());
    let channels = space::channel_summaries(space.reducer());
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "command": "space_join",
                "state": "local_welcome_imported",
                "space_id": space_id,
                "group_reference": group_reference,
                "root_event_id": root_event_id,
                "channels": channels,
                "local_state_persisted": true,
                "network_contacted": false,
                "peer_delivery": false,
                "general_history_replayed": false,
            })
        );
    } else {
        println!("Imported a local Space generation from the Welcome package.");
        println!("Space ID: {space_id}");
        println!("MLS group reference: {group_reference}");
        println!("Root event ID: {root_event_id}");
        println!(
            "This import persisted local state only; no relay or peer delivery, and no general message history replay."
        );
    }
    Ok(())
}

fn execute_space_key_package(
    credential_bytes: Vec<u8>,
    output: &Path,
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_new_output_paths(&[output])?;
    let now = unix_time_now()?;
    let mut client = match Client::open_existing(database_path, protector) {
        Ok(client) => client,
        Err(CoreError::MissingIdentity) => return Err(CliError::missing_identity().into()),
        Err(error) => return Err(Box::new(error)),
    };
    let credential = Credential::new(CredentialType::X509, credential_bytes);
    let credential = client.with_mls_transaction(|identity, _, _| {
        DeviceCredentialInput::from_x509_credential(identity, credential).map_err(CoreError::Mls)
    })?;
    let wire = client.publish_key_package(&credential, now)?;
    write_new_files(&[(output, &wire)])?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "command": "space_key_package",
                "state": "published_locally",
                "output_file": output,
                "key_package_bytes": wire.len(),
                "tracked_as_one_time": true,
                "network_contacted": false,
            })
        );
    } else {
        println!(
            "Published a fresh one-time KeyPackage to {}.",
            output.display()
        );
        println!("No network contact was made.");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn execute_space_invite(
    credential_bytes: Vec<u8>,
    key_package_bytes: &[u8],
    space_id: [u8; 16],
    group_reference: [u8; 32],
    token_output: &Path,
    welcome_output: &Path,
    expires_at: u64,
    expires_at_revision: Option<u64>,
    max_uses: Option<u16>,
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = match Client::open_existing(database_path, protector) {
        Ok(client) => client,
        Err(CoreError::MissingIdentity) => return Err(CliError::missing_identity().into()),
        Err(error) => return Err(Box::new(error)),
    };
    let credential_content = Credential::new(CredentialType::X509, credential_bytes);
    let credential = client.with_mls_transaction(|identity, _, _| {
        DeviceCredentialInput::from_x509_credential(identity, credential_content)
            .map_err(CoreError::Mls)
    })?;
    let mut space = client.restore_space(&space_id, &group_reference)?;
    let invitation = client.create_space_invite(
        &mut space,
        &credential,
        key_package_bytes,
        expires_at_revision,
        expires_at,
        max_uses,
    )?;
    let invite_event_id = hex(invitation.invite_event_id());
    let target_fingerprint = hex(invitation.target_fingerprint());
    write_new_files(&[
        (token_output, invitation.token()),
        (welcome_output, invitation.welcome_bootstrap()),
    ])?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "command": "space_invite",
                "state": "invitation_created_locally",
                "invite_event_id": invite_event_id,
                "target_fingerprint": target_fingerprint,
                "token_file": token_output,
                "welcome_file": welcome_output,
                "expires_at_unix_seconds": expires_at,
                "expires_at_revision": expires_at_revision,
                "max_uses": max_uses,
                "events_queued": 3,
                "peer_delivery": false,
                "network_contacted": false,
            })
        );
    } else {
        println!("Created an offline invitation for {target_fingerprint}.");
        println!("Invite event: {invite_event_id}");
        println!("Signed token: {}", token_output.display());
        println!("Welcome bootstrap: {}", welcome_output.display());
        println!("Queued locally only; no relay or peer delivery occurred.");
    }
    Ok(())
}

fn unix_time_now() -> Result<u64, Box<dyn std::error::Error>> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CliError::invalid_input("system clock is before the Unix epoch"))?
        .as_secs())
}

fn ensure_new_output_paths(paths: &[&Path]) -> Result<(), Box<dyn std::error::Error>> {
    let mut canonical_paths = Vec::with_capacity(paths.len());
    for path in paths {
        let file_name = path
            .file_name()
            .ok_or_else(|| CliError::invalid_input("output path must name a file"))?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let canonical = parent.canonicalize()?.join(file_name);
        if canonical_paths.contains(&canonical) {
            return Err(CliError::invalid_input("output paths must be distinct").into());
        }
        if path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("output file already exists: {}", path.display()),
            )
            .into());
        }
        canonical_paths.push(canonical);
    }
    Ok(())
}

fn write_new_files(files: &[(&Path, &[u8])]) -> Result<(), Box<dyn std::error::Error>> {
    let mut opened = Vec::with_capacity(files.len());
    for (path, _) in files {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(file) => opened.push((path.to_path_buf(), file)),
            Err(error) => {
                let created_count = opened.len();
                drop(opened);
                for (created_path, _) in files.iter().take(created_count) {
                    let _ = std::fs::remove_file(created_path);
                }
                return Err(error.into());
            }
        }
    }
    for (index, (_, bytes)) in files.iter().enumerate() {
        if let Err(error) = std::io::Write::write_all(&mut opened[index].1, bytes) {
            drop(opened);
            for (path, _) in files {
                let _ = std::fs::remove_file(path);
            }
            return Err(error.into());
        }
    }
    Ok(())
}

fn execute_space_recovery(
    credential_bytes: Option<Vec<u8>>,
    input: SpaceCommandInput,
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let credential_bytes = credential_bytes
        .ok_or_else(|| CliError::invalid_input("credential vector was not loaded"))?;
    let SpaceCommandInput::Recover((space_id, prior_group_reference)) = input else {
        return Err(CliError::invalid_input("recovery identifiers were not parsed").into());
    };
    let mut client = match Client::open_existing(database_path, protector) {
        Ok(client) => client,
        Err(CoreError::MissingIdentity) => {
            return Err(CliError::missing_identity().into());
        }
        Err(error) => return Err(Box::new(error)),
    };
    let space = client.recover_space_generation_from_x509_credential(
        &space_id,
        &prior_group_reference,
        credential_bytes,
    )?;
    let space_id = hex(space.space_id());
    let group_reference = hex(space.group_reference());
    let channels = space::channel_summaries(space.reducer());
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "command": "space_recover",
                "state": "one_member_recovery_generation_created",
                "space_id": space_id,
                "prior_group_reference": hex(&prior_group_reference),
                "group_reference": group_reference,
                "channels": channels,
                "prior_members_rejoined": false,
                "network_contacted": false,
            })
        );
    } else {
        println!("Created a local one-member Space recovery generation.");
        println!("Space ID: {space_id}");
        println!("Prior MLS group reference: {}", hex(&prior_group_reference));
        println!("New MLS group reference: {group_reference}");
        println!("Existing members were not rejoined; no network contact was made.");
    }
    Ok(())
}

fn execute_space_restore(
    input: SpaceCommandInput,
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let SpaceCommandInput::Restore((space_id, group_reference)) = input else {
        return Err(CliError::invalid_input("restore identifiers were not parsed").into());
    };
    let mut client = match Client::open_existing(database_path, protector) {
        Ok(client) => client,
        Err(CoreError::MissingIdentity) => {
            return Err(CliError::missing_identity().into());
        }
        Err(error) => return Err(Box::new(error)),
    };
    let space = client.restore_space(&space_id, &group_reference)?;
    let space_id = hex(space.space_id());
    let group_reference = hex(space.group_reference());
    let channels = space::channel_summaries(space.reducer());
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "command": "space_restore",
                "state": "local_snapshot_restored",
                "space_id": space_id,
                "group_reference": group_reference,
                "channels": channels,
                "remote_membership": "not_checked",
                "network_contacted": false,
            })
        );
    } else {
        println!("Restored local Space Genesis snapshot.");
        println!("Space ID: {space_id}");
        println!("MLS group reference: {group_reference}");
        for channel in channels {
            println!(
                "Channel {}: {} (type: {}, archived: {})",
                channel["id"].as_str().unwrap_or_default(),
                channel["name"].as_str().unwrap_or_default(),
                channel["type"].as_str().unwrap_or_default(),
                channel["archived"].as_bool().unwrap_or(false)
            );
        }
        println!("This verifies local state only; remote membership was not checked.");
    }
    Ok(())
}

fn queued_event_json(command: &str, event_id: &[u8; 32]) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "command": command,
        "state": "queued",
        "event_id": hex(event_id),
        "forwarded": false,
        "delivered": false,
        "network_contacted": false,
    })
}

fn print_queued_event(json: bool, command: &str, label: &str, event_id: &[u8; 32]) {
    if json {
        println!("{}", queued_event_json(command, event_id));
    } else {
        let event_id = hex(event_id);
        println!("{label} locally: event {event_id}");
        println!("Not forwarded or delivered; no network contact was made.");
    }
}

fn read_credential_vector(path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut file = std::fs::File::open(path)?;
    let mut bytes = Vec::with_capacity(MAX_SPACE_CREDENTIAL_BYTES.min(4096));
    Read::take(&mut file, (MAX_SPACE_CREDENTIAL_BYTES + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > MAX_SPACE_CREDENTIAL_BYTES {
        return Err(CliError::invalid_input(format!(
            "credential vector must contain 1 to {MAX_SPACE_CREDENTIAL_BYTES} bytes"
        ))
        .into());
    }
    Ok(bytes)
}

fn execute_space_create(
    credential_bytes: Vec<u8>,
    channel_names: Vec<String>,
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let credential = Credential::new(CredentialType::X509, credential_bytes);
    let mut client = match Client::open_existing(database_path, protector) {
        Ok(client) => client,
        Err(CoreError::MissingIdentity) => {
            return Err(CliError::missing_identity().into());
        }
        Err(error) => return Err(Box::new(error)),
    };
    let credential = client.with_mls_transaction(|identity, _, _| {
        DeviceCredentialInput::from_x509_credential(identity, credential).map_err(CoreError::Mls)
    })?;
    let channels = channel_names
        .into_iter()
        .map(|name| InitialChannel {
            channel_type: ChannelType::Text,
            name,
            default_allow: 0,
            default_deny: 0,
            role_overrides: Vec::new(),
        })
        .collect();
    let space = client.create_space(&credential, channels)?;
    let identity = client.identity_info();
    let space_id = hex(space.space_id());
    let group_reference = hex(space.group_reference());
    let genesis_event_id = hex(space.genesis_event().event_id().as_bytes());
    let fingerprint = hex(&identity.fingerprint);
    let channels = space::channel_summaries(space.reducer());
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "command": "space_create",
                "state": "local_genesis_created",
                "space_id": space_id,
                "group_reference": group_reference,
                "genesis_event_id": genesis_event_id,
                "creator_fingerprint": fingerprint,
                "channels": channels,
                "local_snapshot_persisted": true,
                "membership_claimed": false,
                "remote_membership": "not_checked",
                "network_contacted": false,
            })
        );
    } else {
        println!("Created a locally recoverable Space Genesis snapshot.");
        println!("Space ID: {space_id}");
        println!("MLS group reference: {group_reference}");
        println!("Genesis event ID: {genesis_event_id}");
        println!("Creator fingerprint: {fingerprint}");
        for channel in channels {
            println!(
                "Channel {}: {} (type: {}, archived: {})",
                channel["id"].as_str().unwrap_or_default(),
                channel["name"].as_str().unwrap_or_default(),
                channel["type"].as_str().unwrap_or_default(),
                channel["archived"].as_bool().unwrap_or(false)
            );
        }
        println!("This local Genesis does not establish current or remote membership.");
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
                        "message_authoring": true,
                        "network_delivery": false,
                    })
                );
            } else {
                println!("Device identity: initialized");
                println!("Next local event sequence: {sequence}");
                println!("Local message authoring: available to the outbox only");
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
                println!("Local message authoring: unavailable until identity initialization");
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
                    "identity_csr_export",
                    "local_identity_pinning",
                    "local_peer_pin_revocation",
                    "local_event_storage",
                    "local_space_genesis_creation",
                    "local_space_genesis_listing_and_restoration",
                    "local_space_one_member_recovery",
                    "local_space_key_package_publication",
                    "local_space_invitation_creation",
                    "local_space_leave_request",
                    "local_pinned_welcome_bootstrap_import",
                    "local_text_message_queue_and_edit",
                    "local_outgoing_message_history",
                    "local_outbox_state_inspection",
                    "local_relay_settings",
                    "relay_nip11_metadata_probe",
                    "local_profile_diagnostics"
                ],
                "unavailable": [
                    "peer_membership_commit",
                    "certificate_issuance_or_import",
                    "network_message_forwarding_or_delivery",
                    "peer_synchronization",
                    "voice_media",
                    "remote_identity_revocation"
                ],
            })
        );
    } else {
        println!("Lattice local-first communication");
        println!(
            "Available: protected device identity, CSR export, local identity pins and local trust removal; local Space Genesis create/list/restore, one-time KeyPackage publication, signed offline invitations, pinned-inviter Welcome import, one-member recovery, and queued self-leave requests; text send/edit, outgoing history and outbox inspection; local relay settings/probes; profile diagnostics."
        );
        println!(
            "Not available: peer-side membership commits, certificate issuance/import, remote identity revocation, peer synchronization, message forwarding/delivery, or voice media."
        );
        println!("A local queue state is not evidence of relay forwarding or recipient delivery.");
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

pub(crate) fn parse_fixed_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
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
                "protected_key_access": "available",
                "capabilities": {
                    "authenticated_spaces": false,
                    "message_authoring": true,
                    "network_delivery": false,
                },
            })
        );
    } else {
        println!("Fingerprint: {fingerprint}");
        println!("Public bundle: {public_bundle}");
        println!("OS-protected private-key access: available; private key not exposed.");
        println!(
            "Local message authoring (outbox only): available; authenticated Spaces, forwarding, and delivery unavailable."
        );
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
        Cli, Command, IdentityCommand, SpaceCommand, SpaceCommandInput, execute, parse_fixed_hex,
        parse_lookup_fingerprint, parse_send_input, parse_space_command_input, parse_space_cursor,
        parse_space_edit_input, parse_space_history_input, queued_event_json, space_cursor_hex,
        validate_command_inputs,
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
    fn top_level_send_parses_canonical_arguments_and_rejects_invalid_identifiers() {
        let mut parsed = Cli::try_parse_from([
            "lattice",
            "send",
            "--space-id",
            &"11".repeat(16),
            "--group-reference",
            &"22".repeat(32),
            "--credential",
            "device.der",
            "--channel-id",
            &"33".repeat(16),
            "--text",
            "queued text",
        ])
        .expect("top-level send arguments parse");
        assert_eq!(
            parse_send_input(&parsed.command).expect("fixed IDs parse"),
            Some(([0x11; 16], [0x22; 32], [0x33; 16]))
        );
        if let Command::Send { channel_id, .. } = &mut parsed.command {
            *channel_id = "not-a-channel-id".to_owned();
        } else {
            panic!("expected top-level send command");
        }
        assert!(parse_send_input(&parsed.command).is_err());
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock follows epoch")
            .as_nanos();
        let data_dir = std::env::temp_dir().join(format!(
            "lattice-cli-invalid-send-{}-{nonce}",
            std::process::id(),
        ));
        let credential_path = std::env::temp_dir().join(format!(
            "lattice-cli-send-credential-{}-{nonce}.der",
            std::process::id(),
        ));
        std::fs::write(&credential_path, b"invalid fixture").expect("write credential input");
        if let Command::Send { credential, .. } = &mut parsed.command {
            *credential = credential_path.clone();
        }
        let result = execute(
            Cli {
                data_dir: Some(data_dir.clone()),
                json: true,
                command: parsed.command,
            },
            true,
        );
        assert!(result.is_err());
        assert!(!data_dir.exists());
        std::fs::remove_file(credential_path).expect("remove credential fixture");
    }

    #[test]
    fn queued_send_json_never_claims_forwarding_or_delivery() {
        let output = queued_event_json("send", &[0xAB; 32]);
        let encoded = output.to_string();
        let parsed: serde_json::Value =
            serde_json::from_str(&encoded).expect("machine output is valid JSON");

        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["command"], "send");
        assert_eq!(parsed["state"], "queued");
        assert_eq!(parsed["event_id"], "ab".repeat(32));
        assert_eq!(parsed["forwarded"], false);
        assert_eq!(parsed["delivered"], false);
        assert_eq!(parsed["network_contacted"], false);
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
        let unpin = Cli::try_parse_from([
            "lattice",
            "identity",
            "unpin",
            "--fingerprint-hex",
            &"ef".repeat(32),
        ])
        .expect("unpin arguments parse");
        assert_eq!(
            parse_lookup_fingerprint(&unpin.command).expect("unpin fingerprint parses"),
            Some([0xef; 32])
        );
    }

    #[test]
    fn space_edit_parses_and_validates_all_immutable_identifiers() {
        let mut parsed = Cli::try_parse_from([
            "lattice",
            "space",
            "edit",
            "--space-id",
            &"11".repeat(16),
            "--group-reference",
            &"22".repeat(32),
            "--credential",
            "device.der",
            "--channel-id",
            &"33".repeat(16),
            "--target-message-id",
            &"44".repeat(32),
            "--text",
            "replacement",
        ])
        .expect("edit arguments parse");
        assert_eq!(
            parse_space_edit_input(&parsed.command).expect("fixed IDs parse"),
            Some(([0x11; 16], [0x22; 32], [0x33; 16], [0x44; 32]))
        );
        if let Command::Space {
            command: SpaceCommand::Edit {
                target_message_id, ..
            },
        } = &mut parsed.command
        {
            *target_message_id = "44".repeat(31);
        } else {
            panic!("expected space edit command");
        }
        assert!(parse_space_edit_input(&parsed.command).is_err());
    }

    #[test]
    fn space_leave_parses_identifiers_for_a_queued_request() {
        let parsed = Cli::try_parse_from([
            "lattice",
            "space",
            "leave",
            "--space-id",
            &"11".repeat(16),
            "--group-reference",
            &"22".repeat(32),
            "--credential",
            "device.der",
        ])
        .expect("Leave command parses");
        assert!(matches!(
            parse_space_command_input(&parsed.command),
            Ok(SpaceCommandInput::Leave((space_id, group_reference)))
                if space_id == [0x11; 16] && group_reference == [0x22; 32]
        ));
        assert!(validate_command_inputs(&parsed.command).is_ok());
    }

    #[test]
    fn space_invite_and_key_package_commands_parse_local_artifact_inputs() {
        let invite = Cli::try_parse_from([
            "lattice",
            "space",
            "invite",
            "--space-id",
            &"11".repeat(16),
            "--group-reference",
            &"22".repeat(32),
            "--credential",
            "inviter.der",
            "--key-package",
            "invitee.kp",
            "--token-output",
            "invite.token",
            "--welcome-output",
            "welcome.pkg",
            "--expires-at",
            "2000000000",
            "--max-uses",
            "1",
        ])
        .expect("Invite command parses");
        assert!(matches!(
            parse_space_command_input(&invite.command),
            Ok(SpaceCommandInput::Invite((space_id, group_reference)))
                if space_id == [0x11; 16] && group_reference == [0x22; 32]
        ));
        assert!(validate_command_inputs(&invite.command).is_ok());

        let key_package = Cli::try_parse_from([
            "lattice",
            "space",
            "key-package",
            "--credential",
            "device.der",
            "--output",
            "device.kp",
        ])
        .expect("KeyPackage command parses");
        assert!(matches!(
            key_package.command,
            Command::Space {
                command: SpaceCommand::KeyPackage { output, .. }
            } if output == std::path::Path::new("device.kp")
        ));
    }

    #[test]
    fn space_history_parses_and_validates_immutable_identifiers() {
        let mut parsed = Cli::try_parse_from([
            "lattice",
            "space",
            "history",
            "--space-id",
            &"11".repeat(16),
            "--group-reference",
            &"22".repeat(32),
            "--channel-id",
            &"33".repeat(16),
        ])
        .expect("history arguments parse");
        assert_eq!(
            parse_space_history_input(&parsed.command).expect("fixed IDs parse"),
            Some(([0x11; 16], [0x22; 32], [0x33; 16]))
        );
        if let Command::Space {
            command: SpaceCommand::History { channel_id, .. },
        } = &mut parsed.command
        {
            *channel_id = "33".repeat(15);
        } else {
            panic!("expected space history command");
        }
        assert!(parse_space_history_input(&parsed.command).is_err());
    }

    #[test]
    fn space_search_parses_bounds_and_reports_local_match_counts() {
        use lattice_core::{LocalTextMessageRecord, LocalTextMessageSearchResult, OutboxState};

        let mut parsed = Cli::try_parse_from([
            "lattice",
            "space",
            "search",
            "--space-id",
            &"11".repeat(16),
            "--group-reference",
            &"22".repeat(32),
            "--channel-id",
            &"33".repeat(16),
            "--query",
            "needle",
        ])
        .expect("search command parses");
        assert_eq!(
            parse_space_history_input(&parsed.command).expect("search IDs parse"),
            Some(([0x11; 16], [0x22; 32], [0x33; 16]))
        );
        assert!(matches!(
            parse_space_command_input(&parsed.command),
            Ok(SpaceCommandInput::Search(_))
        ));
        assert!(validate_command_inputs(&parsed.command).is_ok());

        if let Command::Space {
            command: SpaceCommand::Search { query, .. },
        } = &mut parsed.command
        {
            query.clear();
        }
        assert!(validate_command_inputs(&parsed.command).is_err());
        if let Command::Space {
            command: SpaceCommand::Search { query, .. },
        } = &mut parsed.command
        {
            *query = "x".repeat(lattice_core::MAX_LOCAL_TEXT_SEARCH_QUERY_BYTES + 1);
        }
        assert!(validate_command_inputs(&parsed.command).is_err());

        let result = LocalTextMessageSearchResult {
            messages: vec![LocalTextMessageRecord {
                event_id: [0x44; 32],
                channel_id: [0x33; 16],
                author_id: [0x55; 32],
                author_sequence: 7,
                lamport: 9,
                content: "needle match".to_owned(),
                outbox_state: Some(OutboxState::Queued),
            }],
            total_matches: 3,
            scanned_messages: 12,
        };
        let output = super::space::space_search_json(
            &[0x11; 16],
            &[0x22; 32],
            &[0x33; 16],
            "needle",
            &result,
        );
        assert_eq!(output["command"], "space_search");
        assert_eq!(output["network_contacted"], false);
        assert_eq!(output["total_matches"], 3);
        assert_eq!(output["scanned_messages"], 12);
        assert_eq!(output["returned_matches"], 1);
        assert_eq!(output["messages"][0]["event_id"], "44".repeat(32));
        assert_eq!(output["messages"][0]["outbox_state"], "queued");
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
    #[test]
    fn identity_csr_command_accepts_output_path() {
        let parsed = Cli::try_parse_from(["lattice", "identity", "csr", "--output", "device.csr"])
            .expect("certificate request command parses");
        assert!(matches!(
            parsed.command,
            Command::Identity {
                command: IdentityCommand::Csr { output: Some(path) }
            } if path == std::path::Path::new("device.csr")
        ));
    }

    #[test]
    fn certificate_request_output_uses_pem_framing_and_wrapping() {
        let pem = super::certificate_request_pem(&[0; 48]);
        assert_eq!(
            pem,
            format!(
                "-----BEGIN CERTIFICATE REQUEST-----\n{}\n-----END CERTIFICATE REQUEST-----\n",
                "A".repeat(64)
            )
        );
    }

    #[test]
    fn invite_artifact_writer_preserves_existing_file_and_cleans_partial_output() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock follows epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "lattice-cli-invite-output-{}-{nonce}",
            std::process::id(),
        ));
        std::fs::create_dir(&directory).expect("create isolated output directory");
        let new_output = directory.join("token.bin");
        let existing_output = directory.join("welcome.bin");
        std::fs::write(&existing_output, b"preserve existing bytes")
            .expect("create existing output fixture");
        let error = super::write_new_files(&[
            (&new_output, b"new token"),
            (&existing_output, b"replacement welcome"),
        ])
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .expect("writer reports the filesystem error")
                .kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert!(!new_output.exists(), "partial output is removed");
        assert_eq!(
            std::fs::read(&existing_output).expect("read untouched existing file"),
            b"preserve existing bytes"
        );
        std::fs::remove_dir_all(directory).expect("remove temporary outputs");
    }

    #[test]
    fn csr_output_does_not_replace_existing_file() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock follows epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "lattice-cli-csr-{}-{nonce}.pem",
            std::process::id(),
        ));
        std::fs::write(&path, b"existing certificate request")
            .expect("create existing output fixture");
        let error =
            super::identity::write_certificate_request_pem(&path, "replacement").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(&path).expect("read preserved output"),
            b"existing certificate request"
        );
        std::fs::remove_file(path).expect("remove output fixture");
    }
}
