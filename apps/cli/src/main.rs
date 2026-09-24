mod doctor;
mod identity;
mod relay;
mod space;
mod sync;

use identity::{
    IdentityCommand, certificate_request_pem, print_pinned_identity, write_certificate_request_pem,
};
use relay::RelayCommand;
use space::{SpaceCommand, print_space_history, print_space_page};
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
    Client, CoreError, DeviceIdentityInfo, InitialChannel, SpaceGenesisCursor, space::ChannelType,
};
use lattice_mls::api::DeviceCredentialInput;
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
    /// Create, list, restore, or recover local Space generations.
    Space {
        #[command(subcommand)]
        command: SpaceCommand,
    },
    /// Report local identity and event-sequence readiness without creating keys.
    Status,
    /// Inspect local profile, protected keys, storage schema, and unavailable transport/wire checks without applying migrations.
    Doctor,
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
}

type PinInput = ([u8; 65], [u8; 32]);
type SpaceMessageInput = ([u8; 16], [u8; 32], [u8; 16]);
type SpaceEditInput = ([u8; 16], [u8; 32], [u8; 16], [u8; 32]);
type SpaceHistoryInput = ([u8; 16], [u8; 32], [u8; 16]);
type SpaceRestoreInput = ([u8; 16], [u8; 32]);
#[derive(Clone, Copy)]
enum SpaceCommandInput {
    None,
    Restore(SpaceRestoreInput),
    Recover(SpaceRestoreInput),
    Message(SpaceMessageInput),
    Edit(SpaceEditInput),
    History(SpaceHistoryInput),
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
            CoreError::PinnedIdentityConflict => "PIN_CONFLICT",
            CoreError::Storage(_) => "STORAGE_ERROR",
            CoreError::Identity(_) => "IDENTITY_ERROR",
            CoreError::Mls(_) => "MLS_ERROR",
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
    let space_credential = read_space_credential(&cli.command)?;
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
        Command::Space { command } => {
            let (database_path, protector) = open_profile(&data_dir)?;
            execute_space(
                command,
                &database_path,
                &protector,
                json,
                space_credential,
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
            command: IdentityCommand::Pinned { fingerprint_hex },
        } => Ok(Some(
            parse_fixed_hex::<32>(fingerprint_hex, "fingerprint")
                .map_err(CliError::invalid_input)?,
        )),
        _ => Ok(None),
    }
}

fn validate_command_inputs(command: &Command) -> Result<(), Box<dyn Error>> {
    match command {
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
            command: SpaceCommand::Message { text, .. } | SpaceCommand::Edit { text, .. },
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

fn parse_space_message_input(command: &Command) -> Result<Option<SpaceMessageInput>, CliError> {
    match command {
        Command::Space {
            command:
                SpaceCommand::Message {
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
            command: SpaceCommand::Message { .. },
        } => parse_space_message_input(command)?
            .map(SpaceCommandInput::Message)
            .ok_or_else(|| CliError::invalid_input("message identifiers were not parsed")),
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
        _ => Ok(SpaceCommandInput::None),
    }
}
fn read_space_credential(command: &Command) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    let Command::Space {
        command:
            SpaceCommand::Create { credential, .. }
            | SpaceCommand::Recover { credential, .. }
            | SpaceCommand::Message { credential, .. }
            | SpaceCommand::Edit { credential, .. },
    } = command
    else {
        return Ok(None);
    };
    Ok(Some(read_credential_vector(credential)?))
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
    }
    Ok(())
}

fn execute_space(
    command: SpaceCommand,
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
    credential_bytes: Option<Vec<u8>>,
    input: SpaceCommandInput,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        SpaceCommand::Create { channels, .. } => {
            let credential_bytes = credential_bytes
                .ok_or_else(|| CliError::invalid_input("credential vector was not loaded"))?;
            execute_space_create(credential_bytes, channels, database_path, protector, json)?;
        }
        SpaceCommand::Restore { .. } => {
            execute_space_restore(input, database_path, protector, json)?;
        }
        SpaceCommand::Recover { .. } => {
            execute_space_recovery(credential_bytes, input, database_path, protector, json)?;
        }
        SpaceCommand::List { after } => {
            let after = after
                .as_deref()
                .map(parse_space_cursor)
                .transpose()
                .map_err(|error| {
                    CliError::invalid_input(format!("invalid --after cursor: {error}"))
                })?;
            let mut client = match Client::open_existing(database_path, protector) {
                Ok(client) => client,
                Err(CoreError::MissingIdentity) => {
                    return Err(CliError::missing_identity().into());
                }
                Err(error) => return Err(Box::new(error)),
            };
            let page = client.restore_space_page(after)?;
            print_space_page(&page, json);
        }
        SpaceCommand::Message { text, .. } => {
            let credential_bytes = credential_bytes
                .ok_or_else(|| CliError::invalid_input("credential vector was not loaded"))?;
            let SpaceCommandInput::Message((space_id, group_reference, channel_id)) = input else {
                return Err(CliError::invalid_input("message identifiers were not parsed").into());
            };
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
                &text,
            )?;
            print_queued_event(json, "space_message", "Queued", queued.event_id());
        }
        SpaceCommand::Edit { text, .. } => {
            let credential_bytes = credential_bytes
                .ok_or_else(|| CliError::invalid_input("credential vector was not loaded"))?;
            let SpaceCommandInput::Edit((space_id, group_reference, channel_id, target)) = input
            else {
                return Err(CliError::invalid_input("edit identifiers were not parsed").into());
            };
            let mut client = match Client::open_existing(database_path, protector) {
                Ok(client) => client,
                Err(CoreError::MissingIdentity) => {
                    return Err(CliError::missing_identity().into());
                }
                Err(error) => return Err(Box::new(error)),
            };
            let queued = client.queue_text_message_edit_from_x509_credential(
                &space_id,
                &group_reference,
                credential_bytes,
                channel_id,
                target,
                &text,
            )?;
            print_queued_event(json, "space_edit", "Edit queued", queued.event_id());
        }
        SpaceCommand::History { .. } => {
            let SpaceCommandInput::History((space_id, group_reference, channel_id)) = input else {
                return Err(CliError::invalid_input("history identifiers were not parsed").into());
            };
            let mut client = match Client::open_existing(database_path, protector) {
                Ok(client) => client,
                Err(CoreError::MissingIdentity) => {
                    return Err(CliError::missing_identity().into());
                }
                Err(error) => return Err(Box::new(error)),
            };
            let messages =
                client.local_text_message_history(&space_id, &group_reference, &channel_id)?;
            print_space_history(&space_id, &group_reference, &channel_id, &messages, json);
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

fn print_queued_event(json: bool, command: &str, label: &str, event_id: &[u8; 32]) {
    let event_id = hex(event_id);
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "command": command,
                "state": "queued",
                "event_id": event_id,
                "forwarded": false,
                "delivered": false,
                "network_contacted": false,
            })
        );
    } else {
        println!("{label} locally: event {event_id}");
        println!("Not forwarded or delivered; no network contact was made.");
    }
}

fn read_credential_vector(path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut file = std::fs::File::open(path)?;
    let mut bytes = Vec::with_capacity(lattice_mls::api::MAX_CREDENTIAL_BYTES.min(4096));
    Read::take(
        &mut file,
        (lattice_mls::api::MAX_CREDENTIAL_BYTES + 1) as u64,
    )
    .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > lattice_mls::api::MAX_CREDENTIAL_BYTES {
        return Err(CliError::invalid_input(format!(
            "credential vector must contain 1 to {} bytes",
            lattice_mls::api::MAX_CREDENTIAL_BYTES
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
                    "local_event_storage",
                    "local_space_genesis_creation",
                    "local_space_genesis_listing_and_restoration",
                    "local_space_one_member_recovery",
                    "local_text_message_queue_and_edit",
                    "local_outgoing_message_history",
                    "local_outbox_state_inspection",
                    "local_relay_settings",
                    "relay_nip11_metadata_probe",
                    "local_profile_diagnostics"
                ],
                "unavailable": [
                    "authenticated_space_join_or_leave",
                    "certificate_issuance_or_import",
                    "network_message_forwarding_or_delivery",
                    "peer_synchronization",
                    "voice_media"
                ],
            })
        );
    } else {
        println!("Lattice local-first communication");
        println!(
            "Available: protected device identity, CSR export and local identity pins; local Space Genesis create/list/restore and one-member recovery; text send/edit queued to the local outbox and outgoing history; outbox inspection; local relay URL settings and NIP-11 metadata probing; profile diagnostics."
        );
        println!(
            "Not available: authenticated Space join/leave, certificate issuance/import, peer synchronization, message forwarding/delivery, or voice media."
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
        Cli, Command, IdentityCommand, SpaceCommand, execute, parse_fixed_hex, parse_space_cursor,
        parse_space_edit_input, parse_space_history_input, space_cursor_hex,
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
