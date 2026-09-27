use lattice_core::{
    Client, CoreError, CreatedSpace, InitialChannel, LocalTextMessageRecord,
    MAX_SPACE_CREDENTIAL_BYTES, MAX_SPACE_WELCOME_BOOTSTRAP_BYTES, OutboxState,
    space::{Channel, ChannelType},
};
use serde::Serialize;

use super::{encoding, profile};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalChannelSummary {
    id: String,
    channel_type: &'static str,
    name: String,
    archived: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalSpaceSummary {
    space_id: String,
    group_reference: String,
    channels: Vec<LocalChannelSummary>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LocalSpacePage {
    spaces: Vec<LocalSpaceSummary>,
    next_cursor: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LocalSpaceCreation {
    state: &'static str,
    space_id: String,
    group_reference: String,
    genesis_event_id: String,
    creator_fingerprint: String,
    channels: Vec<LocalChannelSummary>,
    local_snapshot_persisted: bool,
    membership_claimed: bool,
    network_contacted: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LocalSpaceRecovery {
    state: &'static str,
    space_id: String,
    prior_group_reference: String,
    group_reference: String,
    genesis_event_id: String,
    channels: Vec<LocalChannelSummary>,
    prior_members_rejoined: bool,
    network_contacted: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct QueuedLocalMessage {
    state: &'static str,
    event_id: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LocalTextMessageSummary {
    event_id: String,
    author_id: String,
    author_sequence: u64,
    lamport: u64,
    content: String,
    outbox_state: Option<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LocalTextMessageSearch {
    messages: Vec<LocalTextMessageSummary>,
    total_matches: usize,
    scanned_messages: usize,
}

fn project_local_text_message(message: LocalTextMessageRecord) -> LocalTextMessageSummary {
    LocalTextMessageSummary {
        event_id: encoding::hex(&message.event_id),
        author_id: encoding::hex(&message.author_id),
        author_sequence: message.author_sequence,
        lamport: message.lamport,
        content: message.content,
        outbox_state: message.outbox_state.map(|state| match state {
            OutboxState::Queued => "queued",
            OutboxState::Forwarded => "forwarded",
            OutboxState::Delivered => "delivered",
            OutboxState::Failed => "failed",
        }),
    }
}

fn project_channel(channel: &Channel) -> LocalChannelSummary {
    LocalChannelSummary {
        id: encoding::hex(&channel.id),
        channel_type: match channel.channel_type {
            ChannelType::Text => "text",
            ChannelType::Announcement => "announcement",
            ChannelType::Voice => "voice",
        },
        name: channel.name.clone(),
        archived: channel.archived,
    }
}

fn project_channels(space: &CreatedSpace) -> Result<Vec<LocalChannelSummary>, String> {
    let policy = space
        .reducer()
        .policy()
        .ok_or_else(|| "local Space policy is unavailable".to_owned())?;
    Ok(policy.channels.iter().map(project_channel).collect())
}

// Tauri decodes command arguments into owned strings.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub(crate) fn create_local_space(
    credential_vector_hex: String,
    channel_names: Vec<String>,
) -> Result<LocalSpaceCreation, String> {
    if channel_names.is_empty()
        || channel_names.len() > lattice_core::space::MAX_INITIAL_CHANNELS
        || channel_names
            .iter()
            .any(|name| name.is_empty() || name.len() > 128 || name.contains('\0'))
    {
        return Err("provide 1 to 64 channel names, each 1 to 128 bytes".to_owned());
    }
    let credential_vector = encoding::parse_hex_bytes(
        &credential_vector_hex,
        "RFC 9420 X.509 credential vector",
        MAX_SPACE_CREDENTIAL_BYTES,
    )?;
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
    let (database_path, protector) = profile::open_profile()?;
    let mut client =
        Client::open_existing(database_path, &protector).map_err(|error| error.to_string())?;
    let created = client
        .create_space_from_x509_credential(credential_vector, channels)
        .map_err(|error| error.to_string())?;
    let identity = client.identity_info();
    Ok(LocalSpaceCreation {
        state: "local_genesis_created",
        space_id: encoding::hex(created.space_id()),
        group_reference: encoding::hex(created.group_reference()),
        genesis_event_id: encoding::hex(created.genesis_event().event_id().as_bytes()),
        creator_fingerprint: encoding::hex(&identity.fingerprint),
        channels: project_channels(&created)?,
        local_snapshot_persisted: true,
        membership_claimed: false,
        network_contacted: false,
    })
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LocalSpaceImport {
    state: &'static str,
    space_id: String,
    group_reference: String,
    channels: Vec<LocalChannelSummary>,
    local_checkpoint_imported: bool,
    network_contacted: bool,
}

// Tauri decodes command arguments into owned strings.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub(crate) fn import_local_space_welcome_bootstrap(
    package_hex: String,
    expected_inviter_fingerprint_hex: String,
    credential_vector_hex: String,
) -> Result<LocalSpaceImport, String> {
    if package_hex.is_empty() || package_hex.len() > MAX_SPACE_WELCOME_BOOTSTRAP_BYTES * 2 {
        return Err(
            "invalid Welcome bootstrap package: hex input must encode 1 byte to 1 MiB".to_owned(),
        );
    }
    if credential_vector_hex.is_empty()
        || credential_vector_hex.len() > MAX_SPACE_CREDENTIAL_BYTES * 2
    {
        return Err("invalid X.509 credential: hex input must encode 1 byte to 16 KiB".to_owned());
    }
    let package = encoding::parse_hex_bytes(
        &package_hex,
        "Welcome bootstrap package",
        MAX_SPACE_WELCOME_BOOTSTRAP_BYTES,
    )
    .map_err(|error| format!("invalid Welcome bootstrap package: {error}"))?;
    let credential = encoding::parse_hex_bytes(
        &credential_vector_hex,
        "RFC 9420 X.509 credential vector",
        MAX_SPACE_CREDENTIAL_BYTES,
    )
    .map_err(|error| format!("invalid X.509 credential: {error}"))?;
    let expected_inviter = encoding::parse_fixed_hex::<32>(
        &expected_inviter_fingerprint_hex,
        "expected inviter fingerprint",
    )?;
    let (database_path, protector) = profile::open_profile()?;
    let mut client =
        Client::open_existing(database_path, &protector).map_err(|error| error.to_string())?;
    let imported = client
        .join_space_from_welcome_bootstrap_from_x509_credential(
            &package,
            expected_inviter,
            credential,
        )
        .map_err(|error| match error {
            CoreError::SpaceWelcomeBootstrapInvalid => {
                "invalid Welcome bootstrap package".to_owned()
            }
            CoreError::SpaceCredentialInvalid => "invalid X.509 credential".to_owned(),
            CoreError::SpaceWelcomeBootstrapUntrustedInviter => {
                "expected inviter fingerprint is not pinned or does not match the package"
                    .to_owned()
            }
            other => other.to_string(),
        })?;
    Ok(LocalSpaceImport {
        state: "local_welcome_checkpoint_imported",
        space_id: encoding::hex(imported.space_id()),
        group_reference: encoding::hex(imported.group_reference()),
        channels: project_channels(&imported)?,
        local_checkpoint_imported: true,
        network_contacted: false,
    })
}

// Tauri decodes command arguments into owned strings.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub(crate) fn queue_local_text_message(
    space_id_hex: String,
    group_reference_hex: String,
    credential_vector_hex: String,
    channel_id_hex: String,
    content: String,
) -> Result<QueuedLocalMessage, String> {
    if content.len() > lattice_core::space::MAX_SPACE_PAYLOAD_BYTES {
        return Err("message exceeds the local payload limit".to_owned());
    }
    let space_id = encoding::parse_fixed_hex::<16>(&space_id_hex, "Space ID")?;
    let group_reference =
        encoding::parse_fixed_hex::<32>(&group_reference_hex, "MLS group reference")?;
    let channel_id = encoding::parse_fixed_hex::<16>(&channel_id_hex, "channel ID")?;
    let credential_vector = encoding::parse_hex_bytes(
        &credential_vector_hex,
        "RFC 9420 X.509 credential vector",
        MAX_SPACE_CREDENTIAL_BYTES,
    )?;
    let (database_path, protector) = profile::open_profile()?;
    let mut client =
        Client::open_existing(database_path, &protector).map_err(|error| error.to_string())?;
    let queued = client
        .queue_text_message_from_x509_credential(
            &space_id,
            &group_reference,
            credential_vector,
            channel_id,
            &content,
        )
        .map_err(|error| match error {
            CoreError::SpaceCredentialInvalid => {
                "the X.509 credential is invalid or not trusted".to_owned()
            }
            CoreError::SpaceMessageRejected(_) => {
                "local Space policy rejected this message".to_owned()
            }
            CoreError::SpaceGenesisRejected(_) | CoreError::SpaceGenesisSnapshotNotFound => {
                "local Space generation is unavailable or has changed".to_owned()
            }
            _ => "message could not be committed to the local outbox".to_owned(),
        })?;
    Ok(QueuedLocalMessage {
        state: "queued",
        event_id: encoding::hex(queued.event_id()),
    })
}

// Tauri decodes command arguments into owned strings.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub(crate) fn queue_local_text_message_edit(
    space_id_hex: String,
    group_reference_hex: String,
    credential_vector_hex: String,
    channel_id_hex: String,
    target_message_id_hex: String,
    content: String,
) -> Result<QueuedLocalMessage, String> {
    if content.len() > lattice_core::space::MAX_SPACE_PAYLOAD_BYTES {
        return Err("edit exceeds the local payload limit".to_owned());
    }
    let space_id = encoding::parse_fixed_hex::<16>(&space_id_hex, "Space ID")?;
    let group_reference =
        encoding::parse_fixed_hex::<32>(&group_reference_hex, "MLS group reference")?;
    let channel_id = encoding::parse_fixed_hex::<16>(&channel_id_hex, "channel ID")?;
    let target = encoding::parse_fixed_hex::<32>(&target_message_id_hex, "message ID")?;
    let credential_vector = encoding::parse_hex_bytes(
        &credential_vector_hex,
        "RFC 9420 X.509 credential vector",
        MAX_SPACE_CREDENTIAL_BYTES,
    )?;
    let (database_path, protector) = profile::open_profile()?;
    let mut client =
        Client::open_existing(database_path, &protector).map_err(|error| error.to_string())?;
    let queued = client
        .queue_text_message_edit_from_x509_credential(
            &space_id,
            &group_reference,
            credential_vector,
            channel_id,
            target,
            &content,
        )
        .map_err(|error| match error {
            CoreError::SpaceCredentialInvalid => {
                "the X.509 credential is invalid or not trusted".to_owned()
            }
            CoreError::SpaceMessageRejected(_) => {
                "local Space policy rejected this edit".to_owned()
            }
            CoreError::SpaceGenesisRejected(_) | CoreError::SpaceGenesisSnapshotNotFound => {
                "local Space generation is unavailable or has changed".to_owned()
            }
            _ => "edit could not be committed to the local outbox".to_owned(),
        })?;
    Ok(QueuedLocalMessage {
        state: "queued",
        event_id: encoding::hex(queued.event_id()),
    })
}

// Tauri decodes command arguments into owned strings.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub(crate) fn list_local_text_messages(
    space_id_hex: String,
    group_reference_hex: String,
    channel_id_hex: String,
) -> Result<Vec<LocalTextMessageSummary>, String> {
    let space_id = encoding::parse_fixed_hex::<16>(&space_id_hex, "Space ID")?;
    let group_reference =
        encoding::parse_fixed_hex::<32>(&group_reference_hex, "MLS group reference")?;
    let channel_id = encoding::parse_fixed_hex::<16>(&channel_id_hex, "channel ID")?;
    let (database_path, protector) = profile::open_profile()?;
    let mut client =
        Client::open_existing(database_path, &protector).map_err(|error| error.to_string())?;
    let history = client
        .local_text_message_history(&space_id, &group_reference, &channel_id)
        .map_err(|_| "local message history is unavailable or failed authentication".to_owned())?;
    Ok(history
        .into_iter()
        .map(project_local_text_message)
        .collect())
}

// Tauri decodes command arguments into owned strings.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub(crate) fn search_local_text_messages(
    space_id_hex: String,
    group_reference_hex: String,
    channel_id_hex: String,
    query: String,
) -> Result<LocalTextMessageSearch, String> {
    let space_id = encoding::parse_fixed_hex::<16>(&space_id_hex, "Space ID")?;
    let group_reference =
        encoding::parse_fixed_hex::<32>(&group_reference_hex, "MLS group reference")?;
    let channel_id = encoding::parse_fixed_hex::<16>(&channel_id_hex, "channel ID")?;
    let (database_path, protector) = profile::open_profile()?;
    let mut client =
        Client::open_existing(database_path, &protector).map_err(|error| error.to_string())?;
    let result = client
        .search_local_text_messages(&space_id, &group_reference, &channel_id, &query)
        .map_err(|_| "local message search is unavailable or the query is invalid".to_owned())?;
    Ok(LocalTextMessageSearch {
        messages: result
            .messages
            .into_iter()
            .map(project_local_text_message)
            .collect(),
        total_matches: result.total_matches,
        scanned_messages: result.scanned_messages,
    })
}

// Tauri decodes command arguments into owned strings.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub(crate) fn list_local_spaces(after: Option<String>) -> Result<LocalSpacePage, String> {
    let after = after
        .as_deref()
        .map(encoding::parse_space_cursor)
        .transpose()?;
    let (database_path, protector) = profile::open_profile()?;
    let mut client =
        Client::open_existing(database_path, &protector).map_err(|error| error.to_string())?;
    let page = client
        .restore_space_page(after)
        .map_err(|error| error.to_string())?;
    let spaces = page
        .spaces()
        .iter()
        .map(|space| {
            Ok(LocalSpaceSummary {
                space_id: encoding::hex(space.space_id()),
                group_reference: encoding::hex(space.group_reference()),
                channels: project_channels(space)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(LocalSpacePage {
        spaces,
        next_cursor: page.next_cursor().map(encoding::space_cursor_hex),
    })
}

// Tauri decodes command arguments into owned strings.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub(crate) fn recover_local_space_generation(
    space_id_hex: String,
    group_reference_hex: String,
    credential_vector_hex: String,
) -> Result<LocalSpaceRecovery, String> {
    let space_id = encoding::parse_fixed_hex::<16>(&space_id_hex, "Space ID")?;
    let prior_group_reference =
        encoding::parse_fixed_hex::<32>(&group_reference_hex, "MLS group reference")?;
    let credential = encoding::parse_hex_bytes(
        &credential_vector_hex,
        "X.509 credential vector",
        MAX_SPACE_CREDENTIAL_BYTES,
    )?;
    let (database_path, protector) = profile::open_profile()?;
    let mut client =
        Client::open_existing(database_path, &protector).map_err(|error| error.to_string())?;
    let space = client
        .recover_space_generation_from_x509_credential(
            &space_id,
            &prior_group_reference,
            credential,
        )
        .map_err(|error| error.to_string())?;
    Ok(LocalSpaceRecovery {
        state: "one_member_recovery_generation_created",
        space_id: encoding::hex(space.space_id()),
        prior_group_reference: encoding::hex(&prior_group_reference),
        group_reference: encoding::hex(space.group_reference()),
        genesis_event_id: encoding::hex(space.genesis_event().event_id().as_bytes()),
        channels: project_channels(&space)?,
        prior_members_rejoined: false,
        network_contacted: false,
    })
}
