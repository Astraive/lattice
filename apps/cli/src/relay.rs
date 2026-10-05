use std::{
    error::Error,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::Subcommand;
use lattice_core::{Client, CoreError, SyncedApplicationOutcome};
use lattice_events::VerifiedSignatureOnlyEvent;
use lattice_mls::api::DeviceCredentialInput;
use lattice_node::relay::{
    RelayOutboxRoundRequest, RelayPublishOutcome, RelayPublishStatus,
    load_or_create_relay_signing_key, publish_outbox_entry_to_two_relays,
    retrieve_mailbox_from_two_relays,
};
use lattice_platform::OsKeyringProtector;
pub(super) use lattice_relay::settings::RelaySettingsError as RelayConfigError;
use lattice_relay::settings::{add_relay, list_relays, remove_relay, validate_relay_url};
use lattice_storage::{MAX_OUTBOX_PAGE_SIZE, Store};
use openmls::credentials::{Credential, CredentialType};
use tokio_util::sync::CancellationToken;

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
    /// After admission, queue the fresh generation mailbox in an MLS-protected control event.
    MailboxPublish {
        /// Random 16-byte Space ID as exactly 32 hexadecimal characters.
        #[arg(long)]
        space_id: String,
        /// 32-byte MLS group reference as exactly 64 hexadecimal characters.
        #[arg(long)]
        group_reference: String,
        /// Path to this device's RFC 9420 TLS-encoded X.509 credential vector.
        #[arg(long)]
        credential: PathBuf,
    },
    /// Publish one selected outbox event to two relays and ingest mailbox results through Core.
    Round {
        /// Random 16-byte Space ID as exactly 32 hexadecimal characters.
        #[arg(long)]
        space_id: String,
        /// 32-byte MLS group reference as exactly 64 hexadecimal characters.
        #[arg(long)]
        group_reference: String,
        /// Optional outbox event ID to publish; omit to retrieve only.
        #[arg(long)]
        event_id: Option<String>,
    },
}

pub(super) fn validate_input_url(value: &str) -> Result<(), RelayConfigError> {
    validate_relay_url(value)
}

pub(super) fn validate_command(command: &RelayCommand) -> Result<(), String> {
    match command {
        RelayCommand::MailboxPublish {
            space_id,
            group_reference,
            ..
        }
        | RelayCommand::Round {
            space_id,
            group_reference,
            ..
        } => {
            super::parse_fixed_hex::<16>(space_id, "Space ID")?;
            super::parse_fixed_hex::<32>(group_reference, "MLS group reference")?;
            if let RelayCommand::Round {
                event_id: Some(event_id),
                ..
            } = command
            {
                super::parse_fixed_hex::<32>(event_id, "outbox event ID")?;
            }
            Ok(())
        }
        RelayCommand::Add { url } | RelayCommand::Remove { url } | RelayCommand::Test { url } => {
            validate_input_url(url).map_err(|error| error.to_string())
        }
        RelayCommand::List => Ok(()),
    }
}

pub(super) fn execute(
    command: RelayCommand,
    data_dir: &Path,
    database_path: &Path,
    protector: &OsKeyringProtector,
    credential_bytes: Option<Vec<u8>>,
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
        RelayCommand::MailboxPublish {
            space_id,
            group_reference,
            ..
        } => publish_mailbox(
            &space_id,
            &group_reference,
            credential_bytes,
            database_path,
            protector,
            json,
        )?,
        RelayCommand::Round {
            space_id,
            group_reference,
            event_id,
        } => relay_round(
            &settings_dir,
            &space_id,
            &group_reference,
            event_id.as_deref(),
            database_path,
            protector,
            json,
        )?,
    }
    Ok(())
}

fn publish_mailbox(
    space_id_text: &str,
    group_reference_text: &str,
    credential_bytes: Option<Vec<u8>>,
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    let space_id = super::parse_fixed_hex::<16>(space_id_text, "Space ID")
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    let group_reference = super::parse_fixed_hex::<32>(group_reference_text, "MLS group reference")
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    let credential_bytes = credential_bytes.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "credential vector was not loaded",
        )
    })?;
    let mut client = crate::profile::open_existing_client(database_path, protector)?;
    let credential = Credential::new(CredentialType::X509, credential_bytes);
    let trust_policy = client.credential_trust_policy().clone();
    let credential = client.with_mls_transaction(|identity, _, _| {
        DeviceCredentialInput::from_x509_credential_with_policy(identity, credential, &trust_policy)
            .map_err(CoreError::Mls)
    })?;
    let created = client.restore_space(&space_id, &group_reference)?;
    let published =
        client.publish_space_relay_mailbox_control(&created, &credential, unix_millis()?)?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "command": "relay_mailbox_publish",
                "space_id": super::hex(&space_id),
                "group_reference": super::hex(&group_reference),
                "control_event_id": super::hex(published.event_id()),
                "control_queued": true,
                "mailbox_token_exposed": false,
                "recipient_delivery_claimed": false,
            })
        );
    } else {
        println!(
            "Queued MLS-protected relay mailbox control event {} for Space generation {} / {}.",
            super::hex(published.event_id()),
            super::hex(&space_id),
            super::hex(&group_reference),
        );
        println!("The mailbox token remains protected locally and was not printed.");
        println!("The command did not publish to a relay or claim recipient delivery.");
    }
    Ok(())
}

fn relay_round(
    settings_dir: &Path,
    space_id_text: &str,
    group_reference_text: &str,
    event_id_text: Option<&str>,
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    let space_id = super::parse_fixed_hex::<16>(space_id_text, "Space ID")
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    let group_reference = super::parse_fixed_hex::<32>(group_reference_text, "MLS group reference")
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    let relays = list_relays(settings_dir)?;
    if relays.len() < 2 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "configure at least two distinct relay URLs before running a relay round",
        )
        .into());
    }
    let relay_urls = [relays[0].as_str(), relays[1].as_str()];
    let mut client = crate::profile::open_existing_client(database_path, protector)?;
    let mut created = client.restore_space(&space_id, &group_reference)?;
    let mailbox = client
        .space_relay_mailbox(&space_id, &group_reference)?
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no local protected relay mailbox exists; invoke `relay mailbox-publish` after admission",
            )
        })?;
    let now_millis = unix_millis()?;
    let now_seconds = now_millis / 1_000;
    let next_attempt_ms = i64::try_from(now_millis).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "current time exceeds the outbox schedule range",
        )
    })?;
    let round = RelayRoundContext {
        relay_urls,
        mailbox,
        space_id: &space_id,
        group_reference: &group_reference,
        now_seconds,
        next_attempt_ms,
    };
    let mut store = Store::open(database_path)?;
    let relay_client = lattice_relay::network::RelayClient::new(RELAY_TEST_TIMEOUT)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let cancellation = CancellationToken::new();

    let services = RelayRoundServices {
        protector,
        relay_client: &relay_client,
        runtime: &runtime,
        cancellation: &cancellation,
    };
    let publication =
        publish_round_event(&mut client, &mut store, &services, &round, event_id_text)?;
    let received = runtime.block_on(retrieve_mailbox_from_two_relays(
        &relay_client,
        round.relay_urls,
        round.mailbox,
        round.now_seconds,
        &cancellation,
    ))?;
    let ingress = ingest_round_messages(
        &mut client,
        &mut created,
        &space_id,
        &group_reference,
        &received,
    )?;
    print_round_result(
        json,
        &round,
        event_id_text,
        publication.as_ref(),
        &received,
        &ingress,
    );
    Ok(())
}

struct RelayRoundServices<'a> {
    protector: &'a OsKeyringProtector,
    relay_client: &'a lattice_relay::network::RelayClient,
    runtime: &'a tokio::runtime::Runtime,
    cancellation: &'a CancellationToken,
}

struct RelayRoundContext<'a> {
    relay_urls: [&'a str; 2],
    mailbox: lattice_relay::profile::MailboxToken,
    space_id: &'a [u8; 16],
    group_reference: &'a [u8; 32],
    now_seconds: u64,
    next_attempt_ms: i64,
}

fn publish_round_event(
    client: &mut Client,
    store: &mut Store,
    services: &RelayRoundServices<'_>,
    round: &RelayRoundContext<'_>,
    event_id_text: Option<&str>,
) -> Result<Option<[RelayPublishStatus; 2]>, Box<dyn Error>> {
    let Some(event_id_text) = event_id_text else {
        return Ok(None);
    };
    let event_id = super::parse_fixed_hex::<32>(event_id_text, "outbox event ID")
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    let event_bytes = find_outbox_event(client, round.space_id, round.group_reference, event_id)?
        .ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "event is not a publishable outbox application event for this Space generation",
        )
    })?;
    let event = VerifiedSignatureOnlyEvent::decode_verify(&event_bytes)?;
    if event.event_id().as_bytes() != &event_id
        || event.space_id() != round.space_id
        || event.mls_group_reference() != round.group_reference
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "outbox event is not bound to the selected Space generation",
        )
        .into());
    }
    let identity_fingerprint = client.identity_info().fingerprint;
    let relay_signing_key =
        load_or_create_relay_signing_key(store, services.protector, &identity_fingerprint)?;
    Ok(Some(services.runtime.block_on(
        publish_outbox_entry_to_two_relays(
            store,
            services.relay_client,
            RelayOutboxRoundRequest {
                event_id,
                relay_urls: round.relay_urls,
                mailbox: round.mailbox,
                relay_signing_key: &relay_signing_key,
                now_seconds: round.now_seconds,
                next_attempt_ms: round.next_attempt_ms,
            },
            services.cancellation,
        ),
    )?))
}

fn ingest_round_messages(
    client: &mut Client,
    created: &mut lattice_core::CreatedSpace,
    space_id: &[u8; 16],
    group_reference: &[u8; 32],
    received: &lattice_node::relay::RelayMailboxRound,
) -> Result<Vec<serde_json::Value>, Box<dyn Error>> {
    let mut ingress = Vec::with_capacity(received.messages.len());
    for retrieved in &received.messages {
        let event = retrieved.message.envelope().event();
        let event_id = *event.event_id().as_bytes();
        if event.space_id() != space_id || event.mls_group_reference() != group_reference {
            ingress.push(serde_json::json!({
                "event_id": super::hex(&event_id),
                "status": "generation_mismatch",
            }));
            continue;
        }
        match client.accept_synced_application_event(
            created,
            retrieved.message.envelope().signed_event_bytes(),
        ) {
            Ok(outcome) => {
                ingress.push(ingress_status(
                    event_id,
                    &outcome,
                    &retrieved.source_relay_url,
                ));
                for retry in client.retry_ready_synced_application_events(created)? {
                    let retry_id = match &retry {
                        SyncedApplicationOutcome::Accepted { event_id }
                        | SyncedApplicationOutcome::Duplicate { event_id }
                        | SyncedApplicationOutcome::Pending { event_id, .. }
                        | SyncedApplicationOutcome::CheckpointExcluded { event_id } => *event_id,
                    };
                    ingress.push(ingress_status(retry_id, &retry, "pending-dependency-retry"));
                }
            }
            Err(error) => ingress.push(serde_json::json!({
                "event_id": super::hex(&event_id),
                "source_relay_url": retrieved.source_relay_url,
                "status": "core_rejected",
                "reason": error.to_string(),
            })),
        }
    }
    Ok(ingress)
}

fn print_round_result(
    json: bool,
    round: &RelayRoundContext<'_>,
    event_id_text: Option<&str>,
    publication: Option<&[RelayPublishStatus; 2]>,
    received: &lattice_node::relay::RelayMailboxRound,
    ingress: &[serde_json::Value],
) {
    let publication = publication
        .map(|statuses| statuses.iter().map(publish_status).collect::<Vec<_>>())
        .unwrap_or_default();
    let relay_statuses = received
        .relays
        .iter()
        .map(|status| {
            serde_json::json!({
                "relay_url": status.relay_url,
                "retrieved": status.retrieved,
                "error": status.error,
            })
        })
        .collect::<Vec<_>>();
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "command": "relay_round",
                "space_id": super::hex(round.space_id),
                "group_reference": super::hex(round.group_reference),
                "publication": publication,
                "retrieval": relay_statuses,
                "ingress": ingress,
                "integrity_conflicts": received.integrity_conflicts,
                "recipient_delivery_claimed": false,
            })
        );
    } else {
        print_round_human(
            round.relay_urls,
            event_id_text,
            &publication,
            received,
            ingress.len(),
        );
    }
}

fn print_round_human(
    relay_urls: [&str; 2],
    event_id_text: Option<&str>,
    publication: &[serde_json::Value],
    received: &lattice_node::relay::RelayMailboxRound,
    ingress_count: usize,
) {
    if publication.is_empty() {
        println!("No outbox event was selected for relay publication.");
    } else {
        for (index, status) in publication.iter().enumerate() {
            println!(
                "{} publication result for outbox event {}: {}",
                relay_urls[index],
                event_id_text.unwrap_or("unknown"),
                status["status"],
            );
        }
    }
    for status in &received.relays {
        match &status.error {
            Some(error) => println!("{} retrieval failed: {error}", status.relay_url),
            None => println!(
                "{} returned {} validated profile event(s).",
                status.relay_url, status.retrieved
            ),
        }
    }
    println!(
        "Core reported {ingress_count} ingress outcome(s); {} ID integrity conflict(s) were excluded.",
        received.integrity_conflicts
    );
    println!("Relay acceptance and local Core ingress are not recipient delivery.");
}

fn find_outbox_event(
    client: &Client,
    space_id: &[u8; 16],
    group_reference: &[u8; 32],
    target_event_id: [u8; 32],
) -> Result<Option<Vec<u8>>, CoreError> {
    let mut cursor = None;
    loop {
        let page = client.outbox_application_event_page(
            space_id,
            group_reference,
            cursor,
            MAX_OUTBOX_PAGE_SIZE,
        )?;
        for event_bytes in page.events() {
            let event = VerifiedSignatureOnlyEvent::decode_verify(event_bytes)?;
            if event.event_id().as_bytes() == &target_event_id {
                return Ok(Some(event_bytes.clone()));
            }
        }
        let Some(next_cursor) = page.next_cursor() else {
            return Ok(None);
        };
        cursor = Some(next_cursor);
    }
}

fn ingress_status(
    event_id: [u8; 32],
    outcome: &SyncedApplicationOutcome,
    source_relay_url: &str,
) -> serde_json::Value {
    let status = match outcome {
        SyncedApplicationOutcome::Accepted { .. } => "accepted",
        SyncedApplicationOutcome::Duplicate { .. } => "duplicate",
        SyncedApplicationOutcome::Pending { .. } => "pending",
        SyncedApplicationOutcome::CheckpointExcluded { .. } => "checkpoint_excluded",
    };
    serde_json::json!({
        "event_id": super::hex(&event_id),
        "source_relay_url": source_relay_url,
        "status": status,
    })
}

fn publish_status(status: &RelayPublishStatus) -> serde_json::Value {
    match &status.outcome {
        RelayPublishOutcome::Accepted { relay_event_id } => serde_json::json!({
            "relay_url": status.relay_url,
            "status": "accepted",
            "relay_event_id": super::hex(relay_event_id),
            "recipient_delivery_claimed": false,
        }),
        RelayPublishOutcome::Failed { reason } => serde_json::json!({
            "relay_url": status.relay_url,
            "status": "failed",
            "reason": reason,
            "recipient_delivery_claimed": false,
        }),
        RelayPublishOutcome::AcceptedButNotRecorded {
            relay_event_id,
            reason,
        } => serde_json::json!({
            "relay_url": status.relay_url,
            "status": "accepted_local_state_not_recorded",
            "relay_event_id": super::hex(relay_event_id),
            "reason": reason,
            "recipient_delivery_claimed": false,
        }),
    }
}

fn unix_millis() -> Result<u64, std::io::Error> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(std::io::Error::other)?
        .as_millis();
    u64::try_from(millis).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "current time exceeds the supported millisecond width",
        )
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_round_validates_generation_and_optional_event_id_widths() {
        let valid = RelayCommand::Round {
            space_id: super::super::hex(&[0x11; 16]),
            group_reference: super::super::hex(&[0x22; 32]),
            event_id: Some(super::super::hex(&[0x33; 32])),
        };
        assert!(validate_command(&valid).is_ok());

        let invalid = RelayCommand::Round {
            space_id: "11".to_owned(),
            group_reference: super::super::hex(&[0x22; 32]),
            event_id: Some("33".to_owned()),
        };
        assert!(validate_command(&invalid).is_err());
    }

    #[test]
    fn relay_status_json_distinguishes_acceptance_from_delivery() {
        let accepted = publish_status(&RelayPublishStatus {
            relay_url: "wss://relay-a.example".to_owned(),
            outcome: RelayPublishOutcome::Accepted {
                relay_event_id: [0x44; 32],
            },
        });
        let failed = publish_status(&RelayPublishStatus {
            relay_url: "wss://relay-b.example".to_owned(),
            outcome: RelayPublishOutcome::Failed {
                reason: "timeout".to_owned(),
            },
        });

        assert_eq!(accepted["status"], "accepted");
        assert_eq!(failed["status"], "failed");
        assert_eq!(accepted["recipient_delivery_claimed"], false);
        assert_eq!(failed["recipient_delivery_claimed"], false);
    }
}
