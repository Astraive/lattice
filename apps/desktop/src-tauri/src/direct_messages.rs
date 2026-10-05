use std::{
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use lattice_core::{
    Client, DirectMessageIngressOutcome, DirectMessagePendingInvitation, LocalDirectMessage,
    MAX_DIRECT_MESSAGE_PACKET_BYTES, MAX_DIRECT_MESSAGE_TEXT_BYTES, MAX_SPACE_CREDENTIAL_BYTES,
    OutboxState,
};
use lattice_node::sync::{
    AuthenticatedDirectMessageExchange, DirectMessageIngressReceipt, DirectMessageIngressState,
    execute_authenticated_direct_message_once, serve_authenticated_direct_message_once,
};
use lattice_platform::{MAX_ENVELOPE_BYTES, OsKeyringProtector};
use lattice_storage::{DirectMessageConversation, DirectMessageOutboxEntry};
use lattice_transport::{TcpPeerAdapter, TcpPeerListener};
use serde::Serialize;
use tokio_util::sync::CancellationToken;

use crate::{encoding, profile};

const DM_PAGE_SIZE: usize = 64;
const DM_SESSION_TIMEOUT: Duration = Duration::from_secs(30);
const DM_RETRY_DELAY_MS: i64 = 30_000;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DesktopDirectMessageConversation {
    group_reference: String,
    peer_identity: String,
    closed: bool,
}

impl From<DirectMessageConversation> for DesktopDirectMessageConversation {
    fn from(conversation: DirectMessageConversation) -> Self {
        Self {
            group_reference: encoding::hex(&conversation.group_reference),
            peer_identity: encoding::hex(&conversation.peer_identity),
            closed: conversation.closed,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DesktopDirectMessageInvitation {
    packet_id: String,
    group_reference: String,
    peer_identity: String,
}

impl From<DirectMessagePendingInvitation> for DesktopDirectMessageInvitation {
    fn from(invitation: DirectMessagePendingInvitation) -> Self {
        Self {
            packet_id: encoding::hex(&invitation.packet_id),
            group_reference: encoding::hex(&invitation.group_reference),
            peer_identity: encoding::hex(&invitation.peer_identity),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DesktopDirectMessageHistoryItem {
    packet_id: String,
    author_identity: String,
    content: String,
}

impl From<LocalDirectMessage> for DesktopDirectMessageHistoryItem {
    fn from(message: LocalDirectMessage) -> Self {
        Self {
            packet_id: encoding::hex(&message.packet_id),
            author_identity: encoding::hex(&message.author_identity),
            content: message.content,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DesktopDirectMessageCreation {
    group_reference: String,
    peer_identity: String,
    invitation_packet_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DesktopDirectMessageDelivery {
    packet_id: String,
    ingress_state: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DesktopDirectMessageExchange {
    state: &'static str,
    peer_fingerprint: String,
    listen_address: String,
    sent_packet_id: Option<String>,
    peer_ingress_state: Option<&'static str>,
    received_packet_id: Option<String>,
    received_ingress_state: Option<&'static str>,
    network_contacted: bool,
}

#[tauri::command]
pub(crate) fn publish_local_direct_message_key_package(
    credential_hex: String,
) -> Result<String, String> {
    let credential = parse_credential(&credential_hex)?;
    let (database_path, protector) = profile::open_profile()?;
    let mut client = profile::open_existing_client(database_path, &protector)
        .map_err(|error| format!("open Desktop profile: {error}"))?;
    let package = client
        .publish_direct_message_key_package(credential, unix_seconds())
        .map_err(|error| format!("publish direct-message KeyPackage: {error}"))?;
    Ok(STANDARD.encode(package))
}

// Tauri decodes command payloads into owned strings.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub(crate) fn create_local_direct_message(
    credential_hex: String,
    peer_fingerprint_hex: String,
    peer_key_package_base64: String,
) -> Result<DesktopDirectMessageCreation, String> {
    let credential = parse_credential(&credential_hex)?;
    let peer_identity = encoding::parse_fixed_hex::<32>(&peer_fingerprint_hex, "peer fingerprint")?;
    let peer_key_package = STANDARD
        .decode(peer_key_package_base64.trim())
        .map_err(|_| "peer KeyPackage is not valid Base64".to_owned())?;
    if peer_key_package.is_empty() || peer_key_package.len() > MAX_DIRECT_MESSAGE_PACKET_BYTES {
        return Err("peer KeyPackage exceeds the direct-message bound".to_owned());
    }
    let (database_path, protector) = profile::open_profile()?;
    let mut client = profile::open_existing_client(database_path, &protector)
        .map_err(|error| format!("open Desktop profile: {error}"))?;
    if client
        .pinned_identity(&peer_identity)
        .map_err(|error| format!("read peer identity pin: {error}"))?
        .is_none()
    {
        return Err("pin the peer's exact identity before creating a conversation".to_owned());
    }
    let created = client
        .create_direct_message_from_x509_credential(
            credential,
            peer_identity,
            &peer_key_package,
            unix_millis(),
        )
        .map_err(|error| format!("create direct-message conversation: {error}"))?;
    Ok(DesktopDirectMessageCreation {
        group_reference: encoding::hex(&created.group_reference),
        peer_identity: encoding::hex(&created.peer_identity),
        invitation_packet_id: encoding::hex(&created.invitation.packet_id),
    })
}

#[tauri::command]
pub(crate) fn list_local_direct_message_conversations()
-> Result<Vec<DesktopDirectMessageConversation>, String> {
    let (database_path, protector) = profile::open_profile()?;
    let client = profile::open_existing_client(database_path, &protector)
        .map_err(|error| format!("open Desktop profile: {error}"))?;
    client
        .direct_message_conversations(256)
        .map(|rows| rows.into_iter().map(Into::into).collect())
        .map_err(|error| format!("list direct-message conversations: {error}"))
}

#[tauri::command]
pub(crate) fn list_pending_local_direct_message_invitations()
-> Result<Vec<DesktopDirectMessageInvitation>, String> {
    let (database_path, protector) = profile::open_profile()?;
    let client = profile::open_existing_client(database_path, &protector)
        .map_err(|error| format!("open Desktop profile: {error}"))?;
    client
        .pending_direct_message_invitations(64)
        .map(|rows| rows.into_iter().map(Into::into).collect())
        .map_err(|error| format!("list pending direct-message invitations: {error}"))
}

// Tauri decodes command payloads into owned strings.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub(crate) fn accept_local_direct_message_invitation(
    credential_hex: String,
    peer_fingerprint_hex: String,
    packet_id_hex: String,
) -> Result<String, String> {
    let credential = parse_credential(&credential_hex)?;
    let peer_identity = encoding::parse_fixed_hex::<32>(&peer_fingerprint_hex, "peer fingerprint")?;
    let packet_id = encoding::parse_fixed_hex::<32>(&packet_id_hex, "invitation packet ID")?;
    let (database_path, protector) = profile::open_profile()?;
    let mut client = profile::open_existing_client(database_path, &protector)
        .map_err(|error| format!("open Desktop profile: {error}"))?;
    client
        .accept_pending_direct_message_invitation_from_x509_credential(
            credential,
            peer_identity,
            packet_id,
            true,
        )
        .map(|group_reference| encoding::hex(&group_reference))
        .map_err(|error| format!("accept direct-message invitation: {error}"))
}

// Tauri decodes command payloads into owned strings.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub(crate) fn decline_local_direct_message_invitation(
    packet_id_hex: String,
) -> Result<bool, String> {
    let packet_id = encoding::parse_fixed_hex::<32>(&packet_id_hex, "invitation packet ID")?;
    let (database_path, protector) = profile::open_profile()?;
    let mut client = profile::open_existing_client(database_path, &protector)
        .map_err(|error| format!("open Desktop profile: {error}"))?;
    client
        .decline_pending_direct_message_invitation(packet_id)
        .map_err(|error| format!("decline direct-message invitation: {error}"))
}

// Tauri decodes command payloads into owned strings.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub(crate) fn list_local_direct_message_history(
    group_reference_hex: String,
) -> Result<Vec<DesktopDirectMessageHistoryItem>, String> {
    let group_reference = encoding::parse_fixed_hex::<32>(&group_reference_hex, "group reference")?;
    let (database_path, protector) = profile::open_profile()?;
    let mut client = profile::open_existing_client(database_path, &protector)
        .map_err(|error| format!("open Desktop profile: {error}"))?;
    client
        .direct_message_history(group_reference, 100)
        .map(|rows| rows.into_iter().map(Into::into).collect())
        .map_err(|error| format!("read direct-message history: {error}"))
}

// Tauri decodes command payloads into owned strings.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub(crate) fn queue_local_direct_message_text(
    credential_hex: String,
    group_reference_hex: String,
    content: String,
) -> Result<DesktopDirectMessageDelivery, String> {
    if content.is_empty() || content.len() > MAX_DIRECT_MESSAGE_TEXT_BYTES {
        return Err("message must contain 1 to 65536 UTF-8 bytes".to_owned());
    }
    let credential = parse_credential(&credential_hex)?;
    let group_reference = encoding::parse_fixed_hex::<32>(&group_reference_hex, "group reference")?;
    let (database_path, protector) = profile::open_profile()?;
    let mut client = profile::open_existing_client(database_path, &protector)
        .map_err(|error| format!("open Desktop profile: {error}"))?;
    let packet = client
        .queue_direct_message_text_from_x509_credential(
            credential,
            group_reference,
            &content,
            unix_millis(),
        )
        .map_err(|error| format!("queue direct message: {error}"))?;
    Ok(DesktopDirectMessageDelivery {
        packet_id: encoding::hex(&packet.packet_id),
        ingress_state: "queued",
    })
}

// Tauri decodes command payloads into owned strings.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub(crate) async fn sync_local_direct_messages_once(
    connect_address: String,
    listen_address: String,
    peer_fingerprint_hex: String,
) -> Result<DesktopDirectMessageExchange, String> {
    let connect = connect_address
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid peer address: {error}"))?;
    let listen = listen_address
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid listen address: {error}"))?;
    let peer_fingerprint =
        encoding::parse_fixed_hex::<32>(&peer_fingerprint_hex, "peer fingerprint")?;
    let (database_path, protector) = profile::open_profile()?;
    tauri::async_runtime::spawn_blocking(move || {
        run_direct_message_exchange(
            connect,
            listen,
            peer_fingerprint,
            &database_path,
            &protector,
        )
    })
    .await
    .map_err(|error| format!("direct-message network worker failed: {error}"))?
}

fn run_direct_message_exchange(
    connect: SocketAddr,
    listen: SocketAddr,
    peer_fingerprint: [u8; 32],
    database_path: &std::path::Path,
    protector: &OsKeyringProtector,
) -> Result<DesktopDirectMessageExchange, String> {
    let mut client = profile::open_existing_client(database_path, protector)
        .map_err(|error| format!("open Desktop profile: {error}"))?;
    let outgoing = due_packet_for_peer(&client, &peer_fingerprint, unix_millis())?;
    let outgoing_id = outgoing.as_ref().map(|packet| packet.packet_id);
    let outgoing_bytes = outgoing.map(|packet| (packet.packet_id, packet.envelope_bytes));
    let now = unix_millis();
    let next_attempt = now.saturating_add(DM_RETRY_DELAY_MS);
    if let Some(packet_id) = outgoing_id {
        client
            .mark_direct_message_attempt(packet_id, next_attempt)
            .map_err(|error| format!("record direct-message attempt: {error}"))?;
    }
    let mut ingress_client = profile::open_existing_client(database_path, protector)
        .map_err(|error| format!("open direct-message ingress profile: {error}"))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("build direct-message transport runtime: {error}"))?;
    let (bound, outbound, inbound) = connect_direct_message_adapters(&runtime, connect, listen)?;
    let local_fingerprint = client.identity_info().fingerprint;
    let is_initiator = local_fingerprint < peer_fingerprint;
    let exchange = runtime
        .block_on(async {
            tokio::time::timeout(
                DM_SESSION_TIMEOUT,
                client.with_pinned_identity(
                    &peer_fingerprint,
                    |identity, pinned_peer| async move {
                        let cancellation = CancellationToken::new();
                        let ingest = |peer: &lattice_identity::PinnedIdentity, bytes: &[u8]| {
                            let outcome = ingress_client
                                .ingest_direct_message_packet(peer.fingerprint(), bytes)
                                .map_err(|error| error.to_string())?;
                            let (packet_id, state) = match outcome {
                                DirectMessageIngressOutcome::Accepted { packet_id, .. } => {
                                    (packet_id, DirectMessageIngressState::Accepted)
                                }
                                DirectMessageIngressOutcome::InvitationPending {
                                    packet_id,
                                    ..
                                } => (packet_id, DirectMessageIngressState::InvitationPending),
                                DirectMessageIngressOutcome::Duplicate { packet_id } => {
                                    (packet_id, DirectMessageIngressState::Duplicate)
                                }
                            };
                            Ok(DirectMessageIngressReceipt { packet_id, state })
                        };
                        let outgoing = outgoing_bytes
                            .as_ref()
                            .map(|(packet_id, bytes)| (*packet_id, bytes.as_slice()));
                        if is_initiator {
                            execute_authenticated_direct_message_once(
                                &outbound,
                                identity,
                                pinned_peer,
                                outgoing,
                                ingest,
                                &cancellation,
                            )
                            .await
                        } else {
                            serve_authenticated_direct_message_once(
                                &inbound,
                                identity,
                                pinned_peer,
                                outgoing,
                                ingest,
                                &cancellation,
                            )
                            .await
                        }
                        .map_err(|error| {
                            format!("authenticated direct-message exchange failed: {error}")
                        })
                    },
                ),
            )
            .await
        })
        .map_err(|_| "authenticated direct-message exchange timed out after 30 seconds".to_owned())?
        .map_err(|error| format!("load pinned Desktop identity: {error}"))?
        .ok_or_else(|| "requested peer fingerprint is not pinned in this profile".to_owned())??;
    if let Some(receipt) = exchange.outgoing {
        if Some(receipt.packet_id) != outgoing_id {
            return Err("peer acknowledgement does not match the queued packet".to_owned());
        }
        client
            .record_direct_message_peer_ingress_accepted(receipt.packet_id)
            .map_err(|error| format!("record direct-message peer ingress: {error}"))?;
    }
    Ok(project_exchange(
        exchange,
        bound,
        outgoing_id,
        peer_fingerprint,
    ))
}

fn connect_direct_message_adapters(
    runtime: &tokio::runtime::Runtime,
    connect: SocketAddr,
    listen: SocketAddr,
) -> Result<(SocketAddr, TcpPeerAdapter, TcpPeerAdapter), String> {
    let listener = runtime
        .block_on(TcpPeerListener::bind(listen, MAX_ENVELOPE_BYTES))
        .map_err(|error| format!("bind direct-message listener: {error:?}"))?;
    let bound = listener
        .local_addr()
        .map_err(|error| format!("read direct-message listener address: {error:?}"))?;
    let (outbound, (inbound, _remote)) = runtime
        .block_on(async {
            tokio::time::timeout(DM_SESSION_TIMEOUT, async {
                tokio::try_join!(
                    TcpPeerAdapter::connect(connect, MAX_ENVELOPE_BYTES),
                    listener.accept()
                )
            })
            .await
        })
        .map_err(|_| "direct-message connect/accept timed out after 30 seconds".to_owned())?
        .map_err(|error| format!("direct-message connect/accept failed: {error:?}"))?;
    Ok((bound, outbound, inbound))
}

fn due_packet_for_peer(
    client: &Client,
    peer_fingerprint: &[u8; 32],
    now_ms: i64,
) -> Result<Option<DirectMessageOutboxEntry>, String> {
    let mut cursor = None;
    loop {
        let page = client
            .direct_message_outbox_page(cursor, DM_PAGE_SIZE)
            .map_err(|error| format!("read direct-message outbox: {error}"))?;
        for packet in &page {
            if packet.next_attempt_ms <= now_ms
                && matches!(
                    packet.state,
                    OutboxState::Queued | OutboxState::Forwarding | OutboxState::Forwarded
                )
                && client
                    .direct_message_is_for_peer(packet.group_reference, *peer_fingerprint)
                    .map_err(|error| format!("check direct-message peer route: {error}"))?
            {
                return Ok(Some(packet.clone()));
            }
        }
        if page.len() < DM_PAGE_SIZE {
            return Ok(None);
        }
        cursor = page.last().map(|packet| packet.packet_id);
    }
}

fn project_exchange(
    exchange: AuthenticatedDirectMessageExchange,
    bound: SocketAddr,
    sent_packet_id: Option<[u8; 32]>,
    peer_fingerprint: [u8; 32],
) -> DesktopDirectMessageExchange {
    DesktopDirectMessageExchange {
        state: "authenticated_direct_message_round_completed",
        peer_fingerprint: encoding::hex(&peer_fingerprint),
        listen_address: bound.to_string(),
        sent_packet_id: sent_packet_id.map(|packet_id| encoding::hex(&packet_id)),
        peer_ingress_state: exchange
            .outgoing
            .map(|receipt| ingress_state_text(receipt.state)),
        received_packet_id: exchange
            .incoming
            .map(|receipt| encoding::hex(&receipt.packet_id)),
        received_ingress_state: exchange
            .incoming
            .map(|receipt| ingress_state_text(receipt.state)),
        network_contacted: true,
    }
}

const fn ingress_state_text(state: DirectMessageIngressState) -> &'static str {
    match state {
        DirectMessageIngressState::Accepted => "accepted",
        DirectMessageIngressState::InvitationPending => "invitation_pending_user_consent",
        DirectMessageIngressState::Duplicate => "duplicate",
    }
}

fn parse_credential(credential_hex: &str) -> Result<Vec<u8>, String> {
    encoding::parse_hex_bytes(
        credential_hex,
        "RFC 9420 X.509 credential vector",
        MAX_SPACE_CREDENTIAL_BYTES,
    )
}

fn unix_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(i64::MAX)
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
