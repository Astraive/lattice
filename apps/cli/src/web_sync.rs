use std::{error::Error, io, net::SocketAddr, path::Path};

use futures_util::{SinkExt, StreamExt};
use lattice_core::{Client, SyncedApplicationOutcome};
use lattice_events::VerifiedSignatureOnlyEvent;
use lattice_identity::DeviceIdentity;
use lattice_platform::OsKeyringProtector;
use lattice_storage::{MAX_EVENT_PAGE_SIZE, Store};
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio_tungstenite::{
    accept_hdr_async_with_config,
    tungstenite::{
        Message,
        handshake::server::{ErrorResponse, Request, Response},
        http::StatusCode,
        protocol::WebSocketConfig,
    },
};
use url::Url;

const MAX_EVENT_FRAME_BYTES: usize = 256 * 1024;
const MAX_SYNC_BYTES: usize = 16 * 1024 * 1024;
const MAX_SCANNED_EVENTS: usize = 16_384;
const MAX_HELLO_BYTES: usize = 2048;
const BRIDGE_PATH: &str = "/lattice-sync";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    protocol: String,
    token: String,
    space_id: String,
    group_reference: String,
}

pub(super) fn run(
    listen: SocketAddr,
    allowed_origin: &str,
    space_id_text: &str,
    group_reference_text: &str,
    database_path: &Path,
    protector: &OsKeyringProtector,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    if !listen.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Web sync may bind only a loopback address",
        )
        .into());
    }
    let origin = validate_origin(allowed_origin)?;
    let space_id = super::parse_fixed_hex::<16>(space_id_text, "space ID")
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let group_reference = super::parse_fixed_hex::<32>(group_reference_text, "group reference")
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let token = super::hex(&DeviceIdentity::generate()?.public_bundle().fingerprint());

    let mut client = Client::open_existing(database_path, protector)?;
    let mut created = client.restore_space(&space_id, &group_reference)?;
    let store = Store::open(database_path)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let listener = runtime.block_on(TcpListener::bind(listen))?;
    let bound = listener.local_addr()?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "command": "sync_web_serve_once",
                "state": "listening",
                "endpoint": format!("ws://{bound}{BRIDGE_PATH}"),
                "allowed_origin": origin,
                "pairing_token": token,
            })
        );
    } else {
        eprintln!("Web loopback bridge: ws://{bound}{BRIDGE_PATH}");
        eprintln!("Allowed Origin: {origin}");
        eprintln!("Pairing token (show once): {token}");
        eprintln!(
            "Only a browser at the exact allowed Origin can connect; stop this command to revoke the token."
        );
    }
    let mut session = BridgeSession {
        origin: &origin,
        token: &token,
        store: &store,
        client: &mut client,
        created: &mut created,
        space_id,
        group_reference,
    };
    let (downloaded, accepted, duplicates, pending, checkpoint_excluded) =
        runtime.block_on(accept_and_sync(&listener, &mut session))?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "command": "sync_web_serve_once",
                "state": "completed",
                "downloaded": downloaded,
                "accepted": accepted,
                "duplicates": duplicates,
                "pending": pending,
                "checkpoint_excluded": checkpoint_excluded,
            })
        );
    } else {
        eprintln!(
            "Web bridge session completed: downloaded {downloaded}, accepted {accepted}, deduplicated {duplicates}, pending {pending}, checkpoint-excluded {checkpoint_excluded}."
        );
    }
    Ok(())
}

struct BridgeSession<'a> {
    origin: &'a str,
    token: &'a str,
    store: &'a Store,
    client: &'a mut Client,
    created: &'a mut lattice_core::CreatedSpace,
    space_id: [u8; 16],
    group_reference: [u8; 32],
}

async fn accept_and_sync(
    listener: &TcpListener,
    session: &mut BridgeSession<'_>,
) -> Result<(usize, usize, usize, usize, usize), Box<dyn Error>> {
    let (stream, remote) = listener.accept().await?;
    if !remote.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Web bridge rejected a non-loopback peer",
        )
        .into());
    }
    let callback = origin_callback(session.origin.to_owned());
    let mut config = WebSocketConfig::default();
    config.max_message_size = Some(MAX_EVENT_FRAME_BYTES);
    config.max_frame_size = Some(MAX_EVENT_FRAME_BYTES);
    let mut socket = accept_hdr_async_with_config(stream, callback, Some(config)).await?;
    let hello = tokio::time::timeout(std::time::Duration::from_secs(15), socket.next())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Web bridge hello timed out"))?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Web bridge closed before hello",
            )
        })??;
    let Message::Text(text) = hello else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Web bridge requires a text hello frame",
        )
        .into());
    };
    if text.len() > MAX_HELLO_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Web bridge hello exceeds its byte limit",
        )
        .into());
    }
    let hello: Hello = serde_json::from_str(text.as_str())?;
    let hello_space = super::parse_fixed_hex::<16>(&hello.space_id, "hello Space ID")
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let hello_group = super::parse_fixed_hex::<32>(&hello.group_reference, "hello group reference")
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if hello.protocol != "lattice-web-loopback-v1"
        || !constant_time_equal(hello.token.as_bytes(), session.token.as_bytes())
        || hello_space != session.space_id
        || hello_group != session.group_reference
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Web bridge pairing or selected Space did not match",
        )
        .into());
    }
    socket
        .send(Message::Text(r#"{"type":"ready"}"#.into()))
        .await?;
    let downloaded = send_local_history(
        &mut socket,
        session.store,
        session.space_id,
        session.group_reference,
    )
    .await?;
    socket
        .send(Message::Text(
            format!(r#"{{"type":"download-complete","events":{downloaded}}}"#).into(),
        ))
        .await?;
    let (accepted, duplicates, pending, checkpoint_excluded) = receive_browser_events(
        &mut socket,
        session.client,
        session.created,
        session.space_id,
        session.group_reference,
    )
    .await?;
    socket
        .send(Message::Text(
            format!(
                r#"{{"type":"complete","accepted":{accepted},"duplicates":{duplicates},"pending":{pending},"checkpoint_excluded":{checkpoint_excluded}}}"#
            )
            .into(),
        ))
        .await?;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), socket.close(None)).await;
    Ok((
        downloaded,
        accepted,
        duplicates,
        pending,
        checkpoint_excluded,
    ))
}

#[allow(clippy::result_large_err)] // Tungstenite requires this concrete handshake error type.
fn origin_callback(
    expected_origin: String,
) -> impl Fn(&Request, Response) -> Result<Response, ErrorResponse> {
    move |request, response| {
        let request_origin = request
            .headers()
            .get("origin")
            .and_then(|value| value.to_str().ok());
        if request.uri().path() != BRIDGE_PATH || request_origin != Some(expected_origin.as_str()) {
            let mut rejected = ErrorResponse::new(Some("Origin or path rejected".to_owned()));
            *rejected.status_mut() = StatusCode::FORBIDDEN;
            return Err(rejected);
        }
        Ok(response)
    }
}

pub(super) fn validate_origin(text: &str) -> Result<String, Box<dyn Error>> {
    let url = Url::parse(text).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "allowed Origin must be an HTTP loopback origin",
        )
    })?;
    let host_is_loopback = url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if url.scheme() != "http"
        || !host_is_loopback
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || url.origin().ascii_serialization() != text
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "allowed Origin must be a canonical HTTP loopback origin without a path",
        )
        .into());
    }
    Ok(text.to_owned())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0),
        );
    }
    difference == 0
}

async fn send_local_history(
    socket: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    store: &Store,
    space_id: [u8; 16],
    group_reference: [u8; 32],
) -> Result<usize, Box<dyn Error>> {
    let mut cursor = None;
    let mut scanned_events = 0usize;
    let mut scanned_bytes = 0usize;
    let mut sent_bytes = 0usize;
    let mut sent_events = 0usize;
    loop {
        let page = store.list_event_page(cursor, MAX_EVENT_PAGE_SIZE)?;
        let Some(last) = page.last() else { break };
        cursor = Some(last.event_id);
        for record in page {
            scanned_events = scanned_events.saturating_add(1);
            scanned_bytes = scanned_bytes.saturating_add(record.canonical_bytes.len());
            if scanned_events > MAX_SCANNED_EVENTS || scanned_bytes > MAX_SYNC_BYTES {
                return Err(io::Error::other("Web bridge history scan exceeded its bound").into());
            }
            let event = VerifiedSignatureOnlyEvent::decode_verify(&record.canonical_bytes)?;
            if event.event_id().as_bytes() != &record.event_id
                || event.author_fingerprint() != &record.author_id
                || event.author_sequence() != record.author_seq
            {
                return Err(
                    io::Error::other("stored event metadata does not match signed bytes").into(),
                );
            }
            if event.space_id() != &space_id || event.mls_group_reference() != &group_reference {
                continue;
            }
            let length = record.canonical_bytes.len();
            if length == 0 || length > MAX_EVENT_FRAME_BYTES {
                return Err(
                    io::Error::other("stored event exceeds the Web bridge frame bound").into(),
                );
            }
            sent_bytes = sent_bytes.saturating_add(length);
            if sent_bytes > MAX_SYNC_BYTES {
                return Err(io::Error::other("Web bridge history transfer exceeded 16 MiB").into());
            }
            socket
                .send(Message::Binary(record.canonical_bytes.into()))
                .await?;
            sent_events += 1;
        }
    }
    Ok(sent_events)
}

async fn receive_browser_events(
    socket: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    client: &mut Client,
    created: &mut lattice_core::CreatedSpace,
    space_id: [u8; 16],
    group_reference: [u8; 32],
) -> Result<(usize, usize, usize, usize), Box<dyn Error>> {
    let mut received_bytes = 0usize;
    let mut accepted = 0;
    let mut duplicates = 0;
    let mut pending = 0;
    let mut checkpoint_excluded = 0;
    loop {
        let message = tokio::time::timeout(std::time::Duration::from_secs(30), socket.next())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Web bridge upload timed out"))?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Web bridge closed during upload",
                )
            })??;
        match message {
            Message::Binary(bytes) => {
                if bytes.is_empty() || bytes.len() > MAX_EVENT_FRAME_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Web bridge event frame is empty or oversized",
                    )
                    .into());
                }
                received_bytes = received_bytes.saturating_add(bytes.len());
                if received_bytes > MAX_SYNC_BYTES {
                    return Err(io::Error::other("Web bridge upload exceeded 16 MiB").into());
                }
                let event = VerifiedSignatureOnlyEvent::decode_verify(&bytes)?;
                if event.space_id() != &space_id || event.mls_group_reference() != &group_reference
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Web bridge event targets a different Space generation",
                    )
                    .into());
                }
                match client.accept_synced_application_event(created, &bytes)? {
                    SyncedApplicationOutcome::Accepted { .. } => accepted += 1,
                    SyncedApplicationOutcome::Duplicate { .. } => duplicates += 1,
                    SyncedApplicationOutcome::Pending { .. } => pending += 1,
                    SyncedApplicationOutcome::CheckpointExcluded { .. } => {
                        checkpoint_excluded += 1;
                    }
                }
            }
            Message::Text(text) if text.as_str() == r#"{"type":"upload-complete"}"# => break,
            Message::Ping(payload) => socket.send(Message::Pong(payload)).await?,
            Message::Close(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Web bridge closed during upload",
                )
                .into());
            }
            Message::Text(_) | Message::Pong(_) | Message::Frame(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected Web bridge control frame",
                )
                .into());
            }
        }
    }
    Ok((accepted, duplicates, pending, checkpoint_excluded))
}

#[cfg(test)]
mod tests {
    use super::{constant_time_equal, validate_origin};

    #[test]
    fn loopback_origin_is_exact_and_rejects_remote_or_noncanonical_origins() {
        assert_eq!(
            validate_origin("http://127.0.0.1:1430").expect("loopback origin"),
            "http://127.0.0.1:1430"
        );
        assert!(validate_origin("http://localhost").is_ok());
        assert!(validate_origin("https://localhost").is_err());
        assert!(validate_origin("https://example.org").is_err());
        assert!(validate_origin("http://127.0.0.1:1430/path").is_err());
        assert!(validate_origin("http://127.0.0.1:1430/").is_err());
    }

    #[test]
    fn pairing_token_comparison_requires_exact_bytes() {
        assert!(constant_time_equal(b"ab12", b"ab12"));
        assert!(!constant_time_equal(b"ab12", b"ab13"));
        assert!(!constant_time_equal(b"ab12", b"ab1"));
    }
}
