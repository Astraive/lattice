//! Bounded asynchronous NIP-01/NIP-11 networking for the candidate mailbox profile.
//!
//! This client accepts only secure `wss://` relay URLs, fetches NIP-11 over the
//! corresponding `https://` URL, and validates every inbound profile event
//! through [`RelayProfileMessage::decode`]. Relay acceptance is not recipient
//! delivery, and this module stores no relay cursor or profile state.

use core::fmt;
use futures_util::{SinkExt, StreamExt};
use reqwest::header::{ACCEPT, HeaderValue};
use reqwest::redirect::Policy;
use reqwest::{Client as HttpClient, Url};
use serde::Serialize;
use serde_json::value::RawValue;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_tungstenite::tungstenite::protocol::{Message, WebSocketConfig};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async_with_config};
use tokio_util::sync::CancellationToken;

use crate::nip11::{Nip11Error, RelayCapabilities, parse_nip11};
use crate::profile::{
    MailboxToken, RelayProfileError, RelayProfileMessage, require_compatible_relay,
};

/// Maximum serialized NIP-01 command size, including its JSON array wrapper.
pub const MAX_RELAY_COMMAND_BYTES: usize = 66_048;
/// Maximum WebSocket message size accepted from a relay.
pub const MAX_RELAY_FRAME_BYTES: usize = 66_048;
/// Maximum aggregate WebSocket response bytes accepted for one operation.
pub const MAX_RELAY_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum number of validated messages returned by one retrieval.
pub const MAX_RETRIEVED_EVENTS: usize = 256;
/// Maximum age represented by a retrieval filter, in seconds.
pub const MAX_RETRIEVAL_AGE_SECONDS: u64 = 30 * 24 * 60 * 60;
/// Largest operation timeout accepted by [`RelayClient::new`].
pub const MAX_OPERATION_TIMEOUT: Duration = Duration::from_mins(5);

const MIN_OPERATION_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_WS_CLOSE_GRACE: Duration = Duration::from_millis(250);
static NEXT_SUBSCRIPTION_ID: AtomicU64 = AtomicU64::new(1);

type RelaySocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Failures from bounded NIP-11, publish, and mailbox retrieval operations.
#[derive(Debug)]
pub enum RelayNetworkError {
    /// The operation timeout is outside the supported finite range.
    InvalidTimeout,
    /// The relay URL is malformed or contains credentials or a fragment.
    InvalidRelayUrl,
    /// The relay URL must use `wss://`; insecure `ws://` is not accepted.
    InsecureRelayUrl,
    /// The HTTP client could not be configured or failed to exchange data.
    HttpTransport,
    /// The NIP-11 endpoint did not return a successful HTTP status.
    HttpStatus(u16),
    /// The NIP-11 response body exceeded its strict byte limit.
    Nip11BodyTooLarge,
    /// NIP-11 parsing failed, including malformed or duplicate-key JSON.
    Nip11(Nip11Error),
    /// The relay did not advertise all capabilities required for publishing.
    IncompatibleRelay(RelayProfileError),
    /// The WebSocket handshake or connection failed.
    WebSocketTransport,
    /// A relay closed a subscription before sending EOSE.
    SubscriptionClosed,
    /// A command or response was invalid or exceeded a protocol bound.
    InvalidResponse,
    /// One WebSocket message exceeded the configured byte limit.
    FrameTooLarge,
    /// Aggregate WebSocket response bytes exceeded the operation limit.
    ResponseTooLarge,
    /// The serialized command exceeded [`MAX_RELAY_COMMAND_BYTES`].
    CommandTooLarge,
    /// The relay returned a negative `OK` for the published event.
    RelayRejected(String),
    /// The operation's strict deadline elapsed.
    Timeout,
    /// The supplied cancellation token was cancelled.
    Cancelled,
}

impl fmt::Display for RelayNetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTimeout => {
                write!(f, "relay operation timeout is outside the supported range")
            }
            Self::InvalidRelayUrl => write!(f, "invalid secure relay URL"),
            Self::InsecureRelayUrl => write!(f, "relay URL must use wss://"),
            Self::HttpTransport => write!(f, "relay information HTTP request failed"),
            Self::HttpStatus(status) => {
                write!(f, "relay information endpoint returned HTTP {status}")
            }
            Self::Nip11BodyTooLarge => write!(f, "relay information body exceeds the NIP-11 limit"),
            Self::Nip11(error) => write!(f, "invalid relay information: {error}"),
            Self::IncompatibleRelay(error) => write!(f, "incompatible relay: {error}"),
            Self::WebSocketTransport => write!(f, "relay WebSocket operation failed"),
            Self::SubscriptionClosed => write!(f, "relay closed the subscription before EOSE"),
            Self::InvalidResponse => write!(f, "relay returned an invalid protocol response"),
            Self::FrameTooLarge => write!(f, "relay WebSocket message exceeds its byte limit"),
            Self::ResponseTooLarge => write!(f, "relay response exceeds the aggregate byte limit"),
            Self::CommandTooLarge => write!(f, "relay command exceeds its byte limit"),
            Self::RelayRejected(reason) => write!(f, "relay rejected the event: {reason}"),
            Self::Timeout => write!(f, "relay operation timed out"),
            Self::Cancelled => write!(f, "relay operation was cancelled"),
        }
    }
}

impl std::error::Error for RelayNetworkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Nip11(error) => Some(error),
            Self::IncompatibleRelay(error) => Some(error),
            _ => None,
        }
    }
}

/// Evidence that a relay accepted a specific event with a valid NIP-01 `OK`.
///
/// This is only relay acceptance. It does not indicate that any recipient
/// received, decrypted, or acknowledged the event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayAcceptance {
    event_id: [u8; 32],
}

impl RelayAcceptance {
    /// Returns the event identifier accepted by the relay.
    #[must_use]
    pub const fn event_id(&self) -> &[u8; 32] {
        &self.event_id
    }
}

/// Asynchronous client for one-shot operations against optional Nostr relays.
///
/// Every network operation is bounded by the configured timeout. URLs must be
/// `wss://`; NIP-11 is fetched from the same URL converted to `https://`, with
/// redirects disabled. The client retains no relay cursor or profile state.
pub struct RelayClient {
    http: HttpClient,
    timeout: Duration,
}

impl RelayClient {
    /// Creates a relay client with one strict timeout shared by each operation.
    ///
    /// The timeout must be between 100 ms and [`MAX_OPERATION_TIMEOUT`]. The
    /// lower bound leaves time for a bounded WebSocket close handshake when a
    /// subscription is cancelled or times out.
    ///
    /// # Errors
    ///
    /// Returns [`RelayNetworkError::InvalidTimeout`] when the timeout is out
    /// of range, or [`RelayNetworkError::HttpTransport`] if the HTTP client
    /// cannot be configured.
    pub fn new(timeout: Duration) -> Result<Self, RelayNetworkError> {
        if !(MIN_OPERATION_TIMEOUT..=MAX_OPERATION_TIMEOUT).contains(&timeout) {
            return Err(RelayNetworkError::InvalidTimeout);
        }
        let http = HttpClient::builder()
            .timeout(timeout)
            .redirect(Policy::none())
            .build()
            .map_err(|_| RelayNetworkError::HttpTransport)?;
        Ok(Self { http, timeout })
    }

    /// Fetches and parses a bounded NIP-11 document over HTTPS.
    ///
    /// The input must be a credential-free `wss://` URL. Its scheme is changed
    /// to `https://`, redirects are disabled, the `Accept` header is set to
    /// `application/nostr+json`, and the complete response is limited to
    /// [`crate::nip11::MAX_NIP11_BYTES`]. This method reports parsed metadata
    /// only; every publishing operation separately enforces compatibility.
    ///
    /// # Errors
    ///
    /// Returns a typed error for an invalid/insecure URL, HTTP failure,
    /// oversized or malformed NIP-11 body, or timeout. Dropping this future
    /// cancels the in-flight HTTP request.
    pub async fn relay_capabilities(
        &self,
        relay_url: &str,
    ) -> Result<RelayCapabilities, RelayNetworkError> {
        timeout(self.timeout, self.fetch_nip11(relay_url))
            .await
            .map_err(|_| RelayNetworkError::Timeout)?
    }

    /// Publishes one validated profile event and reports only relay acceptance.
    ///
    /// Before connecting for publish, this fetches NIP-11 over HTTPS and calls
    /// [`require_compatible_relay`]. The command and each response frame are
    /// bounded. A valid positive `OK` for the exact event ID is required; a
    /// mismatched ID or unrelated response can never be reported as accepted.
    /// The cancellation token is observed during HTTP, WebSocket connect, send,
    /// and response waiting. Dropping the future instead of cancelling the
    /// token aborts the in-flight socket at the transport layer.
    ///
    /// # Errors
    ///
    /// Returns a typed error for incompatibility, invalid input URL, HTTP or
    /// WebSocket failure, oversized data, rejection, timeout, or cancellation.
    pub async fn publish(
        &self,
        relay_url: &str,
        message: &RelayProfileMessage,
        cancellation: &CancellationToken,
    ) -> Result<RelayAcceptance, RelayNetworkError> {
        let deadline = Instant::now() + self.timeout;
        if cancellation.is_cancelled() {
            return Err(RelayNetworkError::Cancelled);
        }
        let capabilities = tokio::select! {
            () = cancellation.cancelled() => return Err(RelayNetworkError::Cancelled),
            result = timeout_at(deadline, self.fetch_nip11(relay_url)) => {
                result.map_err(|_| RelayNetworkError::Timeout)??
            }
        };
        require_compatible_relay(&capabilities).map_err(RelayNetworkError::IncompatibleRelay)?;

        let event_id = *message.event().id();
        let event_id_hex = lower_hex(&event_id);
        let command = event_command(message)?;
        let mut socket = connect_until(relay_url, deadline, cancellation).await?;
        let command_text =
            String::from_utf8(command).map_err(|_| RelayNetworkError::InvalidResponse)?;
        if let Err(error) = send_until(
            &mut socket,
            Message::text(command_text),
            deadline,
            cancellation,
        )
        .await
        {
            let _ = close_socket_until(&mut socket, deadline).await;
            return Err(error);
        }

        let mut response_bytes = 0_usize;
        loop {
            let incoming = match next_until(&mut socket, deadline, cancellation).await {
                Ok(Some(message)) => message,
                Ok(None) => {
                    let _ = close_socket_until(&mut socket, deadline).await;
                    return Err(RelayNetworkError::WebSocketTransport);
                }
                Err(error) => {
                    let _ = close_socket_until(&mut socket, deadline).await;
                    return Err(error);
                }
            };
            if incoming.len() > MAX_RELAY_FRAME_BYTES {
                let _ = close_socket_until(&mut socket, deadline).await;
                return Err(RelayNetworkError::FrameTooLarge);
            }
            let Some(total) = response_bytes
                .checked_add(incoming.len())
                .filter(|total| *total <= MAX_RELAY_RESPONSE_BYTES)
            else {
                let _ = close_socket_until(&mut socket, deadline).await;
                return Err(RelayNetworkError::ResponseTooLarge);
            };
            response_bytes = total;

            match &incoming {
                Message::Text(_) => {
                    let response = incoming
                        .to_text()
                        .map_err(|_| RelayNetworkError::InvalidResponse)?;
                    match parse_ok_response(response.as_bytes(), &event_id_hex)? {
                        Some(OkResponse::Accepted) => {
                            let _ = close_socket_until(&mut socket, deadline).await;
                            return Ok(RelayAcceptance { event_id });
                        }
                        Some(OkResponse::Rejected(reason)) => {
                            let _ = close_socket_until(&mut socket, deadline).await;
                            return Err(RelayNetworkError::RelayRejected(reason));
                        }
                        None => {}
                    }
                }
                Message::Close(_) => return Err(RelayNetworkError::WebSocketTransport),
                Message::Binary(_) | Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
            }
        }
    }

    /// Retrieves validated profile messages from the exact private mailbox.
    ///
    /// Sends one bounded `REQ` with `kinds: [39001]`, the exact `#t` mailbox
    /// tag, `since = now - 30 days` (saturating at zero), and `limit: 256`.
    /// Each response frame is capped at [`MAX_RELAY_FRAME_BYTES`], aggregate
    /// response bytes at [`MAX_RELAY_RESPONSE_BYTES`], and results at
    /// [`MAX_RETRIEVED_EVENTS`]. Raw event JSON is passed unchanged to the full
    /// cross-layer profile decoder, so duplicate JSON keys are not normalized
    /// away. Invalid, expired, or unrelated events are discarded.
    /// `now` is the caller's current Unix-seconds reading and is used for both
    /// the retrieval lower bound and local envelope-expiry validation.
    ///
    /// A cancellation token sends NIP-01 `CLOSE` and a WebSocket close frame
    /// before returning when possible. EOSE closes the subscription cleanly;
    /// timeout reserves a bounded close window. Dropping the future directly
    /// aborts the socket at the transport layer, so signal and await the token
    /// when a clean protocol-level cancellation is required.
    ///
    /// # Errors
    ///
    /// Returns typed errors for invalid/insecure URLs, WebSocket or
    /// subscription-close failure, oversized data, cancellation, or timeout.
    /// Malformed, expired, and unrelated events are discarded.
    pub async fn retrieve(
        &self,
        relay_url: &str,
        mailbox: MailboxToken,
        now: u64,
        cancellation: &CancellationToken,
    ) -> Result<Vec<RelayProfileMessage>, RelayNetworkError> {
        if cancellation.is_cancelled() {
            return Err(RelayNetworkError::Cancelled);
        }
        let deadline = Instant::now() + self.timeout;
        let close_grace = (self.timeout / 5).min(MAX_WS_CLOSE_GRACE);
        let read_deadline = deadline - close_grace;
        let subscription_id = next_subscription_id();
        let since = now.saturating_sub(MAX_RETRIEVAL_AGE_SECONDS);
        let command = request_command(&subscription_id, mailbox, since)?;
        let command_text =
            String::from_utf8(command).map_err(|_| RelayNetworkError::InvalidResponse)?;
        let mut socket = connect_until(relay_url, read_deadline, cancellation).await?;

        if let Err(error) = send_until(
            &mut socket,
            Message::text(command_text),
            read_deadline,
            cancellation,
        )
        .await
        {
            let _ = close_subscription_until(&mut socket, &subscription_id, deadline).await;
            return Err(error);
        }

        let mut response_bytes = 0_usize;
        let mut events_seen = 0_usize;
        let mut messages = Vec::with_capacity(MAX_RETRIEVED_EVENTS.min(16));
        loop {
            let incoming = match next_until(&mut socket, read_deadline, cancellation).await {
                Ok(Some(message)) => message,
                Ok(None) => {
                    let _ = close_subscription_until(&mut socket, &subscription_id, deadline).await;
                    return Err(RelayNetworkError::WebSocketTransport);
                }
                Err(error) => {
                    let _ = close_subscription_until(&mut socket, &subscription_id, deadline).await;
                    return Err(error);
                }
            };
            if incoming.len() > MAX_RELAY_FRAME_BYTES {
                let _ = close_subscription_until(&mut socket, &subscription_id, deadline).await;
                return Err(RelayNetworkError::FrameTooLarge);
            }
            let Some(total) = response_bytes
                .checked_add(incoming.len())
                .filter(|total| *total <= MAX_RELAY_RESPONSE_BYTES)
            else {
                let _ = close_subscription_until(&mut socket, &subscription_id, deadline).await;
                return Err(RelayNetworkError::ResponseTooLarge);
            };
            response_bytes = total;

            match &incoming {
                Message::Text(_) => {
                    let Ok(response) = incoming.to_text() else {
                        continue;
                    };
                    match parse_relay_frame(response.as_bytes(), &subscription_id) {
                        ParsedRelayFrame::EndOfStoredEvents => {
                            close_subscription_until(&mut socket, &subscription_id, deadline)
                                .await?;
                            return Ok(messages);
                        }
                        ParsedRelayFrame::Event(event_json) => {
                            events_seen += 1;
                            if let Ok(message) =
                                RelayProfileMessage::decode(event_json.get().as_bytes(), now)
                                && message.mailbox() == mailbox
                            {
                                messages.push(message);
                            }
                            if events_seen == MAX_RETRIEVED_EVENTS {
                                close_subscription_until(&mut socket, &subscription_id, deadline)
                                    .await?;
                                return Ok(messages);
                            }
                        }
                        ParsedRelayFrame::SubscriptionClosed => {
                            let _ =
                                close_subscription_until(&mut socket, &subscription_id, deadline)
                                    .await;
                            return Err(RelayNetworkError::SubscriptionClosed);
                        }
                        ParsedRelayFrame::Other => {}
                    }
                }
                Message::Close(_) => {
                    let _ = close_subscription_until(&mut socket, &subscription_id, deadline).await;
                    return Err(RelayNetworkError::WebSocketTransport);
                }
                Message::Binary(_) | Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
            }
        }
    }

    async fn fetch_nip11(&self, relay_url: &str) -> Result<RelayCapabilities, RelayNetworkError> {
        let url = secure_http_equivalent(relay_url)?;
        let mut response = self
            .http
            .get(url)
            .header(ACCEPT, HeaderValue::from_static("application/nostr+json"))
            .send()
            .await
            .map_err(|_| RelayNetworkError::HttpTransport)?;
        if !response.status().is_success() {
            return Err(RelayNetworkError::HttpStatus(response.status().as_u16()));
        }
        if response
            .content_length()
            .is_some_and(|length| length > crate::nip11::MAX_NIP11_BYTES as u64)
        {
            return Err(RelayNetworkError::Nip11BodyTooLarge);
        }

        let initial_capacity = usize::try_from(
            response
                .content_length()
                .unwrap_or(0)
                .min(crate::nip11::MAX_NIP11_BYTES as u64),
        )
        .map_err(|_| RelayNetworkError::Nip11BodyTooLarge)?;
        let mut body = Vec::with_capacity(initial_capacity);
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| RelayNetworkError::HttpTransport)?
        {
            if body.len().saturating_add(chunk.len()) > crate::nip11::MAX_NIP11_BYTES {
                return Err(RelayNetworkError::Nip11BodyTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        parse_nip11(&body).map_err(RelayNetworkError::Nip11)
    }
}

fn secure_http_equivalent(relay_url: &str) -> Result<Url, RelayNetworkError> {
    let mut url = Url::parse(relay_url).map_err(|_| RelayNetworkError::InvalidRelayUrl)?;
    if url.scheme() != "wss" {
        return Err(RelayNetworkError::InsecureRelayUrl);
    }
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(RelayNetworkError::InvalidRelayUrl);
    }
    url.set_scheme("https")
        .map_err(|()| RelayNetworkError::InvalidRelayUrl)?;
    Ok(url)
}

fn event_command(message: &RelayProfileMessage) -> Result<Vec<u8>, RelayNetworkError> {
    let event_json = message
        .to_json()
        .map_err(|_| RelayNetworkError::InvalidResponse)?;
    let prefix = b"[\"EVENT\",";
    let command_len = prefix
        .len()
        .checked_add(event_json.len())
        .and_then(|length| length.checked_add(1))
        .ok_or(RelayNetworkError::CommandTooLarge)?;
    if command_len > MAX_RELAY_COMMAND_BYTES {
        return Err(RelayNetworkError::CommandTooLarge);
    }
    let mut command = Vec::with_capacity(command_len);
    command.extend_from_slice(prefix);
    command.extend_from_slice(&event_json);
    command.push(b']');
    Ok(command)
}

#[derive(Serialize)]
struct RequestFilter<'a> {
    kinds: [u64; 1],
    #[serde(rename = "#t")]
    mailbox: [&'a str; 1],
    since: u64,
    limit: u16,
}

fn request_command(
    subscription_id: &str,
    mailbox: MailboxToken,
    since: u64,
) -> Result<Vec<u8>, RelayNetworkError> {
    let mailbox_tag = mailbox.retrieval_tag();
    let filter = RequestFilter {
        kinds: [crate::profile::LATTICE_RELAY_KIND],
        mailbox: [&mailbox_tag],
        since,
        limit: u16::try_from(MAX_RETRIEVED_EVENTS)
            .map_err(|_| RelayNetworkError::InvalidResponse)?,
    };
    let command = serde_json::to_vec(&("REQ", subscription_id, filter))
        .map_err(|_| RelayNetworkError::InvalidResponse)?;
    if command.len() > MAX_RELAY_COMMAND_BYTES {
        return Err(RelayNetworkError::CommandTooLarge);
    }
    Ok(command)
}

fn next_subscription_id() -> String {
    let sequence = NEXT_SUBSCRIPTION_ID.fetch_add(1, Ordering::Relaxed);
    format!("lattice-relay-{}-{sequence:x}", std::process::id())
}

fn websocket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_RELAY_FRAME_BYTES))
        .max_frame_size(Some(MAX_RELAY_FRAME_BYTES))
}

async fn connect_until(
    relay_url: &str,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<RelaySocket, RelayNetworkError> {
    let _ = secure_http_equivalent(relay_url)?;
    let connect = connect_async_with_config(relay_url, Some(websocket_config()), true);
    tokio::select! {
        () = cancellation.cancelled() => Err(RelayNetworkError::Cancelled),
        result = timeout_at(deadline, connect) => match result {
            Err(_) => Err(RelayNetworkError::Timeout),
            Ok(Err(error)) => Err(map_websocket_error(&error)),
            Ok(Ok((socket, _response))) => Ok(socket),
        }
    }
}

async fn send_until(
    socket: &mut RelaySocket,
    message: Message,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<(), RelayNetworkError> {
    tokio::select! {
        () = cancellation.cancelled() => Err(RelayNetworkError::Cancelled),
        result = timeout_at(deadline, socket.send(message)) => match result {
            Err(_) => Err(RelayNetworkError::Timeout),
            Ok(Err(error)) => Err(map_websocket_error(&error)),
            Ok(Ok(())) => Ok(()),
        }
    }
}

async fn next_until(
    socket: &mut RelaySocket,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<Option<Message>, RelayNetworkError> {
    tokio::select! {
        () = cancellation.cancelled() => Err(RelayNetworkError::Cancelled),
        result = timeout_at(deadline, socket.next()) => match result {
            Err(_) => Err(RelayNetworkError::Timeout),
            Ok(Some(Ok(message))) => Ok(Some(message)),
            Ok(Some(Err(error))) => Err(map_websocket_error(&error)),
            Ok(None) => Ok(None),
        }
    }
}

async fn close_socket_until(
    socket: &mut RelaySocket,
    deadline: Instant,
) -> Result<(), RelayNetworkError> {
    match timeout_at(deadline, socket.close(None)).await {
        Err(_) => Err(RelayNetworkError::Timeout),
        Ok(Err(error)) => Err(map_websocket_error(&error)),
        Ok(Ok(())) => Ok(()),
    }
}

async fn close_subscription_until(
    socket: &mut RelaySocket,
    subscription_id: &str,
    deadline: Instant,
) -> Result<(), RelayNetworkError> {
    let command = serde_json::to_vec(&("CLOSE", subscription_id))
        .map_err(|_| RelayNetworkError::InvalidResponse)?;
    if command.len() > MAX_RELAY_COMMAND_BYTES {
        return Err(RelayNetworkError::CommandTooLarge);
    }
    let command = String::from_utf8(command).map_err(|_| RelayNetworkError::InvalidResponse)?;
    let close = async {
        socket
            .send(Message::text(command))
            .await
            .map_err(|error| map_websocket_error(&error))?;
        socket
            .close(None)
            .await
            .map_err(|error| map_websocket_error(&error))
    };
    match timeout_at(deadline, close).await {
        Err(_) => Err(RelayNetworkError::Timeout),
        Ok(result) => result,
    }
}

fn map_websocket_error(error: &tokio_tungstenite::tungstenite::Error) -> RelayNetworkError {
    match error {
        tokio_tungstenite::tungstenite::Error::Capacity(_) => RelayNetworkError::FrameTooLarge,
        _ => RelayNetworkError::WebSocketTransport,
    }
}

#[derive(Debug, Eq, PartialEq)]
enum OkResponse {
    Accepted,
    Rejected(String),
}

fn parse_ok_response(
    bytes: &[u8],
    expected_id: &str,
) -> Result<Option<OkResponse>, RelayNetworkError> {
    let Some(values) = parse_raw_array(bytes) else {
        return Ok(None);
    };
    let Some(kind) = values.first().and_then(|value| raw_string(value)) else {
        return Ok(None);
    };
    if kind != "OK" {
        return Ok(None);
    }
    if values.len() != 4 {
        return Err(RelayNetworkError::InvalidResponse);
    }
    let response_id = raw_string(&values[1]).ok_or(RelayNetworkError::InvalidResponse)?;
    if response_id != expected_id {
        return Err(RelayNetworkError::InvalidResponse);
    }
    let accepted = serde_json::from_str::<bool>(values[2].get())
        .map_err(|_| RelayNetworkError::InvalidResponse)?;
    let reason = serde_json::from_str::<String>(values[3].get())
        .map_err(|_| RelayNetworkError::InvalidResponse)?;
    Ok(Some(if accepted {
        OkResponse::Accepted
    } else {
        OkResponse::Rejected(reason)
    }))
}

#[derive(Debug)]
enum ParsedRelayFrame {
    Event(Box<RawValue>),
    EndOfStoredEvents,
    SubscriptionClosed,
    Other,
}

fn parse_relay_frame(bytes: &[u8], expected_subscription: &str) -> ParsedRelayFrame {
    let Some(values) = parse_raw_array(bytes) else {
        return ParsedRelayFrame::Other;
    };
    let Some(kind) = values.first().and_then(|value| raw_string(value)) else {
        return ParsedRelayFrame::Other;
    };
    match kind.as_str() {
        "EVENT" if values.len() == 3 => {
            if values.get(1).and_then(|value| raw_string(value)).as_deref()
                != Some(expected_subscription)
            {
                return ParsedRelayFrame::Other;
            }
            let mut values = values.into_iter();
            let _kind = values.next();
            let _subscription = values.next();
            values
                .next()
                .map_or(ParsedRelayFrame::Other, ParsedRelayFrame::Event)
        }
        "EOSE" if values.len() == 2 => {
            if values.get(1).and_then(|value| raw_string(value)).as_deref()
                == Some(expected_subscription)
            {
                ParsedRelayFrame::EndOfStoredEvents
            } else {
                ParsedRelayFrame::Other
            }
        }
        "CLOSED" if values.len() >= 2 => {
            if values.get(1).and_then(|value| raw_string(value)).as_deref()
                == Some(expected_subscription)
            {
                ParsedRelayFrame::SubscriptionClosed
            } else {
                ParsedRelayFrame::Other
            }
        }
        _ => ParsedRelayFrame::Other,
    }
}

fn parse_raw_array(bytes: &[u8]) -> Option<Vec<Box<RawValue>>> {
    serde_json::from_slice(bytes).ok()
}

fn raw_string(value: &RawValue) -> Option<String> {
    serde_json::from_str(value.get()).ok()
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nip11_url_conversion_requires_secure_credential_free_url() {
        let https = secure_http_equivalent("wss://relay.example.test/path?q=1").unwrap();
        assert_eq!(https.as_str(), "https://relay.example.test/path?q=1");
        assert!(matches!(
            secure_http_equivalent("ws://relay.example.test"),
            Err(RelayNetworkError::InsecureRelayUrl)
        ));
        assert!(matches!(
            secure_http_equivalent("wss://user@relay.example.test"),
            Err(RelayNetworkError::InvalidRelayUrl)
        ));
    }

    #[test]
    fn retrieval_filter_is_exact_and_capped() {
        let mailbox = MailboxToken::from_bytes([0x7a; 32]);
        let command = request_command("sub", mailbox, 100).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&command).unwrap();
        assert_eq!(value[0], "REQ");
        assert_eq!(value[1], "sub");
        assert_eq!(value[2]["kinds"], serde_json::json!([39_001]));
        assert_eq!(value[2]["#t"], serde_json::json!([mailbox.retrieval_tag()]));
        assert_eq!(value[2]["since"], 100);
        assert_eq!(value[2]["limit"], MAX_RETRIEVED_EVENTS);
        assert!(command.len() <= MAX_RELAY_COMMAND_BYTES);
    }

    #[test]
    fn raw_event_json_is_not_normalized_before_profile_validation() {
        let frame = br#"["EVENT","sub",{"id":"first","id":"second"}]"#;
        let ParsedRelayFrame::Event(raw_event) = parse_relay_frame(frame, "sub") else {
            panic!("matching EVENT frame should retain its raw event");
        };
        assert_eq!(raw_event.get(), r#"{"id":"first","id":"second"}"#);
    }

    #[test]
    fn publish_requires_positive_ok_for_the_exact_event_id() {
        let target = "01".repeat(32);
        assert_eq!(
            parse_ok_response(format!(r#"["OK","{target}",true,""]"#).as_bytes(), &target).unwrap(),
            Some(OkResponse::Accepted)
        );
        assert!(matches!(
            parse_ok_response(
                format!(r#"["OK","{}",true,""]"#, "02".repeat(32)).as_bytes(),
                &target
            ),
            Err(RelayNetworkError::InvalidResponse)
        ));
        assert_eq!(
            parse_ok_response(
                format!(r#"["OK","{target}",false,"blocked"]"#).as_bytes(),
                &target
            )
            .unwrap(),
            Some(OkResponse::Rejected("blocked".to_owned()))
        );
    }
}
