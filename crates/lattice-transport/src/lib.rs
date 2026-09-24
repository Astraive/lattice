//! Bounded platform transport ports for opaque envelopes.
//!
//! This crate defines a shared adapter contract only. It does not implement
//! BLE, LAN, Wi-Fi Aware, sockets, or relay networking, and a successful send
//! means local adapter acceptance rather than remote delivery.

/// Package's published crate name.
pub const CRATE_NAME: &str = "lattice-transport";
/// Absolute envelope ceiling shared by all adapters.
pub const MAX_ENVELOPE_BYTES: usize = 16 * 1024 * 1024;

/// Current platform path state; only `Connected` can exchange envelopes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathState {
    /// No path is available due to permission, hardware, or OS state.
    Unavailable,
    /// The path can be established but is not connected yet.
    Available,
    /// The adapter has an authenticated or otherwise usable active link.
    Connected,
}

/// Runtime capabilities reported by one concrete platform path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathCapabilities {
    /// Maximum complete opaque envelope accepted by this path.
    pub max_envelope_bytes: usize,
    /// Whether the path can be considered for bulk application payloads.
    pub supports_bulk: bool,
}

/// Adapter's report after polling one complete envelope into caller storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveResult {
    /// No complete envelope is currently available.
    Empty,
    /// One complete envelope was copied into the supplied buffer.
    Received(usize),
    /// The adapter observed an envelope larger than its bounded receive buffer.
    Oversized,
}

/// A complete opaque envelope was handed to a local adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendOutcome {
    /// Local adapter accepted the envelope; this is not a delivery receipt.
    AcceptedByAdapter,
}

/// Failures detected at the shared bounded transport boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportError<E> {
    /// Adapter reported zero or an over-limit capability.
    InvalidCapabilities,
    /// Path is not connected; caller may retain or retry the envelope.
    NotConnected(PathState),
    /// Envelope exceeds the smaller of the path and crate limits.
    EnvelopeTooLarge { supplied: usize, maximum: usize },
    /// Adapter claimed a receive length outside the supplied bounded buffer.
    InvalidReceiveLength { reported: usize, capacity: usize },
    /// Adapter-specific failure.
    Adapter(E),
}

/// Platform-owned link implementation for already-enveloped opaque bytes.
///
/// Implementations own connection setup, OS permissions, peer authentication,
/// link framing, pacing, and teardown. They must write only within `buffer`;
/// application validation and delivery accounting remain above this port.
pub trait TransportAdapter {
    /// Adapter-specific I/O error.
    type Error;

    /// Returns the path's current lifecycle state.
    fn state(&self) -> PathState;

    /// Returns runtime capabilities discovered from the OS and peer.
    fn capabilities(&self) -> PathCapabilities;

    /// Gives one complete opaque envelope to the connected local adapter.
    ///
    /// # Errors
    ///
    /// Returns the adapter-specific error when local submission fails.
    fn send_envelope(&mut self, envelope: &[u8]) -> Result<(), Self::Error>;

    /// Polls for one complete envelope, writing no more than `buffer.len()`.
    ///
    /// # Errors
    ///
    /// Returns the adapter-specific error when polling fails.
    fn receive_envelope(&mut self, buffer: &mut [u8]) -> Result<ReceiveResult, Self::Error>;
}

/// Submits one bounded opaque envelope after validating path state and limits.
///
/// # Errors
///
/// Returns an error if capabilities are invalid, the path is not connected,
/// the object exceeds the advertised bound, or the adapter rejects the send.
pub fn send_bounded<A: TransportAdapter>(
    adapter: &mut A,
    envelope: &[u8],
) -> Result<SendOutcome, TransportError<A::Error>> {
    let capabilities = checked_capabilities(adapter.capabilities())?;
    if adapter.state() != PathState::Connected {
        return Err(TransportError::NotConnected(adapter.state()));
    }
    let maximum = capabilities.max_envelope_bytes.min(MAX_ENVELOPE_BYTES);
    if envelope.len() > maximum {
        return Err(TransportError::EnvelopeTooLarge {
            supplied: envelope.len(),
            maximum,
        });
    }
    adapter
        .send_envelope(envelope)
        .map_err(TransportError::Adapter)?;
    Ok(SendOutcome::AcceptedByAdapter)
}

/// Receives at most one complete envelope into caller-owned bounded storage.
///
/// The returned slice borrows `buffer`; no allocation or unbounded copy occurs.
///
/// # Errors
///
/// Returns an error if capabilities are invalid, the path is not connected,
/// the adapter claims an impossible length, or the adapter reports an I/O error.
pub fn receive_bounded<'a, A: TransportAdapter>(
    adapter: &mut A,
    buffer: &'a mut [u8],
) -> Result<Option<&'a [u8]>, TransportError<A::Error>> {
    let capabilities = checked_capabilities(adapter.capabilities())?;
    if adapter.state() != PathState::Connected {
        return Err(TransportError::NotConnected(adapter.state()));
    }
    let maximum = capabilities.max_envelope_bytes.min(MAX_ENVELOPE_BYTES);
    let capacity = buffer.len().min(maximum);
    let result = adapter
        .receive_envelope(&mut buffer[..capacity])
        .map_err(TransportError::Adapter)?;
    match result {
        ReceiveResult::Empty | ReceiveResult::Oversized => Ok(None),
        ReceiveResult::Received(reported) if reported <= capacity => Ok(Some(&buffer[..reported])),
        ReceiveResult::Received(reported) => {
            Err(TransportError::InvalidReceiveLength { reported, capacity })
        }
    }
}

fn checked_capabilities<E>(
    capabilities: PathCapabilities,
) -> Result<PathCapabilities, TransportError<E>> {
    if capabilities.max_envelope_bytes == 0 || capabilities.max_envelope_bytes > MAX_ENVELOPE_BYTES
    {
        return Err(TransportError::InvalidCapabilities);
    }
    Ok(capabilities)
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_ENVELOPE_BYTES, PathCapabilities, PathState, ReceiveResult, SendOutcome,
        TransportAdapter, TransportError, receive_bounded, send_bounded,
    };

    use std::convert::Infallible;

    struct MockAdapter {
        state: PathState,
        capabilities: PathCapabilities,
        sent: Vec<Vec<u8>>,
        incoming: Option<Vec<u8>>,
        send_calls: usize,
    }

    impl TransportAdapter for MockAdapter {
        type Error = Infallible;

        fn state(&self) -> PathState {
            self.state
        }

        fn capabilities(&self) -> PathCapabilities {
            self.capabilities
        }

        fn send_envelope(&mut self, envelope: &[u8]) -> Result<(), Self::Error> {
            self.send_calls += 1;
            self.sent.push(envelope.to_vec());
            Ok(())
        }

        fn receive_envelope(&mut self, buffer: &mut [u8]) -> Result<ReceiveResult, Self::Error> {
            let Some(incoming) = self.incoming.take() else {
                return Ok(ReceiveResult::Empty);
            };
            if incoming.len() > buffer.len() {
                return Ok(ReceiveResult::Oversized);
            }
            buffer[..incoming.len()].copy_from_slice(&incoming);
            Ok(ReceiveResult::Received(incoming.len()))
        }
    }

    fn connected_adapter(max_envelope_bytes: usize) -> MockAdapter {
        MockAdapter {
            state: PathState::Connected,
            capabilities: PathCapabilities {
                max_envelope_bytes,
                supports_bulk: false,
            },
            sent: Vec::new(),
            incoming: None,
            send_calls: 0,
        }
    }

    #[test]
    fn rejects_disconnected_and_oversized_sends_before_adapter_io() {
        let mut adapter = connected_adapter(4);
        assert_eq!(
            send_bounded(&mut adapter, b"12345"),
            Err(TransportError::EnvelopeTooLarge {
                supplied: 5,
                maximum: 4,
            })
        );
        assert_eq!(adapter.send_calls, 0);

        adapter.state = PathState::Available;
        assert_eq!(
            send_bounded(&mut adapter, b"1"),
            Err(TransportError::NotConnected(PathState::Available))
        );
        assert_eq!(adapter.send_calls, 0);
    }

    #[test]
    fn accepted_send_is_local_only_and_receive_is_bounded_by_path_capability() {
        let mut adapter = connected_adapter(4);
        assert_eq!(
            send_bounded(&mut adapter, b"data"),
            Ok(SendOutcome::AcceptedByAdapter)
        );
        assert_eq!(adapter.sent, [b"data".to_vec()]);

        adapter.incoming = Some(b"toolong".to_vec());
        let mut storage = [0; 8];
        assert_eq!(receive_bounded(&mut adapter, &mut storage), Ok(None));

        adapter.incoming = Some(b"ok".to_vec());
        assert_eq!(
            receive_bounded(&mut adapter, &mut storage),
            Ok(Some(&b"ok"[..]))
        );
    }

    #[test]
    fn invalid_or_excessive_adapter_capabilities_fail_closed() {
        let mut adapter = connected_adapter(0);
        assert_eq!(
            send_bounded(&mut adapter, b"x"),
            Err(TransportError::InvalidCapabilities)
        );
        adapter.capabilities.max_envelope_bytes = MAX_ENVELOPE_BYTES + 1;
        assert_eq!(
            receive_bounded(&mut adapter, &mut [0; 4]),
            Err(TransportError::InvalidCapabilities)
        );
    }
}
