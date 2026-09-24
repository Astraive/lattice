//! Bounded direct TCP transport for one already-connected peer.

use std::io;
use std::sync::atomic::{AtomicU8, Ordering};

use lattice_platform::{
    AdapterName, EnvelopeBytes, MAX_ENVELOPE_BYTES, PortFuture, TransportAdapter,
    TransportCapabilities, TransportError, TransportLifecycle, TransportReceipt,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::sync::{Mutex, Notify};

struct PendingWrite<'a> {
    state: &'a AtomicU8,
    armed: bool,
}

impl PendingWrite<'_> {
    fn complete(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingWrite<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.state.compare_exchange(
                STATE_RUNNING,
                STATE_FAULTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
    }
}

const STATE_STOPPED: u8 = 0;
const STATE_RUNNING: u8 = 1;
const STATE_STOPPING: u8 = 2;
const STATE_FAULTED: u8 = 3;

/// One bounded, opaque-envelope adapter over a connected TCP peer.
///
/// The adapter owns one stream and supports one concurrent reader and writer.
/// Frames contain a 4-byte big-endian payload length and exactly one envelope.
/// It neither authenticates the peer nor retries or reports destination
/// delivery. `stop` wakes a pending receive; dropping the adapter closes the
/// stream. A cancelled `stop` can safely be called again.
pub struct TcpPeerAdapter {
    capabilities: TransportCapabilities,
    state: AtomicU8,
    reader: Mutex<Reader>,
    writer: Mutex<OwnedWriteHalf>,
    stopped: Notify,
}

struct Reader {
    stream: OwnedReadHalf,
    header: [u8; 4],
    header_read: usize,
    expected: Option<usize>,
    payload: Vec<u8>,
    payload_read: usize,
}

impl Reader {
    fn new(stream: OwnedReadHalf) -> Self {
        Self {
            stream,
            header: [0; 4],
            header_read: 0,
            expected: None,
            payload: Vec::new(),
            payload_read: 0,
        }
    }

    fn reset(&mut self) {
        self.header = [0; 4];
        self.header_read = 0;
        self.expected = None;
        self.payload_read = 0;
    }
}

impl TcpPeerAdapter {
    /// Connects one TCP stream to `endpoint` and immediately makes it available.
    ///
    /// `max_envelope_bytes` must be in `1..=MAX_ENVELOPE_BYTES`. There is no
    /// connect timeout or retry policy; callers may wrap this future in their
    /// own timeout or cancellation.
    ///
    /// # Errors
    ///
    /// Returns `EnvelopeTooLarge` if the requested cap is zero or above the
    /// shared port maximum, `PermissionDenied` for a permission failure,
    /// `Unavailable` for connection refusal, timeout, or reachability failure,
    /// or `OperationFailed` for other socket or address errors.
    pub async fn connect<A: ToSocketAddrs>(
        endpoint: A,
        max_envelope_bytes: usize,
    ) -> Result<Self, TransportError> {
        if max_envelope_bytes == 0 || max_envelope_bytes > MAX_ENVELOPE_BYTES {
            return Err(TransportError::EnvelopeTooLarge);
        }
        let stream = TcpStream::connect(endpoint)
            .await
            .map_err(|error| map_io_error(&error))?;
        Self::from_stream(stream, max_envelope_bytes)
    }

    /// Creates an adapter from a connected or accepted TCP stream.
    ///
    /// The supplied stream is owned by this adapter. The stream remains open
    /// until `stop` or drop; pending reads are woken when `stop` is called.
    ///
    /// # Errors
    ///
    /// Returns `EnvelopeTooLarge` when `max_envelope_bytes` is zero or above
    /// `MAX_ENVELOPE_BYTES`.
    pub fn from_stream(
        stream: TcpStream,
        max_envelope_bytes: usize,
    ) -> Result<Self, TransportError> {
        if max_envelope_bytes == 0 || max_envelope_bytes > MAX_ENVELOPE_BYTES {
            return Err(TransportError::EnvelopeTooLarge);
        }
        let name = AdapterName::try_from("tcp-peer".to_owned())
            .map_err(|_| TransportError::OperationFailed)?;
        let capabilities = TransportCapabilities::new(name, max_envelope_bytes)
            .map_err(|_| TransportError::EnvelopeTooLarge)?;
        let (reader, writer) = stream.into_split();
        Ok(Self {
            capabilities,
            state: AtomicU8::new(STATE_RUNNING),
            reader: Mutex::new(Reader::new(reader)),
            writer: Mutex::new(writer),
            stopped: Notify::new(),
        })
    }

    fn fault(&self) {
        let _ = self.state.compare_exchange(
            STATE_RUNNING,
            STATE_FAULTED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    async fn receive_frame(&self) -> Result<Option<EnvelopeBytes>, TransportError> {
        let mut reader = self.reader.lock().await;
        loop {
            if self.state.load(Ordering::Acquire) != STATE_RUNNING {
                return Err(TransportError::NotRunning);
            }

            if reader.expected.is_none() {
                let header_read = reader.header_read;
                let notified = self.stopped.notified();
                let read_result = {
                    let Reader { stream, header, .. } = &mut *reader;
                    tokio::select! {
                        biased;
                        () = notified => return Err(TransportError::NotRunning),
                        result = stream.read(&mut header[header_read..]) => result,
                    }
                };
                match read_result {
                    Ok(0) if header_read == 0 => {
                        self.fault();
                        return Ok(None);
                    }
                    Ok(0) => {
                        self.fault();
                        return Err(TransportError::InvalidEnvelope);
                    }
                    Ok(read) => reader.header_read += read,
                    Err(error) => {
                        self.fault();
                        return Err(map_io_error(&error));
                    }
                }
                if reader.header_read < 4 {
                    continue;
                }
                let length = u32::from_be_bytes(reader.header) as usize;
                if length == 0 {
                    self.fault();
                    return Err(TransportError::InvalidEnvelope);
                }
                if length > self.capabilities.max_envelope_bytes() {
                    self.fault();
                    return Err(TransportError::EnvelopeTooLarge);
                }
                // The peer-provided size is checked against both bounds before allocation.
                reader.payload = vec![0; length];
                reader.payload_read = 0;
                reader.expected = Some(length);
            }

            let expected = reader.expected.expect("frame length was set");
            let payload_read = reader.payload_read;
            let notified = self.stopped.notified();
            let read_result = {
                let Reader {
                    stream, payload, ..
                } = &mut *reader;
                tokio::select! {
                    biased;
                    () = notified => return Err(TransportError::NotRunning),
                    result = stream.read(&mut payload[payload_read..]) => result,
                }
            };
            match read_result {
                Ok(0) => {
                    self.fault();
                    return Err(TransportError::InvalidEnvelope);
                }
                Ok(read) => reader.payload_read += read,
                Err(error) => {
                    self.fault();
                    return Err(map_io_error(&error));
                }
            }
            if reader.payload_read == expected {
                let bytes = std::mem::take(&mut reader.payload);
                reader.reset();
                return EnvelopeBytes::try_from(bytes)
                    .map(Some)
                    .map_err(|_| TransportError::EnvelopeTooLarge);
            }
        }
    }
}

impl TransportAdapter for TcpPeerAdapter {
    fn capabilities(&self) -> TransportCapabilities {
        self.capabilities.clone()
    }

    fn lifecycle(&self) -> TransportLifecycle {
        match self.state.load(Ordering::Acquire) {
            STATE_STOPPED => TransportLifecycle::Stopped,
            STATE_RUNNING => TransportLifecycle::Running,
            STATE_STOPPING => TransportLifecycle::Stopping,
            _ => TransportLifecycle::Faulted,
        }
    }

    fn start(&self) -> PortFuture<'_, Result<(), TransportError>> {
        Box::pin(async move {
            if self.state.load(Ordering::Acquire) == STATE_RUNNING {
                Ok(())
            } else {
                Err(TransportError::NotRunning)
            }
        })
    }

    fn stop(&self) -> PortFuture<'_, Result<(), TransportError>> {
        Box::pin(async move {
            let state = self.state.load(Ordering::Acquire);
            if state == STATE_STOPPED {
                return Ok(());
            }
            if state != STATE_FAULTED {
                self.state.store(STATE_STOPPING, Ordering::Release);
            }
            self.stopped.notify_one();
            let result = self
                .writer
                .lock()
                .await
                .shutdown()
                .await
                .map_err(|error| map_io_error(&error));
            self.state.store(
                if result.is_ok() {
                    STATE_STOPPED
                } else {
                    STATE_FAULTED
                },
                Ordering::Release,
            );
            result
        })
    }

    fn send(
        &self,
        envelope: EnvelopeBytes,
    ) -> PortFuture<'_, Result<TransportReceipt, TransportError>> {
        Box::pin(async move {
            if self.state.load(Ordering::Acquire) != STATE_RUNNING {
                return Err(TransportError::NotRunning);
            }
            let bytes = envelope.into_bytes();
            if bytes.is_empty() {
                return Err(TransportError::InvalidEnvelope);
            }
            if bytes.len() > self.capabilities.max_envelope_bytes() {
                return Err(TransportError::EnvelopeTooLarge);
            }
            let length =
                u32::try_from(bytes.len()).map_err(|_| TransportError::EnvelopeTooLarge)?;
            let mut writer = self.writer.lock().await;
            let mut pending_write = PendingWrite {
                state: &self.state,
                armed: true,
            };

            if self.state.load(Ordering::Acquire) != STATE_RUNNING {
                return Err(TransportError::NotRunning);
            }
            let write_result = async {
                writer.write_all(&length.to_be_bytes()).await?;
                writer.write_all(&bytes).await
            }
            .await;
            pending_write.complete();

            if let Err(error) = write_result {
                self.state.store(STATE_FAULTED, Ordering::Release);
                return Err(map_io_error(&error));
            }
            Ok(TransportReceipt::QueuedToOs)
        })
    }

    fn receive(&self) -> PortFuture<'_, Result<Option<EnvelopeBytes>, TransportError>> {
        Box::pin(self.receive_frame())
    }
}

fn map_io_error(error: &io::Error) -> TransportError {
    match error.kind() {
        io::ErrorKind::PermissionDenied => TransportError::PermissionDenied,
        io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof => {
            TransportError::InvalidEnvelope
        }
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::NotConnected
        | io::ErrorKind::AddrNotAvailable
        | io::ErrorKind::AddrInUse
        | io::ErrorKind::TimedOut
        | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::HostUnreachable => TransportError::Unavailable,
        _ => TransportError::OperationFailed,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    async fn connected_pair(maximum: usize) -> (TcpPeerAdapter, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let address = listener.local_addr().expect("listener address");
        let (accepted, connected) = tokio::join!(listener.accept(), TcpStream::connect(address));
        let (peer, _) = accepted.expect("accept connection");
        let adapter = TcpPeerAdapter::from_stream(connected.expect("connect peer"), maximum)
            .expect("adapter from connected stream");
        (adapter, peer)
    }

    fn envelope(bytes: &[u8]) -> EnvelopeBytes {
        EnvelopeBytes::try_from(bytes.to_vec()).expect("valid envelope")
    }

    #[tokio::test]
    async fn sends_and_receives_exact_length_prefixed_opaque_frames() {
        let (adapter, mut peer) = connected_pair(32).await;
        assert_eq!(
            adapter.send(envelope(b"opaque")).await,
            Ok(TransportReceipt::QueuedToOs)
        );
        let mut header = [0; 4];
        peer.read_exact(&mut header).await.expect("frame header");
        assert_eq!(header, 6_u32.to_be_bytes());
        let mut payload = [0; 6];
        peer.read_exact(&mut payload).await.expect("frame payload");
        assert_eq!(&payload, b"opaque");

        peer.write_all(&3_u32.to_be_bytes())
            .await
            .expect("write frame header");
        peer.write_all(b"\0\xff!")
            .await
            .expect("write opaque payload");
        assert_eq!(
            adapter
                .receive()
                .await
                .expect("receive succeeds")
                .unwrap()
                .as_bytes(),
            b"\0\xff!"
        );
    }

    #[tokio::test]
    async fn rejects_oversize_and_truncated_frames() {
        let (adapter, mut peer) = connected_pair(4).await;
        peer.write_all(&0_u32.to_be_bytes())
            .await
            .expect("write zero length");
        assert!(matches!(
            adapter.receive().await,
            Err(TransportError::InvalidEnvelope)
        ));

        let (adapter, mut peer) = connected_pair(4).await;
        peer.write_all(&5_u32.to_be_bytes())
            .await
            .expect("write oversized length");
        assert!(matches!(
            adapter.receive().await,
            Err(TransportError::EnvelopeTooLarge)
        ));

        let (adapter, mut peer) = connected_pair(4).await;
        peer.write_all(&[0, 0]).await.expect("write partial header");
        peer.shutdown().await.expect("close peer write side");
        assert!(matches!(
            adapter.receive().await,
            Err(TransportError::InvalidEnvelope)
        ));

        let (adapter, mut peer) = connected_pair(4).await;
        peer.write_all(&4_u32.to_be_bytes())
            .await
            .expect("write payload length");
        peer.write_all(b"ab").await.expect("write partial payload");
        peer.shutdown().await.expect("close peer write side");
        assert!(matches!(
            adapter.receive().await,
            Err(TransportError::InvalidEnvelope)
        ));
    }

    #[tokio::test]
    async fn stop_wakes_pending_receive_and_preserves_stopped_lifecycle() {
        let (adapter, _peer) = connected_pair(8).await;
        let adapter = Arc::new(adapter);
        let pending_adapter = Arc::clone(&adapter);
        let pending = tokio::spawn(async move { pending_adapter.receive().await });
        tokio::task::yield_now().await;
        assert_eq!(adapter.stop().await, Ok(()));
        assert!(matches!(
            pending.await.expect("receive task"),
            Err(TransportError::NotRunning)
        ));
        assert_eq!(adapter.lifecycle(), TransportLifecycle::Stopped);
        assert_eq!(adapter.start().await, Err(TransportError::NotRunning));
    }
}
