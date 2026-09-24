//! Bounded transport orchestration over the shared platform adapter port.
//!
//! This crate does not implement BLE, LAN, Wi-Fi Aware, sockets, or relay
//! networking. A successful send means exact-hop adapter acceptance only.

use lattice_platform::{TransportAdapter, TransportError};

/// Package's published crate name.
pub const CRATE_NAME: &str = "lattice-transport";

/// Submits an opaque envelope only when the platform adapter is running and
/// the object fits the adapter's advertised limit.
///
/// The adapter remains responsible for native framing, permissions, and I/O.
/// This function never retries or allocates; ownership of the envelope passes
/// directly to the platform port after the bounds check.
///
/// # Errors
///
/// Returns `NotRunning` or `EnvelopeTooLarge` before adapter I/O, or the exact
/// error returned by the platform adapter.
pub async fn send_bounded<A: TransportAdapter + ?Sized>(
    adapter: &A,
    envelope: lattice_platform::EnvelopeBytes,
) -> Result<lattice_platform::TransportReceipt, TransportError> {
    let maximum = adapter.capabilities().max_envelope_bytes();
    if adapter.lifecycle() != lattice_platform::TransportLifecycle::Running {
        return Err(TransportError::NotRunning);
    }
    if envelope.as_bytes().len() > maximum {
        return Err(TransportError::EnvelopeTooLarge);
    }
    adapter.send(envelope).await
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    use lattice_platform::{
        AdapterName, EnvelopeBytes, PortFuture, TransportAdapter, TransportCapabilities,
        TransportError, TransportLifecycle, TransportReceipt,
    };

    use super::send_bounded;

    struct MockAdapter {
        capabilities: TransportCapabilities,
        lifecycle: TransportLifecycle,
        sends: AtomicUsize,
    }

    impl MockAdapter {
        fn new(lifecycle: TransportLifecycle, maximum: usize) -> Self {
            Self {
                capabilities: TransportCapabilities::new(
                    AdapterName::try_from("mock-test".to_owned()).expect("valid adapter name"),
                    maximum,
                )
                .expect("valid capability bound"),
                lifecycle,
                sends: AtomicUsize::new(0),
            }
        }
    }

    impl TransportAdapter for MockAdapter {
        fn capabilities(&self) -> TransportCapabilities {
            self.capabilities.clone()
        }

        fn lifecycle(&self) -> TransportLifecycle {
            self.lifecycle
        }

        fn start(&self) -> PortFuture<'_, Result<(), TransportError>> {
            Box::pin(async { Ok(()) })
        }

        fn stop(&self) -> PortFuture<'_, Result<(), TransportError>> {
            Box::pin(async { Ok(()) })
        }

        fn send(
            &self,
            envelope: EnvelopeBytes,
        ) -> PortFuture<'_, Result<TransportReceipt, TransportError>> {
            Box::pin(async move {
                drop(envelope);
                self.sends.fetch_add(1, Ordering::Relaxed);
                Ok(TransportReceipt::AcceptedByNextHop)
            })
        }
    }

    struct NoopWake;

    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    fn run_ready<F: Future>(future: F) -> F::Output {
        let waker = Waker::from(Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);
        let mut future = Box::pin(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("test adapter future must be immediately ready"),
        }
    }

    fn envelope(bytes: &[u8]) -> EnvelopeBytes {
        EnvelopeBytes::try_from(bytes.to_vec()).expect("bounded test envelope")
    }

    #[test]
    fn checks_lifecycle_and_adapter_limit_before_native_io() {
        let stopped = MockAdapter::new(TransportLifecycle::Stopped, 4);
        assert_eq!(
            run_ready(send_bounded(&stopped, envelope(b"x"))),
            Err(TransportError::NotRunning)
        );
        assert_eq!(stopped.sends.load(Ordering::Relaxed), 0);

        let running = MockAdapter::new(TransportLifecycle::Running, 4);
        assert_eq!(
            run_ready(send_bounded(&running, envelope(b"12345"))),
            Err(TransportError::EnvelopeTooLarge)
        );
        assert_eq!(running.sends.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn passing_send_returns_only_the_adapter_hop_receipt() {
        let adapter = MockAdapter::new(TransportLifecycle::Running, 4);
        assert_eq!(
            run_ready(send_bounded(&adapter, envelope(b"data"))),
            Ok(TransportReceipt::AcceptedByNextHop)
        );
        assert_eq!(adapter.sends.load(Ordering::Relaxed), 1);
    }
}
