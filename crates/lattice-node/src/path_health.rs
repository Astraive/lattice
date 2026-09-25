//! Bounded, local observations of transport path lifecycle and exact-hop outcomes.
//!
//! These records do not infer peer presence, physical distance, or destination
//! delivery. Callers report adapter lifecycle and completed I/O observations.

use std::collections::BTreeMap;

use lattice_platform::{TransportError, TransportLifecycle, TransportReceipt};
use lattice_router::{MAX_ROUTING_CANDIDATES, PathId};
use thiserror::Error;

/// Maximum distinct paths retained by one tracker.
pub const MAX_TRACKED_PATHS: usize = MAX_ROUTING_CANDIDATES;

/// One completed send observation with its exact transport scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathSendObservation {
    /// The adapter returned an exact-hop acceptance receipt.
    Accepted {
        /// Caller-supplied monotonic completion time in milliseconds.
        at_mono_ms: u64,
        /// The local OS or immediate next-hop receipt; never recipient delivery.
        receipt: TransportReceipt,
    },
    /// The adapter returned a typed transport failure.
    Failed {
        /// Caller-supplied monotonic completion time in milliseconds.
        at_mono_ms: u64,
        /// Exact error returned by the adapter.
        error: TransportError,
    },
}

/// Truthful local state for one registered transport path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathHealthSnapshot {
    /// Opaque local path identifier.
    pub path_id: PathId,
    /// Latest adapter lifecycle state reported by the caller.
    pub lifecycle: TransportLifecycle,
    /// Most recent completed send, if any.
    pub last_send: Option<PathSendObservation>,
    /// Most recent successful receive completion time, if any.
    pub last_receive_at_mono_ms: Option<u64>,
    /// Most recent accepted send completion time, regardless of later failures.
    pub last_successful_send_at_mono_ms: Option<u64>,
    /// Consecutive failed sends since the last accepted send.
    pub consecutive_send_failures: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PathHealthRecord {
    snapshot: PathHealthSnapshot,
    last_observation_at_mono_ms: Option<u64>,
}

/// Rejected path-health updates.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PathHealthError {
    /// The path is already registered.
    #[error("path is already registered")]
    DuplicatePath,
    /// The bounded tracker already retains the maximum number of paths.
    #[error("path health tracker is full")]
    CapacityReached,
    /// No lifecycle observation has registered this path.
    #[error("path is not registered")]
    UnknownPath,
    /// An observation timestamp predates the latest send or receive observation.
    #[error("path observation timestamp moved backward")]
    OutOfOrderObservation,
}

/// Bounded registry of caller-reported path lifecycle and exact-hop outcomes.
#[derive(Clone, Debug, Default)]
pub struct PathHealthTracker {
    paths: BTreeMap<PathId, PathHealthRecord>,
}

impl PathHealthTracker {
    /// Registers a path with its currently observed adapter lifecycle state.
    ///
    /// # Errors
    ///
    /// Returns [`PathHealthError::DuplicatePath`] for an existing ID or
    /// [`PathHealthError::CapacityReached`] at the fixed registry bound.
    pub fn register(
        &mut self,
        path_id: PathId,
        lifecycle: TransportLifecycle,
    ) -> Result<(), PathHealthError> {
        if self.paths.contains_key(&path_id) {
            return Err(PathHealthError::DuplicatePath);
        }
        if self.paths.len() >= MAX_TRACKED_PATHS {
            return Err(PathHealthError::CapacityReached);
        }
        self.paths.insert(
            path_id,
            PathHealthRecord {
                snapshot: PathHealthSnapshot {
                    path_id,
                    lifecycle,
                    last_send: None,
                    last_receive_at_mono_ms: None,
                    last_successful_send_at_mono_ms: None,
                    consecutive_send_failures: 0,
                },
                last_observation_at_mono_ms: None,
            },
        );
        Ok(())
    }

    /// Updates one path with the adapter's actual lifecycle state.
    ///
    /// A send error does not implicitly change lifecycle state; only an explicit
    /// adapter observation can report that the adapter entered `Faulted`.
    ///
    /// # Errors
    ///
    /// Returns [`PathHealthError::UnknownPath`] when the path was not registered.
    pub fn observe_lifecycle(
        &mut self,
        path_id: PathId,
        lifecycle: TransportLifecycle,
    ) -> Result<(), PathHealthError> {
        let record = self
            .paths
            .get_mut(&path_id)
            .ok_or(PathHealthError::UnknownPath)?;
        record.snapshot.lifecycle = lifecycle;
        Ok(())
    }

    /// Records one completed send without upgrading its receipt to delivery.
    ///
    /// # Errors
    ///
    /// Returns [`PathHealthError::UnknownPath`] for an unregistered path or
    /// [`PathHealthError::OutOfOrderObservation`] for a stale completion.
    pub fn record_send(
        &mut self,
        path_id: PathId,
        at_mono_ms: u64,
        result: Result<TransportReceipt, TransportError>,
    ) -> Result<PathHealthSnapshot, PathHealthError> {
        let record = self
            .paths
            .get_mut(&path_id)
            .ok_or(PathHealthError::UnknownPath)?;
        check_timestamp(record, at_mono_ms)?;
        let observation = match result {
            Ok(receipt) => {
                record.snapshot.consecutive_send_failures = 0;
                record.snapshot.last_successful_send_at_mono_ms = Some(at_mono_ms);
                PathSendObservation::Accepted {
                    at_mono_ms,
                    receipt,
                }
            }
            Err(error) => {
                record.snapshot.consecutive_send_failures =
                    record.snapshot.consecutive_send_failures.saturating_add(1);
                PathSendObservation::Failed { at_mono_ms, error }
            }
        };
        record.snapshot.last_send = Some(observation);
        record.last_observation_at_mono_ms = Some(at_mono_ms);
        Ok(record.snapshot)
    }

    /// Records one complete receive from the path, without inferring reachability
    /// beyond this local receive observation.
    ///
    /// # Errors
    ///
    /// Returns [`PathHealthError::UnknownPath`] for an unregistered path or
    /// [`PathHealthError::OutOfOrderObservation`] for a stale completion.
    pub fn record_receive(
        &mut self,
        path_id: PathId,
        at_mono_ms: u64,
    ) -> Result<PathHealthSnapshot, PathHealthError> {
        let record = self
            .paths
            .get_mut(&path_id)
            .ok_or(PathHealthError::UnknownPath)?;
        check_timestamp(record, at_mono_ms)?;
        record.snapshot.last_receive_at_mono_ms = Some(at_mono_ms);
        record.last_observation_at_mono_ms = Some(at_mono_ms);
        Ok(record.snapshot)
    }

    /// Returns the latest local snapshot for one registered path.
    #[must_use]
    pub fn get(&self, path_id: PathId) -> Option<PathHealthSnapshot> {
        self.paths.get(&path_id).map(|record| record.snapshot)
    }

    /// Removes one path after its adapter has been closed.
    pub fn remove(&mut self, path_id: PathId) -> bool {
        self.paths.remove(&path_id).is_some()
    }
}

fn check_timestamp(record: &PathHealthRecord, at_mono_ms: u64) -> Result<(), PathHealthError> {
    if record
        .last_observation_at_mono_ms
        .is_some_and(|last| at_mono_ms < last)
    {
        return Err(PathHealthError::OutOfOrderObservation);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_observations_preserve_exact_receipt_and_failure_state() {
        let path_id = PathId(7);
        let mut tracker = PathHealthTracker::default();
        tracker
            .register(path_id, TransportLifecycle::Running)
            .expect("register path");
        let failed = tracker
            .record_send(path_id, 10, Err(TransportError::PermissionDenied))
            .expect("record permission failure");
        assert_eq!(failed.lifecycle, TransportLifecycle::Running);
        assert_eq!(failed.consecutive_send_failures, 1);
        assert_eq!(
            failed.last_send,
            Some(PathSendObservation::Failed {
                at_mono_ms: 10,
                error: TransportError::PermissionDenied,
            })
        );

        let accepted = tracker
            .record_send(path_id, 20, Ok(TransportReceipt::AcceptedByNextHop))
            .expect("record next-hop acceptance");
        assert_eq!(accepted.consecutive_send_failures, 0);
        assert_eq!(accepted.last_successful_send_at_mono_ms, Some(20));
        let failed_again = tracker
            .record_send(path_id, 25, Err(TransportError::OperationFailed))
            .expect("record later failed send");
        assert_eq!(failed_again.last_successful_send_at_mono_ms, Some(20));
        assert_eq!(failed_again.consecutive_send_failures, 1);
        assert_eq!(
            accepted.last_send,
            Some(PathSendObservation::Accepted {
                at_mono_ms: 20,
                receipt: TransportReceipt::AcceptedByNextHop,
            })
        );
        assert_eq!(accepted.last_receive_at_mono_ms, None);

        let received = tracker
            .record_receive(path_id, 30)
            .expect("record complete local receive");
        assert_eq!(received.last_receive_at_mono_ms, Some(30));
        assert_eq!(received.last_successful_send_at_mono_ms, Some(20));
        assert_eq!(received.last_send, failed_again.last_send);
    }

    #[test]
    fn path_tracker_rejects_stale_unknown_and_over_capacity_observations() {
        let path_id = PathId(1);
        let mut tracker = PathHealthTracker::default();
        assert_eq!(
            tracker.record_receive(path_id, 1),
            Err(PathHealthError::UnknownPath)
        );
        tracker
            .register(path_id, TransportLifecycle::Stopped)
            .expect("register path");
        tracker
            .record_receive(path_id, 10)
            .expect("record current receive");
        assert_eq!(
            tracker.record_send(path_id, 9, Err(TransportError::Unavailable)),
            Err(PathHealthError::OutOfOrderObservation)
        );
        for raw_path_id in 2..=MAX_TRACKED_PATHS as u64 {
            tracker
                .register(PathId(raw_path_id), TransportLifecycle::Stopped)
                .expect("fill bounded tracker");
        }
        assert_eq!(
            tracker.register(
                PathId(MAX_TRACKED_PATHS as u64 + 1),
                TransportLifecycle::Stopped,
            ),
            Err(PathHealthError::CapacityReached)
        );
    }
}
