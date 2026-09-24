//! Deterministic path selection and bounded forwarding policy.
//!
//! This crate chooses transport paths and accounts for opaque-envelope forwarding
//! budgets. It does not create, validate, decrypt, or deliver events.

use std::cmp::Reverse;
use std::collections::{BTreeSet, VecDeque};
use std::error::Error;
use std::fmt;

pub const CRATE_NAME: &str = "lattice-router";
pub const MAX_LOSS_PER_MILLE: u16 = 1_000;
pub const MAX_ROUTING_CANDIDATES: usize = 64;
pub const MAX_ROUTE_FANOUT: u8 = 8;
pub const MAX_HOP_BUDGET: u8 = 32;
pub const MAX_COPY_BUDGET: u8 = 32;
pub const MAX_ENVELOPE_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_FORWARDING_EXPIRY_SECONDS: u64 = 30 * 24 * 60 * 60;
pub const MAX_EVENT_DEDUPLICATION_CAPACITY: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct PathId(pub u64);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct EventId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct EnvelopeId(pub [u8; 16]);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub enum TrafficClass {
    SecurityDependency,
    InteractiveText,
    History,
    Files,
    Presence,
    Voice,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub enum PathKind {
    Ble,
    Lan,
    WifiAware,
    WifiDirect,
    InternetRelay,
    Courier,
}

impl PathKind {
    const fn is_ip(self) -> bool {
        matches!(
            self,
            Self::Lan | Self::WifiAware | Self::WifiDirect | Self::InternetRelay
        )
    }

    const fn is_internet(self) -> bool {
        matches!(self, Self::InternetRelay)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub enum NetworkScope {
    Local,
    Internet,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub enum EnergyCost {
    Low,
    Moderate,
    High,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
// Each field independently advertises a supported routing capability.
#[allow(clippy::struct_excessive_bools)]
pub struct PathCapabilities {
    pub security_dependencies: bool,
    pub interactive_text: bool,
    pub history: bool,
    pub files: bool,
    pub presence: bool,
    pub voice: bool,
    pub bulk_transfer: bool,
    pub realtime_media: bool,
}

impl PathCapabilities {
    #[must_use]
    pub const fn supports(self, class: TrafficClass) -> bool {
        match class {
            TrafficClass::SecurityDependency => self.security_dependencies,
            TrafficClass::InteractiveText => self.interactive_text,
            TrafficClass::History => self.history,
            TrafficClass::Files => self.files,
            TrafficClass::Presence => self.presence,
            TrafficClass::Voice => self.voice,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathCandidate {
    pub id: PathId,
    pub kind: PathKind,
    pub network_scope: NetworkScope,
    pub capabilities: PathCapabilities,
    pub mtu_bytes: u64,
    pub max_payload_bytes: u64,
    pub reachable: bool,
    pub metered: bool,
    pub energy_cost: EnergyCost,
    pub rtt_ms: Option<u32>,
    pub loss_per_mille: u16,
    pub queued_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoutingPolicy {
    pub allow_internet_routes: bool,
    pub allow_metered: bool,
    pub max_energy_cost: EnergyCost,
    pub max_rtt_ms: Option<u32>,
    pub max_loss_per_mille: u16,
    pub max_queue_bytes: u64,
    pub max_envelope_bytes: u64,
    pub max_candidates: usize,
    pub max_fanout: u8,
    pub max_hops: u8,
    pub max_copies: u8,
    pub max_expiry_seconds: u64,
    pub allow_ble_bulk: bool,
    pub max_ble_bulk_bytes: u64,
}

impl Default for RoutingPolicy {
    fn default() -> Self {
        Self {
            allow_internet_routes: false,
            allow_metered: false,
            max_energy_cost: EnergyCost::Moderate,
            max_rtt_ms: None,
            max_loss_per_mille: MAX_LOSS_PER_MILLE,
            max_queue_bytes: u64::MAX,
            max_envelope_bytes: 1_048_576,
            max_candidates: 32,
            max_fanout: 1,
            max_hops: 8,
            max_copies: 8,
            max_expiry_seconds: 7 * 24 * 60 * 60,
            allow_ble_bulk: false,
            max_ble_bulk_bytes: 64 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForwardingEnvelope {
    /// Stable event identity supplied by the event layer; envelope identity may change.
    pub event_id: EventId,
    pub envelope_id: EnvelopeId,
    pub payload_bytes: u64,
    pub hops_used: u8,
    pub hop_limit: u8,
    pub copies_remaining: u8,
    pub expires_at_unix_seconds: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForwardingCounters {
    pub hops_used: u8,
    pub copies_remaining: u8,
    pub expires_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutePlan {
    /// Candidate identifiers only. This is not a transport receipt or delivery claim.
    pub paths: Vec<PathId>,
    pub counters: ForwardingCounters,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SuppressionReason {
    Expired,
    ExpiryExceedsPolicy,
    PayloadExceedsPolicy,
    HopLimitReached,
    CopyBudgetExhausted,
    CopyBudgetExceedsPolicy,
    FanoutDisabled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RoutingOutcome {
    Forward(RoutePlan),
    NoViablePath,
    Suppressed(SuppressionReason),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RoutingError {
    InvalidPolicy,
    TooManyCandidates {
        supplied: usize,
        maximum: usize,
    },
    DuplicatePathId {
        path_id: PathId,
    },
    InvalidPathLoss {
        path_id: PathId,
        loss_per_mille: u16,
    },
    CounterOverflow,
    ZeroDeduplicationCapacity,
    DeduplicationCapacityExceedsMaximum {
        supplied: usize,
        maximum: usize,
    },
}

impl fmt::Display for RoutingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy => f.write_str("invalid routing policy"),
            Self::TooManyCandidates { supplied, maximum } => {
                write!(f, "{supplied} path candidates exceed maximum {maximum}")
            }
            Self::DuplicatePathId { path_id } => {
                write!(f, "duplicate path identifier {}", path_id.0)
            }
            Self::InvalidPathLoss {
                path_id,
                loss_per_mille,
            } => write!(
                f,
                "path {} has invalid loss value {loss_per_mille} per mille",
                path_id.0
            ),
            Self::CounterOverflow => f.write_str("forwarding counter overflow"),
            Self::ZeroDeduplicationCapacity => {
                f.write_str("event deduplication capacity must be nonzero")
            }
            Self::DeduplicationCapacityExceedsMaximum { supplied, maximum } => write!(
                f,
                "event deduplication capacity {supplied} exceeds maximum {maximum}"
            ),
        }
    }
}

impl Error for RoutingError {}

/// Selects viable routes for one opaque envelope without performing transport work.
///
/// # Errors
///
/// Returns `RoutingError` for an invalid policy or candidate list.
pub fn plan_forward(
    class: TrafficClass,
    envelope: &ForwardingEnvelope,
    now_unix_seconds: u64,
    candidates: &[PathCandidate],
    policy: &RoutingPolicy,
) -> Result<RoutingOutcome, RoutingError> {
    validate_inputs(candidates, policy)?;

    if envelope.payload_bytes > policy.max_envelope_bytes {
        return Ok(RoutingOutcome::Suppressed(
            SuppressionReason::PayloadExceedsPolicy,
        ));
    }

    let Some(lifetime) = envelope
        .expires_at_unix_seconds
        .checked_sub(now_unix_seconds)
    else {
        return Ok(RoutingOutcome::Suppressed(SuppressionReason::Expired));
    };
    if lifetime == 0 {
        return Ok(RoutingOutcome::Suppressed(SuppressionReason::Expired));
    }
    if lifetime > policy.max_expiry_seconds {
        return Ok(RoutingOutcome::Suppressed(
            SuppressionReason::ExpiryExceedsPolicy,
        ));
    }

    if envelope.copies_remaining > policy.max_copies {
        return Ok(RoutingOutcome::Suppressed(
            SuppressionReason::CopyBudgetExceedsPolicy,
        ));
    }
    if envelope.copies_remaining == 0 {
        return Ok(RoutingOutcome::Suppressed(
            SuppressionReason::CopyBudgetExhausted,
        ));
    }
    if policy.max_fanout == 0 {
        return Ok(RoutingOutcome::Suppressed(
            SuppressionReason::FanoutDisabled,
        ));
    }

    let Some(next_hops_used) = envelope.hops_used.checked_add(1) else {
        return Err(RoutingError::CounterOverflow);
    };
    if next_hops_used > envelope.hop_limit.min(policy.max_hops) {
        return Ok(RoutingOutcome::Suppressed(
            SuppressionReason::HopLimitReached,
        ));
    }

    let mut viable: Vec<&PathCandidate> = candidates
        .iter()
        .filter(|candidate| is_viable(class, envelope.payload_bytes, candidate, policy))
        .collect();
    viable.sort_by(|left, right| compare_paths(class, left, right));

    if viable.is_empty() {
        return Ok(RoutingOutcome::NoViablePath);
    }

    let fanout = usize::from(policy.max_fanout.min(envelope.copies_remaining));
    let paths: Vec<PathId> = viable
        .into_iter()
        .take(fanout)
        .map(|candidate| candidate.id)
        .collect();
    let copies_used = u8::try_from(paths.len()).map_err(|_| RoutingError::CounterOverflow)?;
    let copies_remaining = envelope
        .copies_remaining
        .checked_sub(copies_used)
        .ok_or(RoutingError::CounterOverflow)?;

    Ok(RoutingOutcome::Forward(RoutePlan {
        paths,
        counters: ForwardingCounters {
            hops_used: next_hops_used,
            copies_remaining,
            expires_at_unix_seconds: envelope.expires_at_unix_seconds,
        },
    }))
}

fn validate_inputs(
    candidates: &[PathCandidate],
    policy: &RoutingPolicy,
) -> Result<(), RoutingError> {
    if policy.max_candidates == 0
        || policy.max_candidates > MAX_ROUTING_CANDIDATES
        || policy.max_fanout > MAX_ROUTE_FANOUT
        || policy.max_hops > MAX_HOP_BUDGET
        || policy.max_copies > MAX_COPY_BUDGET
        || policy.max_loss_per_mille > MAX_LOSS_PER_MILLE
        || policy.max_envelope_bytes > MAX_ENVELOPE_BYTES
        || policy.max_expiry_seconds > MAX_FORWARDING_EXPIRY_SECONDS
        || policy.max_ble_bulk_bytes > MAX_ENVELOPE_BYTES
    {
        return Err(RoutingError::InvalidPolicy);
    }
    if candidates.len() > policy.max_candidates {
        return Err(RoutingError::TooManyCandidates {
            supplied: candidates.len(),
            maximum: policy.max_candidates,
        });
    }

    let mut path_ids = BTreeSet::new();
    for candidate in candidates {
        if candidate.loss_per_mille > MAX_LOSS_PER_MILLE {
            return Err(RoutingError::InvalidPathLoss {
                path_id: candidate.id,
                loss_per_mille: candidate.loss_per_mille,
            });
        }
        if !path_ids.insert(candidate.id) {
            return Err(RoutingError::DuplicatePathId {
                path_id: candidate.id,
            });
        }
    }
    Ok(())
}

fn is_viable(
    class: TrafficClass,
    payload_bytes: u64,
    candidate: &PathCandidate,
    policy: &RoutingPolicy,
) -> bool {
    if !candidate.reachable || !candidate.capabilities.supports(class) {
        return false;
    }
    if (candidate.network_scope == NetworkScope::Internet || candidate.kind.is_internet())
        && !policy.allow_internet_routes
    {
        return false;
    }
    if candidate.metered && !policy.allow_metered {
        return false;
    }
    if candidate.energy_cost > policy.max_energy_cost
        || candidate.loss_per_mille > policy.max_loss_per_mille
        || candidate.queued_bytes > policy.max_queue_bytes
    {
        return false;
    }
    if let Some(max_rtt_ms) = policy.max_rtt_ms
        && candidate.rtt_ms.is_none_or(|rtt| rtt > max_rtt_ms)
    {
        return false;
    }
    if payload_bytes > candidate.mtu_bytes.min(candidate.max_payload_bytes) {
        return false;
    }
    if class == TrafficClass::Voice
        && (!candidate.kind.is_ip() || !candidate.capabilities.realtime_media)
    {
        return false;
    }
    if matches!(class, TrafficClass::History | TrafficClass::Files) {
        if !candidate.capabilities.bulk_transfer {
            return false;
        }
        if candidate.kind == PathKind::Ble
            && (!policy.allow_ble_bulk || payload_bytes > policy.max_ble_bulk_bytes)
        {
            return false;
        }
    }
    true
}

fn compare_paths(
    class: TrafficClass,
    left: &PathCandidate,
    right: &PathCandidate,
) -> std::cmp::Ordering {
    let left_rtt = left.rtt_ms.unwrap_or(u32::MAX);
    let right_rtt = right.rtt_ms.unwrap_or(u32::MAX);
    let left_capacity = left.mtu_bytes.min(left.max_payload_bytes);
    let right_capacity = right.mtu_bytes.min(right.max_payload_bytes);
    let left_carrier_rank = carrier_rank(class, left.kind);
    let right_carrier_rank = carrier_rank(class, right.kind);

    if class == TrafficClass::Voice {
        (
            left_rtt,
            left.loss_per_mille,
            left.queued_bytes,
            left_carrier_rank,
            left.energy_cost,
            left.id,
        )
            .cmp(&(
                right_rtt,
                right.loss_per_mille,
                right.queued_bytes,
                right_carrier_rank,
                right.energy_cost,
                right.id,
            ))
    } else if matches!(class, TrafficClass::History | TrafficClass::Files) {
        (
            left_carrier_rank,
            Reverse(left_capacity),
            left.queued_bytes,
            left_rtt,
            left.loss_per_mille,
            left.energy_cost,
            left.id,
        )
            .cmp(&(
                right_carrier_rank,
                Reverse(right_capacity),
                right.queued_bytes,
                right_rtt,
                right.loss_per_mille,
                right.energy_cost,
                right.id,
            ))
    } else {
        (
            left_carrier_rank,
            left_rtt,
            left.loss_per_mille,
            left.queued_bytes,
            left.energy_cost,
            left.id,
        )
            .cmp(&(
                right_carrier_rank,
                right_rtt,
                right.loss_per_mille,
                right.queued_bytes,
                right.energy_cost,
                right.id,
            ))
    }
}

const fn carrier_rank(class: TrafficClass, kind: PathKind) -> u8 {
    match class {
        TrafficClass::History | TrafficClass::Files => match kind {
            PathKind::Lan | PathKind::WifiAware | PathKind::WifiDirect => 0,
            PathKind::InternetRelay => 1,
            PathKind::Courier => 2,
            PathKind::Ble => 3,
        },
        TrafficClass::Voice => match kind {
            PathKind::Lan | PathKind::WifiAware | PathKind::WifiDirect => 0,
            PathKind::InternetRelay => 1,
            PathKind::Ble | PathKind::Courier => 2,
        },
        TrafficClass::SecurityDependency
        | TrafficClass::InteractiveText
        | TrafficClass::Presence => match kind {
            PathKind::Lan | PathKind::WifiAware | PathKind::WifiDirect => 0,
            PathKind::Ble => 1,
            PathKind::InternetRelay => 2,
            PathKind::Courier => 3,
        },
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeduplicationOutcome {
    FirstSeen { evicted: Option<EventId> },
    Duplicate,
}

/// Bounded event-identity cache. Re-enveloping an event does not make it new.
#[derive(Debug)]
pub struct EventDeduplicator {
    capacity: usize,
    order: VecDeque<EventId>,
    seen: BTreeSet<EventId>,
}

impl EventDeduplicator {
    ///
    /// # Errors
    ///
    /// Returns `ZeroDeduplicationCapacity` for zero or
    /// `DeduplicationCapacityExceedsMaximum` above the configured maximum.
    pub fn new(capacity: usize) -> Result<Self, RoutingError> {
        if capacity == 0 {
            return Err(RoutingError::ZeroDeduplicationCapacity);
        }
        if capacity > MAX_EVENT_DEDUPLICATION_CAPACITY {
            return Err(RoutingError::DeduplicationCapacityExceedsMaximum {
                supplied: capacity,
                maximum: MAX_EVENT_DEDUPLICATION_CAPACITY,
            });
        }
        Ok(Self {
            capacity,
            order: VecDeque::with_capacity(capacity),
            seen: BTreeSet::new(),
        })
    }

    pub fn observe(&mut self, event_id: EventId) -> DeduplicationOutcome {
        if self.seen.contains(&event_id) {
            return DeduplicationOutcome::Duplicate;
        }

        let evicted = if self.order.len() == self.capacity {
            let oldest = self.order.pop_front();
            if let Some(oldest) = oldest {
                self.seen.remove(&oldest);
            }
            oldest
        } else {
            None
        };
        self.order.push_back(event_id);
        self.seen.insert(event_id);
        DeduplicationOutcome::FirstSeen { evicted }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capabilities(class: TrafficClass) -> PathCapabilities {
        let mut capabilities = PathCapabilities::default();
        match class {
            TrafficClass::SecurityDependency => capabilities.security_dependencies = true,
            TrafficClass::InteractiveText => capabilities.interactive_text = true,
            TrafficClass::History => {
                capabilities.history = true;
                capabilities.bulk_transfer = true;
            }
            TrafficClass::Files => {
                capabilities.files = true;
                capabilities.bulk_transfer = true;
            }
            TrafficClass::Presence => capabilities.presence = true,
            TrafficClass::Voice => {
                capabilities.voice = true;
                capabilities.realtime_media = true;
            }
        }
        capabilities
    }

    fn path(
        id: u64,
        kind: PathKind,
        scope: NetworkScope,
        class: TrafficClass,
        payload_limit: u64,
        rtt_ms: Option<u32>,
    ) -> PathCandidate {
        PathCandidate {
            id: PathId(id),
            kind,
            network_scope: scope,
            capabilities: capabilities(class),
            mtu_bytes: payload_limit,
            max_payload_bytes: payload_limit,
            reachable: true,
            metered: false,
            energy_cost: EnergyCost::Low,
            rtt_ms,
            loss_per_mille: 0,
            queued_bytes: 0,
        }
    }

    fn envelope(payload_bytes: u64) -> ForwardingEnvelope {
        ForwardingEnvelope {
            event_id: EventId([1; 32]),
            envelope_id: EnvelopeId([2; 16]),
            payload_bytes,
            hops_used: 0,
            hop_limit: 4,
            copies_remaining: 4,
            expires_at_unix_seconds: 1_000,
        }
    }

    fn selected(outcome: RoutingOutcome) -> Vec<PathId> {
        match outcome {
            RoutingOutcome::Forward(plan) => plan.paths,
            other => panic!("expected a forwarding plan, got {other:?}"),
        }
    }

    #[test]
    fn voice_uses_viable_ip_path_and_never_ble() {
        let ble = path(
            1,
            PathKind::Ble,
            NetworkScope::Local,
            TrafficClass::Voice,
            4_096,
            Some(1),
        );
        let slow_ip = path(
            2,
            PathKind::Lan,
            NetworkScope::Local,
            TrafficClass::Voice,
            64_000,
            Some(80),
        );
        let fast_ip = path(
            3,
            PathKind::WifiAware,
            NetworkScope::Local,
            TrafficClass::Voice,
            64_000,
            Some(20),
        );

        assert_eq!(
            selected(
                plan_forward(
                    TrafficClass::Voice,
                    &envelope(1_200),
                    900,
                    &[ble, slow_ip, fast_ip],
                    &RoutingPolicy::default(),
                )
                .unwrap()
            ),
            vec![PathId(3)]
        );
    }

    #[test]
    fn oversized_bulk_uses_faster_path_instead_of_ble() {
        let ble = path(
            1,
            PathKind::Ble,
            NetworkScope::Local,
            TrafficClass::Files,
            64 * 1024,
            Some(10),
        );
        let ip = path(
            2,
            PathKind::Lan,
            NetworkScope::Local,
            TrafficClass::Files,
            2 * 1024 * 1024,
            Some(30),
        );
        let mut policy = RoutingPolicy {
            allow_ble_bulk: true,
            ..RoutingPolicy::default()
        };
        policy.max_envelope_bytes = 2 * 1024 * 1024;
        let outcome = plan_forward(
            TrafficClass::Files,
            &envelope(256 * 1024),
            900,
            &[ble, ip],
            &policy,
        )
        .unwrap();

        assert_eq!(selected(outcome), vec![PathId(2)]);
    }

    #[test]
    fn internet_relay_is_not_selected_when_internet_is_disabled() {
        let relay = path(
            1,
            PathKind::InternetRelay,
            NetworkScope::Internet,
            TrafficClass::InteractiveText,
            8_192,
            Some(40),
        );
        let direct = path(
            2,
            PathKind::Ble,
            NetworkScope::Local,
            TrafficClass::InteractiveText,
            2_048,
            Some(60),
        );
        let outcome = plan_forward(
            TrafficClass::InteractiveText,
            &envelope(100),
            900,
            &[relay, direct],
            &RoutingPolicy::default(),
        )
        .unwrap();

        assert_eq!(selected(outcome), vec![PathId(2)]);
    }

    #[test]
    fn unreachable_only_path_has_explicit_no_route_outcome() {
        let mut unreachable = path(
            1,
            PathKind::Lan,
            NetworkScope::Local,
            TrafficClass::InteractiveText,
            8_192,
            Some(10),
        );
        unreachable.reachable = false;

        assert_eq!(
            plan_forward(
                TrafficClass::InteractiveText,
                &envelope(100),
                900,
                &[unreachable],
                &RoutingPolicy::default(),
            )
            .unwrap(),
            RoutingOutcome::NoViablePath
        );
    }

    #[test]
    fn event_deduplication_ignores_envelope_identity() {
        let mut deduplicator = EventDeduplicator::new(4).unwrap();
        let first = envelope(100);
        let re_enveloped = ForwardingEnvelope {
            envelope_id: EnvelopeId([9; 16]),
            ..first
        };

        assert_ne!(first.envelope_id, re_enveloped.envelope_id);
        assert_eq!(first.event_id, re_enveloped.event_id);
        assert_eq!(
            deduplicator.observe(first.event_id),
            DeduplicationOutcome::FirstSeen { evicted: None }
        );
        assert_eq!(
            deduplicator.observe(re_enveloped.event_id),
            DeduplicationOutcome::Duplicate
        );
    }

    #[test]
    fn fanout_is_limited_by_policy_and_copy_budget() {
        let paths = [
            path(
                1,
                PathKind::Lan,
                NetworkScope::Local,
                TrafficClass::InteractiveText,
                8_192,
                Some(10),
            ),
            path(
                2,
                PathKind::WifiAware,
                NetworkScope::Local,
                TrafficClass::InteractiveText,
                8_192,
                Some(20),
            ),
            path(
                3,
                PathKind::WifiDirect,
                NetworkScope::Local,
                TrafficClass::InteractiveText,
                8_192,
                Some(30),
            ),
        ];
        let envelope = ForwardingEnvelope {
            copies_remaining: 2,
            ..envelope(100)
        };
        let policy = RoutingPolicy {
            max_fanout: 3,
            ..RoutingPolicy::default()
        };
        let outcome = plan_forward(
            TrafficClass::InteractiveText,
            &envelope,
            900,
            &paths,
            &policy,
        )
        .unwrap();

        match outcome {
            RoutingOutcome::Forward(plan) => {
                assert_eq!(plan.paths, vec![PathId(1), PathId(2)]);
                assert_eq!(plan.counters.copies_remaining, 0);
                assert_eq!(plan.counters.hops_used, 1);
                assert_eq!(plan.counters.expires_at_unix_seconds, 1_000);
            }
            other => panic!("expected a forwarding plan, got {other:?}"),
        }
    }

    #[test]
    fn hop_expiry_and_copy_limits_produce_explicit_suppressions() {
        let candidate = path(
            1,
            PathKind::Lan,
            NetworkScope::Local,
            TrafficClass::InteractiveText,
            8_192,
            Some(10),
        );
        let policy = RoutingPolicy::default();

        let at_hop_limit = ForwardingEnvelope {
            hops_used: 4,
            ..envelope(100)
        };
        assert_eq!(
            plan_forward(
                TrafficClass::InteractiveText,
                &at_hop_limit,
                900,
                &[candidate],
                &policy,
            )
            .unwrap(),
            RoutingOutcome::Suppressed(SuppressionReason::HopLimitReached)
        );

        let expired = ForwardingEnvelope {
            expires_at_unix_seconds: 900,
            ..envelope(100)
        };
        assert_eq!(
            plan_forward(
                TrafficClass::InteractiveText,
                &expired,
                900,
                &[candidate],
                &policy,
            )
            .unwrap(),
            RoutingOutcome::Suppressed(SuppressionReason::Expired)
        );

        let exhausted = ForwardingEnvelope {
            copies_remaining: 0,
            ..envelope(100)
        };
        assert_eq!(
            plan_forward(
                TrafficClass::InteractiveText,
                &exhausted,
                900,
                &[candidate],
                &policy,
            )
            .unwrap(),
            RoutingOutcome::Suppressed(SuppressionReason::CopyBudgetExhausted)
        );
    }

    #[test]
    fn path_payload_and_resource_constraints_are_enforced() {
        let mut metered = path(
            1,
            PathKind::Lan,
            NetworkScope::Local,
            TrafficClass::InteractiveText,
            8_192,
            Some(10),
        );
        metered.metered = true;
        let too_small = path(
            2,
            PathKind::WifiAware,
            NetworkScope::Local,
            TrafficClass::InteractiveText,
            99,
            Some(5),
        );
        let high_loss = PathCandidate {
            loss_per_mille: 600,
            ..path(
                3,
                PathKind::WifiDirect,
                NetworkScope::Local,
                TrafficClass::InteractiveText,
                8_192,
                Some(5),
            )
        };
        let policy = RoutingPolicy {
            max_loss_per_mille: 500,
            ..RoutingPolicy::default()
        };

        assert_eq!(
            plan_forward(
                TrafficClass::InteractiveText,
                &envelope(100),
                900,
                &[metered, too_small, high_loss],
                &policy,
            )
            .unwrap(),
            RoutingOutcome::NoViablePath
        );
    }
}
