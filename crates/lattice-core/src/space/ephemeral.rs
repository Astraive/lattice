//! Bounded, process-local projection of authenticated presence and typing hints.
//!
//! These values are not Space events, message history, or delivery receipts.
//! Receivers start expiry from their own monotonic observation time; sender
//! wall clocks are never used to claim that a peer is globally online.

use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    time::{Duration, Instant},
};

use lattice_events::EventKind;
use lattice_protocol::{Value, decode_canonical, encode_canonical};

use crate::{
    MlsBoundEvent,
    space::{Fingerprint, GroupReference, SpaceId, SpaceReducer, active_member},
};

pub const MAX_EPHEMERAL_PAYLOAD_BYTES: usize = 64;
pub const MAX_EPHEMERAL_ENTRIES: usize = 8_192;
pub const MAX_PRESENCE_TTL: Duration = Duration::from_mins(1);
pub const MAX_TYPING_TTL: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EphemeralKind {
    Presence,
    Typing,
}

/// Active/clear update. `active` only means observed recently, never online
/// globally. Clear updates must have zero lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EphemeralUpdate {
    pub kind: EphemeralKind,
    pub active: bool,
    pub ttl: Duration,
}

impl EphemeralUpdate {
    /// Encode the canonical payload carried inside an MLS application message.
    ///
    /// # Errors
    ///
    /// Returns an error if the lifetime is invalid or canonical encoding fails.
    pub fn encode(self) -> Result<Vec<u8>, EphemeralError> {
        self.validate()?;
        let ttl_ms = u64::try_from(self.ttl.as_millis()).map_err(|_| EphemeralError::InvalidTtl)?;
        encode_canonical(&Value::Map(vec![
            (0, Value::Unsigned(1)),
            (
                1,
                Value::Unsigned(match self.kind {
                    EphemeralKind::Presence => 0,
                    EphemeralKind::Typing => 1,
                }),
            ),
            (2, Value::Bool(self.active)),
            (3, Value::Unsigned(ttl_ms)),
        ]))
        .map_err(|_| EphemeralError::InvalidPayload)
    }

    fn validate(self) -> Result<(), EphemeralError> {
        if !self.active {
            return if self.ttl.is_zero() {
                Ok(())
            } else {
                Err(EphemeralError::InvalidTtl)
            };
        }
        let maximum = match self.kind {
            EphemeralKind::Presence => MAX_PRESENCE_TTL,
            EphemeralKind::Typing => MAX_TYPING_TTL,
        };
        if self.ttl.is_zero() || self.ttl > maximum {
            return Err(EphemeralError::InvalidTtl);
        }
        Ok(())
    }

    fn decode(bytes: &[u8]) -> Result<Self, EphemeralError> {
        if bytes.len() > MAX_EPHEMERAL_PAYLOAD_BYTES {
            return Err(EphemeralError::InvalidPayload);
        }
        let Value::Map(fields) =
            decode_canonical(bytes).map_err(|_| EphemeralError::InvalidPayload)?
        else {
            return Err(EphemeralError::InvalidPayload);
        };
        if fields.len() != 4 || fields.iter().map(|(key, _)| *key).ne(0..4) {
            return Err(EphemeralError::InvalidPayload);
        }
        let kind = match fields[1].1 {
            Value::Unsigned(0) => EphemeralKind::Presence,
            Value::Unsigned(1) => EphemeralKind::Typing,
            _ => return Err(EphemeralError::InvalidPayload),
        };
        let Value::Bool(active) = fields[2].1 else {
            return Err(EphemeralError::InvalidPayload);
        };
        let Value::Unsigned(ttl_ms) = fields[3].1 else {
            return Err(EphemeralError::InvalidPayload);
        };
        let update = Self {
            kind,
            active,
            ttl: Duration::from_millis(ttl_ms),
        };
        update.validate()?;
        Ok(update)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EphemeralApplyResult {
    Applied,
    Duplicate,
    IgnoredStale,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct StateKey {
    space_id: SpaceId,
    group_reference: GroupReference,
    author: Fingerprint,
    kind: EphemeralKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Entry {
    sequence: u64,
    event_id: [u8; 32],
    active_until: Option<Instant>,
    watermark_until: Instant,
}

/// In-memory-only state for one or more Space generations.
#[derive(Clone, Debug, Default)]
pub struct EphemeralStateTable {
    entries: BTreeMap<StateKey, Entry>,
}

impl EphemeralStateTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept one exact MLS-authenticated ephemeral event for the reducer's
    /// current generation and an active member. No storage API is called.
    ///
    /// # Errors
    ///
    /// Returns an error if the event is malformed, belongs to another context,
    /// was authored by a non-member, or exceeds the in-memory capacity.
    pub fn apply(
        &mut self,
        reducer: &SpaceReducer,
        event: &MlsBoundEvent,
        observed_at: Instant,
    ) -> Result<EphemeralApplyResult, EphemeralError> {
        let policy = reducer.policy().ok_or(EphemeralError::MissingPolicy)?;
        let verified = event.event();
        if reducer.conflicted {
            return Err(EphemeralError::PolicyConflicted);
        }
        if verified.kind() != EventKind::Ephemeral
            || verified.channel_id().is_some()
            || !verified.parents().is_empty()
        {
            return Err(EphemeralError::InvalidEventShape);
        }
        if verified.space_id() != &policy.space_id {
            return Err(EphemeralError::WrongSpace);
        }
        if verified.mls_group_reference() != &policy.group_reference {
            return Err(EphemeralError::WrongGroup);
        }
        let author = *verified.author_fingerprint();
        if !active_member(policy, &author) {
            return Err(EphemeralError::UnauthorizedMember);
        }

        let update = EphemeralUpdate::decode(event.plaintext())?;
        let key = StateKey {
            space_id: policy.space_id,
            group_reference: policy.group_reference,
            author,
            kind: update.kind,
        };
        self.prune(observed_at);
        let sequence = verified.author_sequence();
        let event_id = *verified.event_id().as_bytes();
        if let Some(previous) = self.entries.get(&key) {
            if sequence < previous.sequence {
                return Ok(EphemeralApplyResult::IgnoredStale);
            }
            if sequence == previous.sequence {
                return if event_id == previous.event_id {
                    Ok(EphemeralApplyResult::Duplicate)
                } else {
                    Err(EphemeralError::SequenceEquivocation)
                };
            }
        } else if self.entries.len() >= MAX_EPHEMERAL_ENTRIES {
            return Err(EphemeralError::CapacityExceeded);
        }

        let active_until = if update.active {
            Some(
                observed_at
                    .checked_add(update.ttl)
                    .ok_or(EphemeralError::InvalidTtl)?,
            )
        } else {
            None
        };
        let watermark_until = observed_at
            .checked_add(MAX_PRESENCE_TTL)
            .ok_or(EphemeralError::InvalidTtl)?;
        self.entries.insert(
            key,
            Entry {
                sequence,
                event_id,
                active_until,
                watermark_until,
            },
        );
        Ok(EphemeralApplyResult::Applied)
    }

    /// Drop active values at TTL and replay watermarks after the maximum TTL.
    pub fn prune(&mut self, now: Instant) -> usize {
        let previous = self.entries.len();
        self.entries.retain(|_, entry| entry.watermark_until > now);
        previous - self.entries.len()
    }

    /// Return whether an active member's presence hint remains active.
    pub fn is_present(
        &mut self,
        reducer: &SpaceReducer,
        author: Fingerprint,
        now: Instant,
    ) -> bool {
        self.is_current_member_active(reducer, author, EphemeralKind::Presence, now)
    }

    /// Return whether an active member's typing hint remains active.
    pub fn is_typing(&mut self, reducer: &SpaceReducer, author: Fingerprint, now: Instant) -> bool {
        self.is_current_member_active(reducer, author, EphemeralKind::Typing, now)
    }

    fn is_current_member_active(
        &mut self,
        reducer: &SpaceReducer,
        author: Fingerprint,
        kind: EphemeralKind,
        now: Instant,
    ) -> bool {
        let Some(policy) = reducer.policy() else {
            return false;
        };
        if reducer.conflicted || !active_member(policy, &author) {
            return false;
        }
        self.is_active(policy.space_id, policy.group_reference, author, kind, now)
    }

    fn is_active(
        &mut self,
        space_id: SpaceId,
        group_reference: GroupReference,
        author: Fingerprint,
        kind: EphemeralKind,
        now: Instant,
    ) -> bool {
        self.prune(now);
        self.entries
            .get(&StateKey {
                space_id,
                group_reference,
                author,
                kind,
            })
            .is_some_and(|entry| entry.active_until.is_some_and(|expires| expires > now))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EphemeralError {
    InvalidPayload,
    InvalidTtl,
    MissingPolicy,
    PolicyConflicted,
    InvalidEventShape,
    WrongSpace,
    WrongGroup,
    UnauthorizedMember,
    SequenceEquivocation,
    CapacityExceeded,
}

impl fmt::Display for EphemeralError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidPayload => "invalid ephemeral state payload",
            Self::InvalidTtl => "ephemeral state lifetime is outside its allowed bound",
            Self::MissingPolicy => "ephemeral state requires an active Space policy",
            Self::PolicyConflicted => "ephemeral state is disabled for a conflicted policy",
            Self::InvalidEventShape => "ephemeral state event has an invalid kind or shape",
            Self::WrongSpace => "ephemeral state event belongs to another Space",
            Self::WrongGroup => "ephemeral state event belongs to another MLS generation",
            Self::UnauthorizedMember => "ephemeral state author is not an active Space member",
            Self::SequenceEquivocation => "ephemeral author sequence identifies different events",
            Self::CapacityExceeded => "ephemeral state capacity is exhausted",
        };
        formatter.write_str(message)
    }
}

impl Error for EphemeralError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_round_trips_and_enforces_class_specific_ttls() {
        let update = EphemeralUpdate {
            kind: EphemeralKind::Typing,
            active: true,
            ttl: Duration::from_secs(5),
        };
        assert_eq!(
            EphemeralUpdate::decode(&update.encode().unwrap()).unwrap(),
            update
        );
        assert_eq!(
            EphemeralUpdate {
                kind: EphemeralKind::Typing,
                active: true,
                ttl: MAX_TYPING_TTL + Duration::from_millis(1),
            }
            .encode(),
            Err(EphemeralError::InvalidTtl)
        );
        assert_eq!(
            EphemeralUpdate {
                kind: EphemeralKind::Presence,
                active: false,
                ttl: Duration::from_millis(1),
            }
            .encode(),
            Err(EphemeralError::InvalidTtl)
        );
    }

    #[test]
    fn hints_expire_and_clear_without_persisting_state() {
        let start = Instant::now();
        let key = StateKey {
            space_id: [1; 16],
            group_reference: [2; 32],
            author: [3; 32],
            kind: EphemeralKind::Presence,
        };
        let mut table = EphemeralStateTable::new();
        table.entries.insert(
            key,
            Entry {
                sequence: 1,
                event_id: [4; 32],
                active_until: Some(start + Duration::from_secs(1)),
                watermark_until: start + MAX_PRESENCE_TTL,
            },
        );
        assert!(table.is_active(
            key.space_id,
            key.group_reference,
            key.author,
            key.kind,
            start,
        ));
        assert!(!table.is_active(
            key.space_id,
            key.group_reference,
            key.author,
            key.kind,
            start + Duration::from_secs(1),
        ));
        assert_eq!(table.len(), 1, "short active TTL retains replay watermark");
        assert_eq!(table.prune(start + MAX_PRESENCE_TTL), 1);
        assert!(table.is_empty());
    }
}
