//! Pure Rust voice-room signaling state.
//!
//! This crate does not perform network I/O, authenticate peers, parse SDP/ICE, or
//! implement WebRTC or media. `SignalingConnected` records only a caller-reported
//! signaling transition; it must never be presented as an established media path.
//! Permission values are explicit caller-provided policy inputs, not proof of
//! membership, identity, or peer authorization.

use std::error::Error;
use std::fmt;
use std::time::Duration;

pub const CRATE_NAME: &str = "lattice-voice";

/// Maximum UTF-8 byte length of a room identifier.
pub const MAX_ROOM_ID_BYTES: usize = 256;
/// Maximum UTF-8 byte length of one offer or answer.
pub const MAX_SDP_BYTES: usize = 16 * 1024;
/// Maximum UTF-8 byte length of one ICE candidate string.
pub const MAX_CANDIDATE_BYTES: usize = 1024;
/// Maximum number of candidate strings accepted by one session.
pub const MAX_CANDIDATES: usize = 64;

/// A fresh random identifier for one room-session incarnation.
///
/// Create sessions with [`VoiceSession::new`], which obtains this value from the
/// operating-system cryptographic random source. The byte conversion methods are
/// intended for carrying the opaque identifier through an external signaling
/// protocol; they do not validate peer authorization.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SessionIncarnation([u8; 16]);

impl SessionIncarnation {
    /// Reconstructs an opaque incarnation value from its exact 16-byte form.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the exact 16-byte incarnation value.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Caller-supplied policy decisions for a voice operation.
///
/// These booleans are inputs to local state transitions only. They do not
/// authenticate a caller or establish that a remote peer is authorized.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VoicePermissions {
    /// The caller's current policy permits joining this room.
    pub can_join: bool,
    /// The caller's current policy permits speaking in this room.
    pub can_speak: bool,
}

impl VoicePermissions {
    /// Constructs explicit join and speak policy inputs.
    #[must_use]
    pub const fn new(can_join: bool, can_speak: bool) -> Self {
        Self {
            can_join,
            can_speak,
        }
    }
}

/// Signaling-only state of a voice session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VoiceState {
    /// The session incarnation exists but has not joined.
    Requested,
    /// Join permission was supplied and the local state joined the room.
    Joined,
    /// A local offer string was accepted by the bounded signaling state machine.
    OfferSent,
    /// A remote offer string was accepted by the bounded signaling state machine.
    OfferReceived,
    /// A remote answer string was accepted by the bounded signaling state machine.
    AnswerReceived,
    /// A local answer string was accepted by the bounded signaling state machine.
    AnswerSent,
    /// At least one candidate string was accepted after an answer.
    CandidateExchanged,
    /// Signaling was reported complete by the caller. This is not media-connected.
    SignalingConnected,
    /// The session was explicitly left.
    Left,
    /// The injected monotonic time reached the session deadline.
    TimedOut,
    /// The caller reported a terminal failure; this does not assert media behavior.
    Failed(VoiceFailure),
}

/// A caller-reported reason for ending a voice-session attempt.
///
/// These values preserve the reason supplied by a policy or platform/media
/// adapter. They are not proof that a network path or media engine behaved in
/// any particular way.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VoiceFailure {
    /// Current Space policy no longer permits joining the room.
    PermissionRevoked(VoicePermission),
    /// No eligible direct or locally allowed relay path was reported.
    NoUsablePath,
    /// The ICE implementation reported that candidate checks failed.
    IceFailed,
    /// Direct ICE failed and policy did not permit a configured TURN route.
    TurnRequired,
    /// The platform reported that microphone capture is unavailable.
    MicrophoneUnavailable,
    /// The remote participant left the session.
    PeerLeft,
    /// The platform interrupted the call because of application lifecycle state.
    BackgroundInterrupted,
}

/// Media capability represented by this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MediaStatus {
    /// No media engine is implemented or controlled by this crate.
    NotImplemented,
}

/// A permission gate that denied an operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VoicePermission {
    /// Joining or continuing signaling requires voice-join permission.
    Join,
    /// Requesting the speaking capability requires voice-speak permission.
    Speak,
}

/// Failure from a voice signaling operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VoiceError {
    /// The operating system did not provide random bytes for a new incarnation.
    RandomSourceUnavailable,
    /// The room identifier was empty, too long, or contained a control character.
    InvalidRoomId,
    /// A session lifetime must be nonzero and representable at its start time.
    InvalidLifetime,
    /// The supplied incarnation did not match this room session.
    StaleIncarnation,
    /// The supplied caller policy denied the requested capability.
    PermissionDenied(VoicePermission),
    /// A sequence number below the next expected number was replayed.
    SequenceReplay { expected: u64, received: u64 },
    /// A sequence number above the next expected number was out of order.
    SequenceOutOfOrder { expected: u64, received: u64 },
    /// The sequence space cannot safely advance further.
    SequenceExhausted,
    /// The requested operation is not valid in the current state.
    InvalidTransition(VoiceState),
    /// An offer or answer exceeded the configured byte bound.
    SdpTooLong { max: usize, actual: usize },
    /// An offer or answer was empty or contained invalid line/control characters.
    InvalidSdp,
    /// A candidate exceeded the configured byte bound.
    CandidateTooLong { max: usize, actual: usize },
    /// A candidate was empty or contained a control character.
    InvalidCandidate,
    /// The per-session candidate limit has been reached.
    TooManyCandidates,
    /// Injected monotonic time moved backwards.
    ClockRegressed,
    /// The session deadline was reached.
    SessionExpired,
    /// The session was already left or timed out.
    SessionEnded,
}

impl fmt::Display for VoiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RandomSourceUnavailable => f.write_str("random source unavailable"),
            Self::InvalidRoomId => f.write_str("invalid room identifier"),
            Self::InvalidLifetime => f.write_str("invalid voice session lifetime"),
            Self::StaleIncarnation => f.write_str("stale voice session incarnation"),
            Self::PermissionDenied(permission) => {
                write!(f, "voice permission denied: {permission:?}")
            }
            Self::SequenceReplay { expected, received } => {
                write!(
                    f,
                    "voice sequence replay: expected {expected}, got {received}"
                )
            }
            Self::SequenceOutOfOrder { expected, received } => {
                write!(
                    f,
                    "voice sequence out of order: expected {expected}, got {received}"
                )
            }
            Self::SequenceExhausted => f.write_str("voice sequence exhausted"),
            Self::InvalidTransition(state) => {
                write!(f, "invalid voice transition from {state:?}")
            }
            Self::SdpTooLong { max, actual } => {
                write!(f, "SDP is too long: maximum {max} bytes, got {actual}")
            }
            Self::InvalidSdp => f.write_str("invalid SDP line or control characters"),
            Self::CandidateTooLong { max, actual } => {
                write!(
                    f,
                    "candidate is too long: maximum {max} bytes, got {actual}"
                )
            }
            Self::InvalidCandidate => f.write_str("invalid ICE candidate string"),
            Self::TooManyCandidates => f.write_str("voice candidate limit reached"),
            Self::ClockRegressed => f.write_str("monotonic voice clock moved backwards"),
            Self::SessionExpired => f.write_str("voice session expired"),
            Self::SessionEnded => f.write_str("voice session has ended"),
        }
    }
}

impl Error for VoiceError {}

/// A bounded, caller-clocked signaling state machine for one room incarnation.
///
/// Every session gets a cryptographically random 128-bit incarnation at
/// construction. The caller supplies all timestamps and current permission
/// decisions. This type does not retain SDP/candidate contents, parse markup, send
/// signaling, or operate a media engine.
pub struct VoiceSession {
    room_id: String,
    incarnation: SessionIncarnation,
    state: VoiceState,
    deadline: Duration,
    last_observed_time: Duration,
    next_sequence: u64,
    candidate_count: usize,
}

impl VoiceSession {
    /// Creates a new requested session with a fresh random 128-bit incarnation.
    ///
    /// `now` is an injected monotonic timestamp, such as elapsed time from a
    /// process-local clock origin. No clock is read by this crate.
    ///
    /// # Errors
    ///
    /// Returns `VoiceError` for an invalid room ID or lifetime, time overflow,
    /// or unavailable randomness.
    pub fn new(room_id: &str, now: Duration, lifetime: Duration) -> Result<Self, VoiceError> {
        if room_id.is_empty()
            || room_id.len() > MAX_ROOM_ID_BYTES
            || room_id.chars().any(char::is_control)
        {
            return Err(VoiceError::InvalidRoomId);
        }
        if lifetime.is_zero() {
            return Err(VoiceError::InvalidLifetime);
        }
        let deadline = now
            .checked_add(lifetime)
            .ok_or(VoiceError::InvalidLifetime)?;
        let mut incarnation = [0_u8; 16];
        getrandom::fill(&mut incarnation).map_err(|_| VoiceError::RandomSourceUnavailable)?;

        Ok(Self {
            room_id: room_id.to_owned(),
            incarnation: SessionIncarnation(incarnation),
            state: VoiceState::Requested,
            deadline,
            last_observed_time: now,
            next_sequence: 1,
            candidate_count: 0,
        })
    }

    /// Returns the room identifier bound to this session.
    #[must_use]
    pub fn room_id(&self) -> &str {
        &self.room_id
    }

    /// Returns the session's opaque 128-bit incarnation.
    #[must_use]
    pub const fn incarnation(&self) -> SessionIncarnation {
        self.incarnation
    }

    /// Returns the current signaling state.
    #[must_use]
    pub const fn state(&self) -> VoiceState {
        self.state
    }

    /// Returns the next exact control sequence number required by this session.
    #[must_use]
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Returns the injected-time deadline for this session.
    #[must_use]
    pub const fn deadline(&self) -> Duration {
        self.deadline
    }

    /// Reports the media capability of this crate without implying a media path.
    #[must_use]
    pub const fn media_status(&self) -> MediaStatus {
        MediaStatus::NotImplemented
    }

    /// Joins the session after checking the current caller-provided join policy.
    ///
    /// # Errors
    ///
    /// Returns `VoiceError` if the session, permission, sequence, or state
    /// transition is invalid.
    pub fn join(
        &mut self,
        incarnation: SessionIncarnation,
        sequence: u64,
        now: Duration,
        permissions: VoicePermissions,
    ) -> Result<(), VoiceError> {
        self.check_control(incarnation, sequence, now, permissions, true)?;
        self.require_state(VoiceState::Requested)?;
        self.commit_control(VoiceState::Joined)
    }

    /// Accepts a bounded offer string as signaling input.
    ///
    /// SDP is only checked for size and safe line structure. It is neither parsed
    /// nor interpreted as markup, and accepting it does not establish a connection.
    ///
    /// # Errors
    ///
    /// Returns `VoiceError` if the session, permission, sequence, current
    /// state, or bounded SDP is invalid.
    pub fn send_offer(
        &mut self,
        incarnation: SessionIncarnation,
        sequence: u64,
        now: Duration,
        permissions: VoicePermissions,
        sdp: &str,
    ) -> Result<(), VoiceError> {
        self.check_control(incarnation, sequence, now, permissions, true)?;
        self.require_state(VoiceState::Joined)?;
        validate_sdp(sdp)?;
        self.commit_control(VoiceState::OfferSent)
    }

    /// Accepts a bounded remote offer string as signaling input.
    ///
    /// This is the answerer's counterpart to [`send_offer`]. The SDP is checked
    /// only for size and safe line structure; it is not parsed or authenticated.
    /// Accepting it does not establish a connection.
    ///
    /// # Errors
    ///
    /// Returns `VoiceError` if the session, permission, sequence, current
    /// state, or bounded SDP is invalid.
    pub fn receive_offer(
        &mut self,
        incarnation: SessionIncarnation,
        sequence: u64,
        now: Duration,
        permissions: VoicePermissions,
        sdp: &str,
    ) -> Result<(), VoiceError> {
        self.check_control(incarnation, sequence, now, permissions, true)?;
        self.require_state(VoiceState::Joined)?;
        validate_sdp(sdp)?;
        self.commit_control(VoiceState::OfferReceived)
    }

    /// Accepts a bounded local answer string after [`receive_offer`].
    ///
    /// This records signaling input only; it does not create or configure a
    /// WebRTC peer connection.
    ///
    /// # Errors
    ///
    /// Returns `VoiceError` if the session, permission, sequence, current
    /// state, or bounded SDP is invalid.
    pub fn send_answer(
        &mut self,
        incarnation: SessionIncarnation,
        sequence: u64,
        now: Duration,
        permissions: VoicePermissions,
        sdp: &str,
    ) -> Result<(), VoiceError> {
        self.check_control(incarnation, sequence, now, permissions, true)?;
        self.require_state(VoiceState::OfferReceived)?;
        validate_sdp(sdp)?;
        self.commit_control(VoiceState::AnswerSent)
    }

    /// Accepts a bounded answer string as signaling input.
    ///
    /// # Errors
    ///
    /// Returns `VoiceError` if the session, permission, sequence, current
    /// state, or bounded SDP is invalid.
    pub fn receive_answer(
        &mut self,
        incarnation: SessionIncarnation,
        sequence: u64,
        now: Duration,
        permissions: VoicePermissions,
        sdp: &str,
    ) -> Result<(), VoiceError> {
        self.check_control(incarnation, sequence, now, permissions, true)?;
        self.require_state(VoiceState::OfferSent)?;
        validate_sdp(sdp)?;
        self.commit_control(VoiceState::AnswerReceived)
    }

    /// Accepts one bounded ICE candidate string after an answer.
    ///
    /// Candidate text is kept opaque: the state machine does not parse, resolve,
    /// or connect to addresses contained in it.
    ///
    /// # Errors
    ///
    /// Returns `VoiceError` if the session, permission, sequence, state,
    /// candidate count, or candidate string is invalid.
    pub fn add_candidate(
        &mut self,
        incarnation: SessionIncarnation,
        sequence: u64,
        now: Duration,
        permissions: VoicePermissions,
        candidate: &str,
    ) -> Result<(), VoiceError> {
        self.check_control(incarnation, sequence, now, permissions, true)?;
        if !matches!(
            self.state,
            VoiceState::AnswerReceived | VoiceState::AnswerSent | VoiceState::CandidateExchanged
        ) {
            return Err(VoiceError::InvalidTransition(self.state));
        }
        validate_candidate(candidate)?;
        if self.candidate_count >= MAX_CANDIDATES {
            return Err(VoiceError::TooManyCandidates);
        }
        self.commit_sequence()?;
        self.candidate_count += 1;
        self.state = VoiceState::CandidateExchanged;
        Ok(())
    }

    /// Records completion of signaling, not establishment of media connectivity.
    ///
    /// # Errors
    ///
    /// Returns `VoiceError` if the session, permission, sequence, or state
    /// transition is invalid.
    pub fn mark_signaling_connected(
        &mut self,
        incarnation: SessionIncarnation,
        sequence: u64,
        now: Duration,
        permissions: VoicePermissions,
    ) -> Result<(), VoiceError> {
        self.check_control(incarnation, sequence, now, permissions, true)?;
        if !matches!(
            self.state,
            VoiceState::AnswerReceived | VoiceState::AnswerSent | VoiceState::CandidateExchanged
        ) {
            return Err(VoiceError::InvalidTransition(self.state));
        }
        self.commit_control(VoiceState::SignalingConnected)
    }

    /// Records a caller-reported terminal failure without implying media success.
    ///
    /// Failure reports and cleanup remain allowed after permission revocation.
    /// `reason` is supplied by the caller; this crate does not probe routes,
    /// permissions, microphone availability, or media state itself.
    ///
    /// # Errors
    ///
    /// Returns `VoiceError` if the session, sequence, or timestamp is invalid.
    pub fn fail(
        &mut self,
        incarnation: SessionIncarnation,
        sequence: u64,
        now: Duration,
        permissions: VoicePermissions,
        reason: VoiceFailure,
    ) -> Result<(), VoiceError> {
        self.check_control(incarnation, sequence, now, permissions, false)?;
        self.commit_control(VoiceState::Failed(reason))
    }

    /// Checks join and speak policy before a caller requests speaking capability.
    ///
    /// This is a policy check only. It does not capture audio, change media state,
    /// or grant a persistent permission lease.
    ///
    /// # Errors
    ///
    /// Returns `VoiceError` if the session has expired, its incarnation is
    /// wrong, or current join/speak permission is absent.
    pub fn authorize_speaking(
        &mut self,
        incarnation: SessionIncarnation,
        now: Duration,
        permissions: VoicePermissions,
    ) -> Result<(), VoiceError> {
        self.check_session(incarnation, now)?;
        if !permissions.can_join {
            return Err(VoiceError::PermissionDenied(VoicePermission::Join));
        }
        if !permissions.can_speak {
            return Err(VoiceError::PermissionDenied(VoicePermission::Speak));
        }
        if self.state == VoiceState::Requested {
            return Err(VoiceError::InvalidTransition(self.state));
        }
        Ok(())
    }

    /// Leaves an active session. Cleanup remains allowed after permission revocation.
    ///
    /// # Errors
    ///
    /// Returns `VoiceError` if the session, sequence, or timestamp is invalid.
    pub fn leave(
        &mut self,
        incarnation: SessionIncarnation,
        sequence: u64,
        now: Duration,
        permissions: VoicePermissions,
    ) -> Result<(), VoiceError> {
        self.check_control(incarnation, sequence, now, permissions, false)?;
        self.commit_control(VoiceState::Left)
    }

    /// Advances injected monotonic time and transitions to timeout at the deadline.
    ///
    /// # Errors
    ///
    /// Returns `ClockRegressed` when `now` is earlier than the last observed
    /// monotonic timestamp.
    pub fn advance_time(&mut self, now: Duration) -> Result<VoiceState, VoiceError> {
        if now < self.last_observed_time {
            return Err(VoiceError::ClockRegressed);
        }
        self.last_observed_time = now;
        if !matches!(
            self.state,
            VoiceState::Left | VoiceState::TimedOut | VoiceState::Failed(_)
        ) && now >= self.deadline
        {
            self.state = VoiceState::TimedOut;
        }
        Ok(self.state)
    }

    fn check_control(
        &mut self,
        incarnation: SessionIncarnation,
        sequence: u64,
        now: Duration,
        permissions: VoicePermissions,
        require_join: bool,
    ) -> Result<(), VoiceError> {
        self.check_session(incarnation, now)?;
        if require_join && !permissions.can_join {
            return Err(VoiceError::PermissionDenied(VoicePermission::Join));
        }
        if sequence < self.next_sequence {
            return Err(VoiceError::SequenceReplay {
                expected: self.next_sequence,
                received: sequence,
            });
        }
        if sequence > self.next_sequence {
            return Err(VoiceError::SequenceOutOfOrder {
                expected: self.next_sequence,
                received: sequence,
            });
        }
        self.next_sequence
            .checked_add(1)
            .ok_or(VoiceError::SequenceExhausted)?;
        Ok(())
    }

    fn check_session(
        &mut self,
        incarnation: SessionIncarnation,
        now: Duration,
    ) -> Result<(), VoiceError> {
        if now < self.last_observed_time {
            return Err(VoiceError::ClockRegressed);
        }
        self.last_observed_time = now;
        if !matches!(
            self.state,
            VoiceState::Left | VoiceState::TimedOut | VoiceState::Failed(_)
        ) && now >= self.deadline
        {
            self.state = VoiceState::TimedOut;
            return Err(VoiceError::SessionExpired);
        }
        if self.state == VoiceState::TimedOut {
            return Err(VoiceError::SessionExpired);
        }
        if matches!(self.state, VoiceState::Left | VoiceState::Failed(_)) {
            return Err(VoiceError::SessionEnded);
        }
        if incarnation != self.incarnation {
            return Err(VoiceError::StaleIncarnation);
        }
        Ok(())
    }

    fn require_state(&self, required: VoiceState) -> Result<(), VoiceError> {
        if self.state == required {
            Ok(())
        } else {
            Err(VoiceError::InvalidTransition(self.state))
        }
    }

    fn commit_control(&mut self, state: VoiceState) -> Result<(), VoiceError> {
        self.commit_sequence()?;
        self.state = state;
        Ok(())
    }

    fn commit_sequence(&mut self) -> Result<(), VoiceError> {
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(VoiceError::SequenceExhausted)?;
        Ok(())
    }
}

fn validate_sdp(sdp: &str) -> Result<(), VoiceError> {
    if sdp.is_empty() {
        return Err(VoiceError::InvalidSdp);
    }
    if sdp.len() > MAX_SDP_BYTES {
        return Err(VoiceError::SdpTooLong {
            max: MAX_SDP_BYTES,
            actual: sdp.len(),
        });
    }
    let mut chars = sdp.chars();
    while let Some(ch) = chars.next() {
        if ch == '\r' {
            if chars.next() != Some('\n') {
                return Err(VoiceError::InvalidSdp);
            }
        } else if ch.is_control() {
            // SDP's CRLF line separators are accepted above; all other controls,
            // including bare LF, are rejected.
            return Err(VoiceError::InvalidSdp);
        }
    }
    Ok(())
}

fn validate_candidate(candidate: &str) -> Result<(), VoiceError> {
    if candidate.is_empty() || candidate.chars().any(char::is_control) {
        return Err(VoiceError::InvalidCandidate);
    }
    if candidate.len() > MAX_CANDIDATE_BYTES {
        return Err(VoiceError::CandidateTooLong {
            max: MAX_CANDIDATE_BYTES,
            actual: candidate.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL: Duration = Duration::from_secs(30);
    const ALLOW_ALL: VoicePermissions = VoicePermissions::new(true, true);

    fn session() -> VoiceSession {
        VoiceSession::new("voice-room", Duration::ZERO, TTL).unwrap()
    }

    fn to_answered(session: &mut VoiceSession) {
        let incarnation = session.incarnation();
        session
            .join(incarnation, 1, Duration::from_secs(1), ALLOW_ALL)
            .unwrap();
        session
            .send_offer(
                incarnation,
                2,
                Duration::from_secs(2),
                ALLOW_ALL,
                "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n",
            )
            .unwrap();
        session
            .receive_answer(
                incarnation,
                3,
                Duration::from_secs(3),
                ALLOW_ALL,
                "v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\n",
            )
            .unwrap();
    }

    #[test]
    fn denied_role_cannot_join_or_request_speaking() {
        let mut session = session();
        let incarnation = session.incarnation();
        assert_eq!(
            session.join(
                incarnation,
                1,
                Duration::from_secs(1),
                VoicePermissions::new(false, false),
            ),
            Err(VoiceError::PermissionDenied(VoicePermission::Join))
        );
        assert_eq!(session.state(), VoiceState::Requested);
        assert_eq!(session.next_sequence(), 1);

        session
            .join(
                incarnation,
                1,
                Duration::from_secs(2),
                VoicePermissions::new(true, false),
            )
            .unwrap();
        assert_eq!(
            session.authorize_speaking(
                incarnation,
                Duration::from_secs(3),
                VoicePermissions::new(true, false),
            ),
            Err(VoiceError::PermissionDenied(VoicePermission::Speak))
        );
    }

    #[test]
    fn stale_incarnation_is_rejected_without_consuming_sequence() {
        let mut session = session();
        let stale = VoiceSession::new("voice-room", Duration::ZERO, TTL)
            .unwrap()
            .incarnation();
        assert_eq!(
            session.join(stale, 1, Duration::from_secs(1), ALLOW_ALL),
            Err(VoiceError::StaleIncarnation)
        );
        assert_eq!(session.next_sequence(), 1);
        assert_eq!(session.state(), VoiceState::Requested);
    }

    #[test]
    fn sequence_replay_and_out_of_order_controls_are_rejected() {
        let mut session = session();
        let incarnation = session.incarnation();
        assert_eq!(
            session.join(incarnation, 2, Duration::from_secs(1), ALLOW_ALL),
            Err(VoiceError::SequenceOutOfOrder {
                expected: 1,
                received: 2,
            })
        );
        session
            .join(incarnation, 1, Duration::from_secs(2), ALLOW_ALL)
            .unwrap();
        assert_eq!(
            session.join(incarnation, 1, Duration::from_secs(3), ALLOW_ALL),
            Err(VoiceError::SequenceReplay {
                expected: 2,
                received: 1,
            })
        );
    }

    #[test]
    fn signaling_limits_and_control_characters_are_enforced() {
        let mut session = session();
        let incarnation = session.incarnation();
        session
            .join(incarnation, 1, Duration::from_secs(1), ALLOW_ALL)
            .unwrap();
        assert_eq!(
            session.send_offer(
                incarnation,
                2,
                Duration::from_secs(2),
                ALLOW_ALL,
                &"x".repeat(MAX_SDP_BYTES + 1),
            ),
            Err(VoiceError::SdpTooLong {
                max: MAX_SDP_BYTES,
                actual: MAX_SDP_BYTES + 1,
            })
        );
        assert_eq!(
            session.send_offer(
                incarnation,
                2,
                Duration::from_secs(2),
                ALLOW_ALL,
                "v=0\nmalformed-line-ending",
            ),
            Err(VoiceError::InvalidSdp)
        );
        session
            .send_offer(
                incarnation,
                2,
                Duration::from_secs(2),
                ALLOW_ALL,
                "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n",
            )
            .unwrap();
        session
            .receive_answer(
                incarnation,
                3,
                Duration::from_secs(3),
                ALLOW_ALL,
                "v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\n",
            )
            .unwrap();
        assert_eq!(
            session.add_candidate(
                incarnation,
                4,
                Duration::from_secs(4),
                ALLOW_ALL,
                "candidate:1\r\n",
            ),
            Err(VoiceError::InvalidCandidate)
        );
        assert_eq!(
            session.add_candidate(
                incarnation,
                4,
                Duration::from_secs(4),
                ALLOW_ALL,
                &"x".repeat(MAX_CANDIDATE_BYTES + 1),
            ),
            Err(VoiceError::CandidateTooLong {
                max: MAX_CANDIDATE_BYTES,
                actual: MAX_CANDIDATE_BYTES + 1,
            })
        );
    }

    #[test]
    fn candidate_count_is_bounded_and_signaling_is_not_media() {
        let mut session = session();
        to_answered(&mut session);
        let incarnation = session.incarnation();
        for offset in 0..MAX_CANDIDATES {
            session
                .add_candidate(
                    incarnation,
                    4 + u64::try_from(offset).unwrap(),
                    Duration::from_secs(4),
                    ALLOW_ALL,
                    "candidate:1 1 UDP 1 192.0.2.1 10000 typ host",
                )
                .unwrap();
        }
        assert_eq!(
            session.add_candidate(
                incarnation,
                4 + u64::try_from(MAX_CANDIDATES).unwrap(),
                Duration::from_secs(4),
                ALLOW_ALL,
                "candidate:2 1 UDP 1 192.0.2.2 10001 typ host",
            ),
            Err(VoiceError::TooManyCandidates)
        );
        session
            .mark_signaling_connected(
                incarnation,
                4 + u64::try_from(MAX_CANDIDATES).unwrap(),
                Duration::from_secs(5),
                ALLOW_ALL,
            )
            .unwrap();
        assert_eq!(session.state(), VoiceState::SignalingConnected);
        assert_eq!(session.media_status(), MediaStatus::NotImplemented);
    }

    #[test]
    fn answerer_accepts_offer_and_answers_before_exchanging_candidates() {
        let mut session = session();
        let incarnation = session.incarnation();
        let mut stale_bytes = *incarnation.as_bytes();
        stale_bytes[0] ^= 1;
        let stale_incarnation = SessionIncarnation::from_bytes(stale_bytes);
        let offer = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n";
        let answer = "v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\n";
        session
            .join(incarnation, 1, Duration::from_secs(1), ALLOW_ALL)
            .unwrap();
        assert_eq!(
            session.receive_offer(
                stale_incarnation,
                2,
                Duration::from_secs(2),
                ALLOW_ALL,
                offer,
            ),
            Err(VoiceError::StaleIncarnation)
        );
        assert_eq!(session.next_sequence(), 2);
        assert_eq!(session.state(), VoiceState::Joined);
        assert_eq!(
            session.add_candidate(
                incarnation,
                2,
                Duration::from_secs(2),
                ALLOW_ALL,
                "candidate:1 1 UDP 1 192.0.2.1 10000 typ host",
            ),
            Err(VoiceError::InvalidTransition(VoiceState::Joined))
        );
        session
            .receive_offer(incarnation, 2, Duration::from_secs(2), ALLOW_ALL, offer)
            .unwrap();
        assert_eq!(session.state(), VoiceState::OfferReceived);
        assert_eq!(
            session.send_answer(
                stale_incarnation,
                3,
                Duration::from_secs(3),
                ALLOW_ALL,
                answer,
            ),
            Err(VoiceError::StaleIncarnation)
        );
        assert_eq!(session.next_sequence(), 3);
        session
            .send_answer(incarnation, 3, Duration::from_secs(3), ALLOW_ALL, answer)
            .unwrap();
        session
            .add_candidate(
                incarnation,
                4,
                Duration::from_secs(4),
                ALLOW_ALL,
                "candidate:1 1 UDP 1 192.0.2.1 10000 typ host",
            )
            .unwrap();
        session
            .mark_signaling_connected(incarnation, 5, Duration::from_secs(5), ALLOW_ALL)
            .unwrap();
        assert_eq!(session.state(), VoiceState::SignalingConnected);
        assert_eq!(session.media_status(), MediaStatus::NotImplemented);
    }

    #[test]
    fn caller_reported_failure_is_terminal_and_retains_its_reason() {
        let mut session = session();
        let incarnation = session.incarnation();
        session
            .join(incarnation, 1, Duration::from_secs(1), ALLOW_ALL)
            .unwrap();
        let failure = VoiceFailure::PermissionRevoked(VoicePermission::Join);
        session
            .fail(
                incarnation,
                2,
                Duration::from_secs(2),
                VoicePermissions::default(),
                failure,
            )
            .unwrap();
        assert_eq!(session.state(), VoiceState::Failed(failure));
        assert_eq!(
            session.authorize_speaking(incarnation, Duration::from_secs(3), ALLOW_ALL),
            Err(VoiceError::SessionEnded)
        );
        assert_eq!(
            session.advance_time(Duration::from_secs(30)),
            Ok(VoiceState::Failed(failure))
        );
    }

    #[test]
    fn leave_and_expiry_are_terminal_transitions() {
        let mut left = session();
        let incarnation = left.incarnation();
        left.join(incarnation, 1, Duration::from_secs(1), ALLOW_ALL)
            .unwrap();
        left.leave(
            incarnation,
            2,
            Duration::from_secs(2),
            VoicePermissions::default(),
        )
        .unwrap();
        assert_eq!(left.state(), VoiceState::Left);
        assert_eq!(
            left.advance_time(Duration::from_secs(3)),
            Ok(VoiceState::Left)
        );

        let mut expired =
            VoiceSession::new("voice-room", Duration::ZERO, Duration::from_secs(5)).unwrap();
        assert_eq!(
            expired.advance_time(Duration::from_secs(5)),
            Ok(VoiceState::TimedOut)
        );
        assert_eq!(
            expired.join(expired.incarnation(), 1, Duration::from_secs(5), ALLOW_ALL,),
            Err(VoiceError::SessionExpired)
        );
    }
}
