//! Safe Ed25519 adapters and reviewed lower-layer Noise session mechanics.
//!
//! Noise sessions do not authenticate a Lattice identity by themselves. Higher
//! layers must bind the completed transcript to separately pinned identity
//! keys before authorization; generated Noise static keys are not identity keys.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use thiserror::Error;
use zeroize::Zeroizing;

/// Errors returned by the Ed25519 adapter.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Ed25519Error {
    /// A supplied public key or signature has an invalid byte length.
    #[error("invalid {kind} length: expected {expected} bytes, got {actual}")]
    InvalidLength {
        /// Name of the malformed input.
        kind: &'static str,
        /// Required byte count.
        expected: usize,
        /// Supplied byte count.
        actual: usize,
    },
    /// The public-key bytes are not a valid Ed25519 point.
    #[error("invalid Ed25519 public key")]
    InvalidPublicKey,
    /// Signature verification failed.
    #[error("Ed25519 signature verification failed")]
    VerificationFailed,
}

/// Ed25519 signing key that deliberately does not implement `Debug` or serialization.
pub struct Ed25519SigningKey(SigningKey);

impl Ed25519SigningKey {
    /// Constructs a signing key from a 32-byte secret seed.
    ///
    /// The caller is responsible for obtaining the seed from a cryptographically
    /// secure source and protecting it for its lifetime.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let seed = Zeroizing::new(seed);
        Self(SigningKey::from_bytes(&seed))
    }

    /// Returns the corresponding 32-byte public verification key.
    #[must_use]
    pub fn verifying_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    /// Signs a message and returns its 64-byte Ed25519 signature.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(message).to_bytes()
    }
}

/// Verifies an Ed25519 signature using exact-length byte inputs.
///
/// Public key and signature inputs with malformed lengths are rejected before
/// conversion. This function does not confer authorization or identity trust.
///
/// # Errors
///
/// Returns `Ed25519Error` when either input length is invalid, the public key
/// encoding is invalid, or signature verification fails.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Ed25519Error> {
    let public_key: &[u8; 32] = public_key
        .try_into()
        .map_err(|_| Ed25519Error::InvalidLength {
            kind: "public key",
            expected: 32,
            actual: public_key.len(),
        })?;
    let signature: &[u8; 64] = signature
        .try_into()
        .map_err(|_| Ed25519Error::InvalidLength {
            kind: "signature",
            expected: 64,
            actual: signature.len(),
        })?;
    let public_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| Ed25519Error::InvalidPublicKey)?;
    public_key
        .verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| Ed25519Error::VerificationFailed)
}

mod noise_session {
    use snow::HandshakeState as SnowHandshakeState;
    use thiserror::Error;
    use zeroize::Zeroizing;

    /// Exact Noise protocol name used by every session.
    pub const NOISE_PROTOCOL_NAME: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
    /// Maximum size of a Noise handshake packet, in bytes.
    pub const MAX_NOISE_PACKET_SIZE: usize = 65_535;
    /// Maximum size of the caller-supplied application prologue, in bytes.
    pub const MAX_NOISE_PROLOGUE_SIZE: usize = 4096;
    /// Maximum plaintext accepted by one Noise transport message.
    ///
    /// The corresponding ciphertext always fits in one maximum-size packet.
    pub const MAX_NOISE_TRANSPORT_MESSAGE_SIZE: usize = MAX_NOISE_PACKET_SIZE - 16;
    const MAX_XX_MESSAGE_OVERHEAD: usize = 96;

    /// The explicit local role in a Noise XX handshake.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum NoiseRole {
        /// Sends the first handshake message.
        Initiator,
        /// Receives the first handshake message.
        Responder,
    }

    /// The protocol step currently expected by a [`NoiseSession`].
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum NoiseHandshakeStep {
        /// Initiator must write message 1.
        InitiatorSendMessage1,
        /// Initiator must read message 2.
        InitiatorReadMessage2,
        /// Initiator must write message 3.
        InitiatorSendMessage3,
        /// Responder must read message 1.
        ResponderReadMessage1,
        /// Responder must write message 2.
        ResponderSendMessage2,
        /// Responder must read message 3.
        ResponderReadMessage3,
        /// The Noise handshake has completed.
        Finished,
        /// A malformed handshake message irreversibly failed this session.
        Failed,
    }

    impl NoiseHandshakeStep {
        const fn name(self) -> &'static str {
            match self {
                Self::InitiatorSendMessage1 => "initiator-send-message-1",
                Self::InitiatorReadMessage2 => "initiator-read-message-2",
                Self::InitiatorSendMessage3 => "initiator-send-message-3",
                Self::ResponderReadMessage1 => "responder-read-message-1",
                Self::ResponderSendMessage2 => "responder-send-message-2",
                Self::ResponderReadMessage3 => "responder-read-message-3",
                Self::Finished => "finished",
                Self::Failed => "failed",
            }
        }
    }

    /// Typed failures from constructing or advancing a Noise XX handshake.
    #[derive(Debug, Error, PartialEq, Eq)]
    pub enum NoiseSessionError {
        /// The prologue is empty or exceeds the configured bound.
        #[error("application prologue must be nonempty and at most {maximum} bytes (got {actual})")]
        InvalidPrologueLength {
            /// Supplied prologue length.
            actual: usize,
            /// Maximum supported prologue length.
            maximum: usize,
        },
        /// A packet or payload exceeds the supported bound.
        #[error("{kind} exceeds the {maximum}-byte limit (got {actual})")]
        PacketTooLarge {
            /// Whether the oversized value was an incoming packet or outgoing payload.
            kind: &'static str,
            /// Supplied size.
            actual: usize,
            /// Maximum supported size.
            maximum: usize,
        },
        /// The requested operation is not valid at the current handshake step.
        #[error("cannot {operation} while Noise handshake is at {state}")]
        InvalidState {
            /// Requested operation.
            operation: &'static str,
            /// Current handshake step.
            state: &'static str,
        },
        /// A peer message was malformed or failed Noise authentication.
        #[error("malformed or unauthenticated Noise handshake packet")]
        MalformedMessage,
        /// Snow could not initialize or advance the Noise handshake.
        #[error("Noise handshake operation failed")]
        HandshakeFailure,
        /// The handshake has not completed successfully.
        #[error("Noise handshake is not finished")]
        HandshakeNotFinished,
    }

    /// Local Noise static private bytes are kept in a non-formatting zeroizing
    /// wrapper and are never accepted from Lattice device identity keys.
    struct LocalStaticPrivate(Zeroizing<Vec<u8>>);

    impl LocalStaticPrivate {
        fn from_generated(bytes: Vec<u8>) -> Self {
            Self(Zeroizing::new(bytes))
        }

        fn as_bytes(&self) -> &[u8] {
            self.0.as_slice()
        }
    }

    /// Stateful, bounded Noise XX handshake. It deliberately has no `Debug`
    /// implementation so Snow's private handshake material cannot be formatted.
    pub struct NoiseSession {
        role: NoiseRole,
        step: NoiseHandshakeStep,
        handshake: Option<SnowHandshakeState>,
    }

    impl NoiseSession {
        /// Creates an initiator or responder using a byte-exact application
        /// prologue. The prologue MUST canonically bind the Lattice protocol
        /// version, negotiated capabilities, and rotating rendezvous token.
        /// Both peers must pass identical bytes. This constructor checks only
        /// the size and nonempty requirements; it does not parse that encoding.
        ///
        /// Noise generates a per-session X25519 static key with its configured
        /// cryptographic RNG. This key is not a Lattice identity key.
        ///
        /// # Errors
        /// Returns an error for an empty or oversized prologue, or if Snow
        /// cannot initialize the handshake.
        pub fn new(
            role: NoiseRole,
            application_prologue: &[u8],
        ) -> Result<Self, NoiseSessionError> {
            if application_prologue.is_empty()
                || application_prologue.len() > MAX_NOISE_PROLOGUE_SIZE
            {
                return Err(NoiseSessionError::InvalidPrologueLength {
                    actual: application_prologue.len(),
                    maximum: MAX_NOISE_PROLOGUE_SIZE,
                });
            }

            let params = NOISE_PROTOCOL_NAME
                .parse()
                .map_err(|_| NoiseSessionError::HandshakeFailure)?;
            let builder = snow::Builder::new(params);
            let generated = builder
                .generate_keypair()
                .map_err(|_| NoiseSessionError::HandshakeFailure)?;
            let local_static = LocalStaticPrivate::from_generated(generated.private);
            let builder = builder
                .local_private_key(local_static.as_bytes())
                .map_err(|_| NoiseSessionError::HandshakeFailure)?
                .prologue(application_prologue)
                .map_err(|_| NoiseSessionError::HandshakeFailure)?;
            let handshake = match role {
                NoiseRole::Initiator => builder.build_initiator(),
                NoiseRole::Responder => builder.build_responder(),
            }
            .map_err(|_| NoiseSessionError::HandshakeFailure)?;

            let step = match role {
                NoiseRole::Initiator => NoiseHandshakeStep::InitiatorSendMessage1,
                NoiseRole::Responder => NoiseHandshakeStep::ResponderReadMessage1,
            };

            Ok(Self {
                role,
                step,
                handshake: Some(handshake),
            })
        }

        /// Returns the explicit role selected at construction.
        #[must_use]
        pub const fn role(&self) -> NoiseRole {
            self.role
        }

        /// Returns the current monotonic handshake step.
        #[must_use]
        pub const fn step(&self) -> NoiseHandshakeStep {
            self.step
        }

        /// Writes the next handshake message with an optional Noise payload.
        ///
        /// Every resulting packet is at most [`MAX_NOISE_PACKET_SIZE`] bytes.
        /// The payload limit reserves the maximum overhead for this exact XX
        /// pattern, so Snow never receives an undersized output buffer.
        ///
        /// # Errors
        /// Returns [`NoiseSessionError::InvalidState`] unless this role must
        /// send next, [`NoiseSessionError::PacketTooLarge`] for an oversized
        /// payload, or [`NoiseSessionError::HandshakeFailure`] on an internal
        /// Snow failure.
        pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseSessionError> {
            let next_step = match self.step {
                NoiseHandshakeStep::InitiatorSendMessage1 => {
                    NoiseHandshakeStep::InitiatorReadMessage2
                }
                NoiseHandshakeStep::InitiatorSendMessage3 => NoiseHandshakeStep::Finished,
                NoiseHandshakeStep::ResponderSendMessage2 => {
                    NoiseHandshakeStep::ResponderReadMessage3
                }
                _ => {
                    return Err(NoiseSessionError::InvalidState {
                        operation: "write a message",
                        state: self.step.name(),
                    });
                }
            };

            let maximum_payload = MAX_NOISE_PACKET_SIZE - MAX_XX_MESSAGE_OVERHEAD;
            if payload.len() > maximum_payload {
                return Err(NoiseSessionError::PacketTooLarge {
                    kind: "outgoing payload",
                    actual: payload.len(),
                    maximum: maximum_payload,
                });
            }

            let mut message = vec![0_u8; MAX_NOISE_PACKET_SIZE];
            let result = match self.handshake.as_mut() {
                Some(handshake) => handshake.write_message(payload, &mut message),
                None => {
                    return Err(NoiseSessionError::InvalidState {
                        operation: "write a message",
                        state: self.step.name(),
                    });
                }
            };

            match result {
                Ok(message_length) if message_length <= MAX_NOISE_PACKET_SIZE => {
                    message.truncate(message_length);
                    self.step = next_step;
                    Ok(message)
                }
                Ok(_) | Err(_) => {
                    self.poison();
                    Err(NoiseSessionError::HandshakeFailure)
                }
            }
        }

        /// Reads the next peer handshake message and returns its decrypted
        /// Noise payload. Incoming packets and decrypted payload buffers are
        /// capped at [`MAX_NOISE_PACKET_SIZE`] bytes.
        ///
        /// Any malformed, unauthenticated, or oversized packet irreversibly
        /// fails and clears this session's handshake state.
        ///
        /// # Errors
        /// Returns [`NoiseSessionError::InvalidState`] unless this role must
        /// receive next, [`NoiseSessionError::PacketTooLarge`] for an oversized
        /// packet, or [`NoiseSessionError::MalformedMessage`] if Snow rejects
        /// the packet.
        pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, NoiseSessionError> {
            let next_step = match self.step {
                NoiseHandshakeStep::ResponderReadMessage1 => {
                    NoiseHandshakeStep::ResponderSendMessage2
                }
                NoiseHandshakeStep::InitiatorReadMessage2 => {
                    NoiseHandshakeStep::InitiatorSendMessage3
                }
                NoiseHandshakeStep::ResponderReadMessage3 => NoiseHandshakeStep::Finished,
                _ => {
                    return Err(NoiseSessionError::InvalidState {
                        operation: "read a message",
                        state: self.step.name(),
                    });
                }
            };

            if message.len() > MAX_NOISE_PACKET_SIZE {
                self.poison();
                return Err(NoiseSessionError::PacketTooLarge {
                    kind: "incoming packet",
                    actual: message.len(),
                    maximum: MAX_NOISE_PACKET_SIZE,
                });
            }
            let mut payload = vec![0_u8; MAX_NOISE_PACKET_SIZE];
            let result = match self.handshake.as_mut() {
                Some(handshake) => handshake.read_message(message, &mut payload),
                None => {
                    return Err(NoiseSessionError::InvalidState {
                        operation: "read a message",
                        state: self.step.name(),
                    });
                }
            };

            match result {
                Ok(payload_length) if payload_length <= MAX_NOISE_PACKET_SIZE => {
                    payload.truncate(payload_length);
                    self.step = next_step;
                    Ok(payload)
                }
                Ok(_) | Err(_) => {
                    self.poison();
                    Err(NoiseSessionError::MalformedMessage)
                }
            }
        }

        /// Consumes a completed handshake and exports the transcript hash and
        /// the peer's Noise static public key. The remote key is not an identity
        /// assertion; callers MUST compare or pin it using a separately
        /// reviewed identity-binding mechanism before trusting the peer.
        ///
        /// This intentionally does not expose a transport state or application
        /// content key.
        ///
        /// # Errors
        /// Returns [`NoiseSessionError::HandshakeNotFinished`] before the final
        /// handshake message has been successfully processed.
        pub fn finish(mut self) -> Result<EstablishedNoiseSession, NoiseSessionError> {
            if self.step != NoiseHandshakeStep::Finished {
                return Err(NoiseSessionError::HandshakeNotFinished);
            }

            let Some(handshake) = self.handshake.take() else {
                return Err(NoiseSessionError::HandshakeFailure);
            };
            if !handshake.is_handshake_finished() {
                return Err(NoiseSessionError::HandshakeFailure);
            }

            let remote_static_public_key: [u8; 32] = handshake
                .get_remote_static()
                .ok_or(NoiseSessionError::HandshakeFailure)?
                .try_into()
                .map_err(|_| NoiseSessionError::HandshakeFailure)?;
            let session_hash: [u8; 32] = handshake
                .get_handshake_hash()
                .try_into()
                .map_err(|_| NoiseSessionError::HandshakeFailure)?;

            Ok(EstablishedNoiseSession {
                remote_static_public_key,
                session_hash,
            })
        }

        /// Consumes a completed handshake and enters Noise transport mode.
        ///
        /// The resulting object retains Snow's directional cipher states and
        /// never exports traffic keys. Its monotonically increasing nonces
        /// reject replayed or out-of-order packets; callers must discard the
        /// session after any transport error.
        ///
        /// # Errors
        ///
        /// Returns [`NoiseSessionError::HandshakeNotFinished`] before the last
        /// handshake message, or [`NoiseSessionError::HandshakeFailure`] if
        /// Snow cannot create the transport state.
        pub fn finish_transport(
            mut self,
        ) -> Result<EstablishedNoiseTransportSession, NoiseSessionError> {
            if self.step != NoiseHandshakeStep::Finished {
                return Err(NoiseSessionError::HandshakeNotFinished);
            }

            let Some(handshake) = self.handshake.take() else {
                return Err(NoiseSessionError::HandshakeFailure);
            };
            if !handshake.is_handshake_finished() {
                return Err(NoiseSessionError::HandshakeFailure);
            }

            let remote_static_public_key: [u8; 32] = handshake
                .get_remote_static()
                .ok_or(NoiseSessionError::HandshakeFailure)?
                .try_into()
                .map_err(|_| NoiseSessionError::HandshakeFailure)?;
            let session_hash: [u8; 32] = handshake
                .get_handshake_hash()
                .try_into()
                .map_err(|_| NoiseSessionError::HandshakeFailure)?;
            let transport = handshake
                .into_transport_mode()
                .map_err(|_| NoiseSessionError::HandshakeFailure)?;

            Ok(EstablishedNoiseTransportSession {
                remote_static_public_key,
                session_hash,
                failed: false,
                transport,
            })
        }

        fn poison(&mut self) {
            self.handshake = None;
            self.step = NoiseHandshakeStep::Failed;
        }
    }

    /// Errors from one bounded Noise transport operation.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
    pub enum NoiseTransportError {
        /// The plaintext or ciphertext exceeds the one-message bound.
        #[error("Noise transport message exceeds its configured bound")]
        MessageTooLarge,
        /// A ciphertext is too short to contain a Noise authentication tag.
        #[error("Noise transport ciphertext is truncated")]
        TruncatedCiphertext,
        /// Encryption failed; the caller must discard this session.
        #[error("Noise transport encryption failed")]
        EncryptionFailed,
        /// Authentication/decryption failed; the caller must discard this session.
        #[error("Noise transport authentication failed")]
        AuthenticationFailed,
        /// The transport session previously failed and is unusable.
        #[error("Noise transport session is failed")]
        SessionFailed,
    }

    /// A completed Noise transport channel with private directional cipher state.
    ///
    /// The type deliberately has no `Debug`, `Clone`, or serialization
    /// implementation, and never exposes content keys. A packet can be opened
    /// only once at the expected transport nonce.
    pub struct EstablishedNoiseTransportSession {
        remote_static_public_key: [u8; 32],
        session_hash: [u8; 32],
        transport: snow::TransportState,
        failed: bool,
    }

    impl EstablishedNoiseTransportSession {
        /// Returns the remote Noise static public key. It is not an identity
        /// assertion unless separately bound to a pinned Lattice identity.
        #[must_use]
        pub const fn remote_static_public_key(&self) -> &[u8; 32] {
            &self.remote_static_public_key
        }

        /// Returns the completed Noise handshake hash for application binding.
        #[must_use]
        pub const fn session_hash(&self) -> &[u8; 32] {
            &self.session_hash
        }

        /// Encrypts one bounded plaintext using the next directional nonce.
        ///
        /// The returned ciphertext is authenticated but is not, by itself,
        /// authenticated as any Lattice identity.
        ///
        /// # Errors
        ///
        /// Returns [`NoiseTransportError::MessageTooLarge`] when plaintext
        /// exceeds the one-message bound, or an opaque Snow encryption error.
        pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseTransportError> {
            if self.failed {
                return Err(NoiseTransportError::SessionFailed);
            }
            if plaintext.len() > MAX_NOISE_TRANSPORT_MESSAGE_SIZE {
                return Err(NoiseTransportError::MessageTooLarge);
            }
            let output_len = plaintext
                .len()
                .checked_add(16)
                .ok_or(NoiseTransportError::MessageTooLarge)?;
            let mut ciphertext = vec![0_u8; output_len];
            let Ok(written) = self.transport.write_message(plaintext, &mut ciphertext) else {
                self.failed = true;
                return Err(NoiseTransportError::EncryptionFailed);
            };
            ciphertext.truncate(written);
            Ok(ciphertext)
        }

        /// Authenticates and decrypts one packet at the next directional nonce.
        ///
        /// A replayed, reordered, truncated, or modified packet fails. The
        /// caller must discard this session after any error.
        ///
        /// # Errors
        ///
        /// Returns an error when ciphertext is malformed, over the bound, or
        /// fails Noise authentication.
        pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseTransportError> {
            if self.failed {
                return Err(NoiseTransportError::SessionFailed);
            }
            if ciphertext.len() > MAX_NOISE_PACKET_SIZE {
                self.failed = true;
                return Err(NoiseTransportError::MessageTooLarge);
            }
            if ciphertext.len() < 16 {
                self.failed = true;
                return Err(NoiseTransportError::TruncatedCiphertext);
            }
            let mut plaintext = vec![0_u8; ciphertext.len() - 16];
            let Ok(written) = self.transport.read_message(ciphertext, &mut plaintext) else {
                self.failed = true;
                return Err(NoiseTransportError::AuthenticationFailed);
            };
            plaintext.truncate(written);
            Ok(plaintext)
        }
    }

    /// Public transcript outputs from a completed Noise XX handshake.
    ///
    /// This structure deliberately has no `Debug` implementation. Its values
    /// are public transcript material, but the distinction reduces accidental
    /// logging of future or adjacent secret fields.
    pub struct EstablishedNoiseSession {
        remote_static_public_key: [u8; 32],
        session_hash: [u8; 32],
    }

    impl EstablishedNoiseSession {
        /// Returns the remote Noise static public key. It is not an identity
        /// key unless a separately reviewed binding and pin check says so.
        #[must_use]
        pub const fn remote_static_public_key(&self) -> &[u8; 32] {
            &self.remote_static_public_key
        }

        /// Returns the Noise handshake hash for channel binding.
        #[must_use]
        pub const fn session_hash(&self) -> &[u8; 32] {
            &self.session_hash
        }
    }
}

pub use noise_session::{
    EstablishedNoiseSession, EstablishedNoiseTransportSession, MAX_NOISE_PACKET_SIZE,
    MAX_NOISE_PROLOGUE_SIZE, MAX_NOISE_TRANSPORT_MESSAGE_SIZE, NOISE_PROTOCOL_NAME,
    NoiseHandshakeStep, NoiseRole, NoiseSession, NoiseSessionError, NoiseTransportError,
};

#[cfg(test)]
mod noise_session_tests {
    use super::{
        EstablishedNoiseSession, EstablishedNoiseTransportSession, MAX_NOISE_PACKET_SIZE,
        MAX_NOISE_PROLOGUE_SIZE, NoiseHandshakeStep, NoiseRole, NoiseSession, NoiseSessionError,
        NoiseTransportError,
    };
    const PROLOGUE: &[u8] = b"lattice/v1\0capabilities:sync+files\0rendezvous:rotating-token-01";

    fn complete_handshake(
        initiator_prologue: &[u8],
        responder_prologue: &[u8],
    ) -> (EstablishedNoiseSession, EstablishedNoiseSession) {
        let mut initiator = NoiseSession::new(NoiseRole::Initiator, initiator_prologue).unwrap();
        let mut responder = NoiseSession::new(NoiseRole::Responder, responder_prologue).unwrap();

        let message1 = initiator.write_message(b"initiator payload").unwrap();
        assert_eq!(
            responder.read_message(&message1).unwrap().as_slice(),
            b"initiator payload"
        );
        let message2 = responder.write_message(b"responder payload").unwrap();
        assert_eq!(
            initiator.read_message(&message2).unwrap().as_slice(),
            b"responder payload"
        );
        let message3 = initiator.write_message(b"final payload").unwrap();
        assert_eq!(
            responder.read_message(&message3).unwrap().as_slice(),
            b"final payload"
        );

        (initiator.finish().unwrap(), responder.finish().unwrap())
    }

    #[test]
    fn peers_complete_xx_and_share_session_hash() {
        let (initiator, responder) = complete_handshake(PROLOGUE, PROLOGUE);
        assert_eq!(initiator.session_hash(), responder.session_hash());
        assert_ne!(initiator.remote_static_public_key(), &[0_u8; 32]);
        assert_ne!(responder.remote_static_public_key(), &[0_u8; 32]);
    }

    #[test]
    fn transcript_tampering_and_prologue_mismatch_are_rejected() {
        let mut initiator = NoiseSession::new(NoiseRole::Initiator, PROLOGUE).unwrap();
        let mut responder = NoiseSession::new(NoiseRole::Responder, PROLOGUE).unwrap();
        let message1 = initiator.write_message(b"").unwrap();
        responder.read_message(&message1).unwrap();
        let mut message2 = responder.write_message(b"").unwrap();
        let last = message2.len() - 1;
        message2[last] ^= 1;
        assert_eq!(
            initiator.read_message(&message2),
            Err(NoiseSessionError::MalformedMessage)
        );
        assert_eq!(initiator.step(), NoiseHandshakeStep::Failed);

        for mismatched_prologue in [
            b"lattice/v2\0capabilities:sync+files\0rendezvous:rotating-token-01".as_slice(),
            b"lattice/v1\0capabilities:sync\0rendezvous:rotating-token-01".as_slice(),
            b"lattice/v1\0capabilities:sync+files\0rendezvous:rotating-token-02".as_slice(),
        ] {
            let mut initiator = NoiseSession::new(NoiseRole::Initiator, PROLOGUE).unwrap();
            let mut responder =
                NoiseSession::new(NoiseRole::Responder, mismatched_prologue).unwrap();
            let message1 = initiator.write_message(b"").unwrap();
            responder.read_message(&message1).unwrap();
            let message2 = responder.write_message(b"").unwrap();
            assert_eq!(
                initiator.read_message(&message2),
                Err(NoiseSessionError::MalformedMessage)
            );
        }
    }

    #[test]
    fn wrong_order_replay_and_invalid_packets_fail() {
        let mut initiator = NoiseSession::new(NoiseRole::Initiator, PROLOGUE).unwrap();
        let mut responder = NoiseSession::new(NoiseRole::Responder, PROLOGUE).unwrap();
        assert!(matches!(
            initiator.read_message(b"unexpected"),
            Err(NoiseSessionError::InvalidState { .. })
        ));

        let message1 = initiator.write_message(b"").unwrap();
        responder.read_message(&message1).unwrap();
        assert!(matches!(
            responder.read_message(&message1),
            Err(NoiseSessionError::InvalidState { .. })
        ));

        let mut malformed = NoiseSession::new(NoiseRole::Responder, PROLOGUE).unwrap();
        assert_eq!(
            malformed.read_message(b""),
            Err(NoiseSessionError::MalformedMessage)
        );
        assert_eq!(malformed.step(), NoiseHandshakeStep::Failed);
    }

    #[test]
    fn prologue_and_packet_sizes_are_bounded() {
        assert!(matches!(
            NoiseSession::new(NoiseRole::Initiator, b""),
            Err(NoiseSessionError::InvalidPrologueLength {
                actual: 0,
                maximum: MAX_NOISE_PROLOGUE_SIZE,
            })
        ));
        let oversized_prologue = vec![0_u8; MAX_NOISE_PROLOGUE_SIZE + 1];
        assert!(matches!(
            NoiseSession::new(NoiseRole::Initiator, &oversized_prologue),
            Err(NoiseSessionError::InvalidPrologueLength { .. })
        ));

        let mut initiator = NoiseSession::new(NoiseRole::Initiator, PROLOGUE).unwrap();
        assert!(matches!(
            initiator.write_message(&vec![0_u8; MAX_NOISE_PACKET_SIZE]),
            Err(NoiseSessionError::PacketTooLarge { .. })
        ));

        let mut responder = NoiseSession::new(NoiseRole::Responder, PROLOGUE).unwrap();
        let oversized_packet = vec![0_u8; MAX_NOISE_PACKET_SIZE + 1];
        assert!(matches!(
            responder.read_message(&oversized_packet),
            Err(NoiseSessionError::PacketTooLarge { .. })
        ));
        assert_eq!(responder.step(), NoiseHandshakeStep::Failed);
        assert!(matches!(
            responder.read_message(b""),
            Err(NoiseSessionError::InvalidState { .. })
        ));
    }
    fn complete_transport_handshake() -> (
        EstablishedNoiseTransportSession,
        EstablishedNoiseTransportSession,
    ) {
        let mut initiator = NoiseSession::new(NoiseRole::Initiator, PROLOGUE).unwrap();
        let mut responder = NoiseSession::new(NoiseRole::Responder, PROLOGUE).unwrap();
        let message1 = initiator.write_message(b"").unwrap();
        responder.read_message(&message1).unwrap();
        let message2 = responder.write_message(b"").unwrap();
        initiator.read_message(&message2).unwrap();
        let message3 = initiator.write_message(b"").unwrap();
        responder.read_message(&message3).unwrap();
        (
            initiator.finish_transport().unwrap(),
            responder.finish_transport().unwrap(),
        )
    }

    #[test]
    fn transport_state_encrypts_and_poison_fails_closed_on_tamper_or_replay() {
        let (mut initiator, mut responder) = complete_transport_handshake();
        let ciphertext = initiator.encrypt(b"scoped sync request").unwrap();
        assert_eq!(
            responder.decrypt(&ciphertext).unwrap(),
            b"scoped sync request"
        );
        assert_eq!(
            responder.decrypt(&ciphertext),
            Err(NoiseTransportError::AuthenticationFailed)
        );
        assert_eq!(
            responder.decrypt(&ciphertext),
            Err(NoiseTransportError::SessionFailed)
        );

        let (mut initiator, mut responder) = complete_transport_handshake();
        let mut tampered = initiator.encrypt(b"scoped sync response").unwrap();
        tampered[0] ^= 1;
        assert_eq!(
            responder.decrypt(&tampered),
            Err(NoiseTransportError::AuthenticationFailed)
        );
        assert_eq!(
            responder.decrypt(&tampered),
            Err(NoiseTransportError::SessionFailed)
        );
    }
}
