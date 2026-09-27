use std::sync::{Arc, Mutex, MutexGuard};

use lattice_crypto::{
    EstablishedNoiseTransportSession, NoiseHandshakeStep, NoiseRole, NoiseSession,
};
use lattice_identity::{BleExp0IdentitySignature, IdentityPublicBundle, verify_ble_exp0_signature};
use sha2::{Digest, Sha256};

use crate::{MobileClient, MobileError};

const PROLOGUE_DOMAIN: &[u8] = b"lattice:ble:exp0:noise-xx:v0\0";
const SERVICE_UUID_BYTES: [u8; 16] = [
    0x1c, 0x9a, 0x00, 0x00, 0x7d, 0x31, 0x4f, 0x6a, 0x9b, 0x43, 0x4c, 0x41, 0x54, 0x54, 0x49, 0x43,
];
const PROFILE_DISCRIMINATOR: u8 = 0;
const TOKEN_BYTES: usize = 9;
const IDENTITY_RECORD_BYTES: usize = 4 + 1 + 1 + 65 + 64;
const CONFIRMATION_RECORD_BYTES: usize = 4 + 1 + 1 + 64;
const MAX_GATT_VALUE_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum MobileBleRole {
    Initiator,
    Responder,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IdentityProofProgress {
    AwaitingResponderToken,
    Ready,
    LocalProofSent,
    PeerProofReceived,
    Complete,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfirmationProgress {
    NotStarted,
    InitiatorSent,
    ResponderReceived,
    ResponderWritePending,
    Authenticated,
    Failed,
}

/// Public peer identity and comparison string from a transcript-verified proof.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MobileBlePeerInfo {
    pub identity_bundle: Vec<u8>,
    pub fingerprint: Vec<u8>,
    pub safety_number: String,
    pub already_pinned: bool,
}

struct PeerIdentity {
    bundle: [u8; 65],
    fingerprint: [u8; 32],
    safety_number: String,
    already_pinned: bool,
}

struct BleSessionState {
    role: MobileBleRole,
    responder_token: [u8; TOKEN_BYTES],
    local_bundle: [u8; 65],
    local_fingerprint: [u8; 32],
    handshake: Option<NoiseSession>,
    transport: Option<EstablishedNoiseTransportSession>,
    handshake_hash: Option<[u8; 32]>,
    peer: Option<PeerIdentity>,
    identity_progress: IdentityProofProgress,
    confirmation_progress: ConfirmationProgress,
}

/// One exp0 connection's transcript-bound Noise and Lattice identity state.
///
/// It produces no private keys or Noise cipher keys. First-contact peers remain
/// blocked from application records until this device pins the verified peer
/// bundle after the user compares the session safety number.
#[derive(uniffi::Object)]
pub struct MobileBleSession {
    client: Arc<MobileClient>,
    state: Mutex<BleSessionState>,
}

#[uniffi::export]
impl MobileBleSession {
    /// Creates an exp0 Noise XX session using the observed responder token.
    ///
    /// The responder caller must pass its currently advertised token; the
    /// initiator caller must pass the exact token observed in Service Data.
    ///
    /// # Errors
    ///
    /// Returns `InvalidBleDiscoveryToken` for a token whose width is not nine
    /// bytes and `BleSessionFailed` if Core or Noise cannot initialize.
    #[uniffi::constructor]
    pub fn new(
        client: Arc<MobileClient>,
        role: MobileBleRole,
        responder_token: Vec<u8>,
    ) -> Result<Arc<Self>, MobileError> {
        let responder_token: [u8; TOKEN_BYTES] = responder_token
            .try_into()
            .map_err(|_| MobileError::InvalidBleDiscoveryToken)?;
        let identity = client.identity_info()?;
        let local_bundle: [u8; 65] = identity
            .public_bundle
            .try_into()
            .map_err(|_| MobileError::BleSessionFailed)?;
        let local_fingerprint: [u8; 32] = identity
            .fingerprint
            .try_into()
            .map_err(|_| MobileError::BleSessionFailed)?;
        let mut prologue = Vec::with_capacity(61);
        prologue.extend_from_slice(PROLOGUE_DOMAIN);
        prologue.extend_from_slice(&SERVICE_UUID_BYTES);
        prologue.push(PROFILE_DISCRIMINATOR);
        prologue.extend_from_slice(&[0; 6]);
        prologue.extend_from_slice(&responder_token);
        if prologue.len() != 61 {
            return Err(MobileError::BleSessionFailed);
        }
        let noise_role = match role {
            MobileBleRole::Initiator => NoiseRole::Initiator,
            MobileBleRole::Responder => NoiseRole::Responder,
        };
        let handshake =
            NoiseSession::new(noise_role, &prologue).map_err(|_| MobileError::BleSessionFailed)?;
        Ok(Arc::new(Self {
            client,
            state: Mutex::new(BleSessionState {
                role,
                responder_token,
                local_bundle,
                local_fingerprint,
                handshake: Some(handshake),
                transport: None,
                handshake_hash: None,
                peer: None,
                identity_progress: match role {
                    MobileBleRole::Initiator => IdentityProofProgress::Ready,
                    MobileBleRole::Responder => IdentityProofProgress::AwaitingResponderToken,
                },
                confirmation_progress: ConfirmationProgress::NotStarted,
            }),
        }))
    }

    /// Writes the next empty-payload Noise XX handshake packet.
    ///
    /// # Errors
    ///
    /// Returns `BleRecordRejected` when the peer is not ready for a local
    /// packet, or `BleSessionFailed` if Noise fails and the session is cleared.
    pub fn write_handshake_message(&self) -> Result<Vec<u8>, MobileError> {
        let mut state = self.lock_state()?;
        let role = state.role;
        let handshake = state
            .handshake
            .as_mut()
            .ok_or(MobileError::BleSessionFailed)?;
        let step = handshake.step();
        let may_write = matches!(
            (role, step),
            (
                MobileBleRole::Initiator,
                NoiseHandshakeStep::InitiatorSendMessage1
                    | NoiseHandshakeStep::InitiatorSendMessage3
            ) | (
                MobileBleRole::Responder,
                NoiseHandshakeStep::ResponderSendMessage2
            )
        );
        if !may_write {
            return Err(MobileError::BleRecordRejected);
        }
        let packet = match handshake.write_message(&[]) {
            Ok(packet) if !packet.is_empty() && packet.len() <= MAX_GATT_VALUE_BYTES => packet,
            _ => {
                poison(&mut state);
                return Err(MobileError::BleSessionFailed);
            }
        };
        finish_noise_if_ready(&mut state)?;
        Ok(packet)
    }

    /// Reads one empty-payload Noise XX handshake packet.
    ///
    /// # Errors
    ///
    /// Returns `BleSessionFailed` for malformed or failed Noise packets, or
    /// `BleRecordRejected` when the current handshake step cannot read.
    #[allow(clippy::needless_pass_by_value)] // UniFFI exposes packet bytes as an owned byte array.
    pub fn read_handshake_message(&self, packet: Vec<u8>) -> Result<(), MobileError> {
        if packet.is_empty() || packet.len() > MAX_GATT_VALUE_BYTES {
            self.poison_state()?;
            return Err(MobileError::BleSessionFailed);
        }
        let mut state = self.lock_state()?;
        let role = state.role;
        let handshake = state
            .handshake
            .as_mut()
            .ok_or(MobileError::BleSessionFailed)?;
        let step = handshake.step();
        let may_read = matches!(
            (role, step),
            (
                MobileBleRole::Initiator,
                NoiseHandshakeStep::InitiatorReadMessage2
            ) | (
                MobileBleRole::Responder,
                NoiseHandshakeStep::ResponderReadMessage1
                    | NoiseHandshakeStep::ResponderReadMessage3,
            )
        );
        if !may_read {
            return Err(MobileError::BleRecordRejected);
        }
        match handshake.read_message(&packet) {
            Ok(payload) if payload.is_empty() => {}
            _ => {
                poison(&mut state);
                return Err(MobileError::BleSessionFailed);
            }
        }
        finish_noise_if_ready(&mut state)
    }

    /// Reports whether Noise has established the encrypted transport.
    ///
    /// # Errors
    ///
    /// Returns `BleSessionFailed` if the session state mutex is poisoned.
    pub fn handshake_complete(&self) -> Result<bool, MobileError> {
        Ok(self.lock_state()?.transport.is_some())
    }

    /// Writes the role-specific encrypted 135-byte identity proof.
    ///
    /// # Errors
    ///
    /// Returns `BleRecordRejected` when the handshake/proof ordering is invalid,
    /// or a Core/Noise error when signing or encrypting fails.
    pub fn write_identity_proof(&self) -> Result<Vec<u8>, MobileError> {
        let mut state = self.lock_state()?;
        let handshake_hash = state.handshake_hash.ok_or(MobileError::BleSessionFailed)?;
        let can_write = match state.role {
            MobileBleRole::Initiator => state.identity_progress == IdentityProofProgress::Ready,
            MobileBleRole::Responder => {
                state.identity_progress == IdentityProofProgress::PeerProofReceived
            }
        };
        if !can_write {
            return Err(MobileError::BleRecordRejected);
        }
        let context = match state.role {
            MobileBleRole::Initiator if state.peer.is_none() => {
                BleExp0IdentitySignature::InitiatorProof {
                    handshake_hash,
                    responder_token: state.responder_token,
                }
            }
            MobileBleRole::Responder if state.peer.is_some() => {
                let initiator_bundle = state
                    .peer
                    .as_ref()
                    .ok_or(MobileError::BleRecordRejected)?
                    .bundle;
                BleExp0IdentitySignature::ResponderProof {
                    handshake_hash,
                    responder_token: state.responder_token,
                    initiator_bundle,
                }
            }
            _ => return Err(MobileError::BleRecordRejected),
        };
        let signature = self.client.sign_ble_exp0_identity_signature(&context)?;
        let mut record = Vec::with_capacity(IDENTITY_RECORD_BYTES);
        match state.role {
            MobileBleRole::Initiator => {
                record.extend_from_slice(b"LBEI");
                record.push(0);
                record.push(1);
            }
            MobileBleRole::Responder => {
                record.extend_from_slice(b"LBER");
                record.push(0);
                record.push(2);
            }
        }
        record.extend_from_slice(&state.local_bundle);
        record.extend_from_slice(&signature);
        let packet = match state.transport.as_mut() {
            Some(transport) => transport.encrypt(&record),
            None => return Err(MobileError::BleSessionFailed),
        };
        let packet = match packet {
            Ok(packet) if packet.len() <= MAX_GATT_VALUE_BYTES => packet,
            _ => {
                poison(&mut state);
                return Err(MobileError::BleSessionFailed);
            }
        };
        state.identity_progress = match state.role {
            MobileBleRole::Initiator => IdentityProofProgress::LocalProofSent,
            MobileBleRole::Responder => IdentityProofProgress::Complete,
        };
        Ok(packet)
    }

    /// Checks the responder token again against the advertiser's active token.
    ///
    /// Responders must call this immediately before consuming the initiator's
    /// identity proof; a token rotation during the handshake invalidates it.
    ///
    /// # Errors
    ///
    /// Returns `InvalidBleDiscoveryToken` for a malformed token and
    /// `BleRecordRejected` if the role, state, or token value does not match.
    pub fn validate_active_responder_token(
        &self,
        active_token: Vec<u8>,
    ) -> Result<(), MobileError> {
        let mut state = self.lock_state()?;
        if state.role != MobileBleRole::Responder
            || state.peer.is_some()
            || state.identity_progress != IdentityProofProgress::AwaitingResponderToken
        {
            return Err(MobileError::BleRecordRejected);
        }
        let active_token: [u8; TOKEN_BYTES] = active_token
            .try_into()
            .map_err(|_| MobileError::InvalidBleDiscoveryToken)?;
        if active_token != state.responder_token {
            poison(&mut state);
            return Err(MobileError::BleRecordRejected);
        }
        state.identity_progress = IdentityProofProgress::Ready;
        Ok(())
    }

    /// Verifies the remote identity proof and returns the SAS for explicit pinning.
    ///
    /// # Errors
    ///
    /// Returns `BleRecordRejected` for an invalid proof or transition,
    /// `BlePeerIdentityMismatch` for a conflicting pin, or Core/session errors.
    #[allow(clippy::needless_pass_by_value)] // UniFFI exposes packet bytes as an owned byte array.
    pub fn read_identity_proof(&self, packet: Vec<u8>) -> Result<MobileBlePeerInfo, MobileError> {
        let mut state = self.lock_state()?;
        if packet.is_empty() || packet.len() > MAX_GATT_VALUE_BYTES {
            poison(&mut state);
            return Err(MobileError::BleSessionFailed);
        }
        let can_read = match state.role {
            MobileBleRole::Initiator => {
                state.identity_progress == IdentityProofProgress::LocalProofSent
                    && state.peer.is_none()
            }
            MobileBleRole::Responder => {
                state.identity_progress == IdentityProofProgress::Ready && state.peer.is_none()
            }
        };
        if !can_read {
            return Err(MobileError::BleRecordRejected);
        }
        let plaintext = match state.transport.as_mut() {
            Some(transport) => transport.decrypt(&packet),
            None => return Err(MobileError::BleSessionFailed),
        };
        let Ok(mut plaintext) = plaintext else {
            poison(&mut state);
            return Err(MobileError::BleSessionFailed);
        };
        if plaintext.len() != IDENTITY_RECORD_BYTES {
            plaintext.fill(0);
            poison(&mut state);
            return Err(MobileError::BleRecordRejected);
        }
        let (expected_magic, expected_role) = match state.role {
            MobileBleRole::Initiator => (b"LBER", 2),
            MobileBleRole::Responder => (b"LBEI", 1),
        };
        if plaintext[..4] != expected_magic[..]
            || plaintext[4] != 0
            || plaintext[5] != expected_role
        {
            plaintext.fill(0);
            poison(&mut state);
            return Err(MobileError::BleRecordRejected);
        }
        let mut peer_bundle = [0_u8; 65];
        peer_bundle.copy_from_slice(&plaintext[6..71]);
        let signature = &plaintext[71..135];
        let Ok(parsed_bundle) = IdentityPublicBundle::from_bytes(&peer_bundle) else {
            plaintext.fill(0);
            poison(&mut state);
            return Err(MobileError::BleRecordRejected);
        };
        let handshake_hash = state.handshake_hash.ok_or(MobileError::BleSessionFailed)?;
        let context = match state.role {
            MobileBleRole::Responder => BleExp0IdentitySignature::InitiatorProof {
                handshake_hash,
                responder_token: state.responder_token,
            },
            MobileBleRole::Initiator => BleExp0IdentitySignature::ResponderProof {
                handshake_hash,
                responder_token: state.responder_token,
                initiator_bundle: state.local_bundle,
            },
        };
        if verify_ble_exp0_signature(&peer_bundle, &context, signature).is_err() {
            plaintext.fill(0);
            poison(&mut state);
            return Err(MobileError::BleRecordRejected);
        }
        plaintext.fill(0);
        let fingerprint = parsed_bundle.fingerprint();
        let pinned = self.client.pinned_identity(fingerprint.to_vec())?;
        if let Some(pinned) = &pinned
            && pinned.public_bundle != peer_bundle
        {
            poison(&mut state);
            return Err(MobileError::BlePeerIdentityMismatch);
        }
        let (initiator_fingerprint, responder_fingerprint) = match state.role {
            MobileBleRole::Initiator => (state.local_fingerprint, fingerprint),
            MobileBleRole::Responder => (fingerprint, state.local_fingerprint),
        };
        let safety_number = safety_number(
            &handshake_hash,
            &initiator_fingerprint,
            &responder_fingerprint,
        );
        let peer = PeerIdentity {
            bundle: peer_bundle,
            fingerprint,
            safety_number: safety_number.clone(),
            already_pinned: pinned.is_some(),
        };
        let info = peer_info(&peer);
        state.peer = Some(peer);
        state.identity_progress = match state.role {
            MobileBleRole::Initiator => IdentityProofProgress::Complete,
            MobileBleRole::Responder => IdentityProofProgress::PeerProofReceived,
        };
        Ok(info)
    }

    /// Writes the role-appropriate encrypted identity confirmation after this device pins the peer.
    ///
    /// # Errors
    ///
    /// Returns a pin or state error when the peer is not verified and pinned,
    /// or a Core/Noise error if signing or encryption fails.
    pub fn write_confirmation(&self) -> Result<Vec<u8>, MobileError> {
        let mut state = self.lock_state()?;
        let peer = state.peer.as_ref().ok_or(MobileError::BleRecordRejected)?;
        require_peer_pin(&self.client, peer)?;
        let handshake_hash = state.handshake_hash.ok_or(MobileError::BleSessionFailed)?;
        let context = match state.role {
            MobileBleRole::Initiator
                if state.identity_progress == IdentityProofProgress::Complete
                    && state.confirmation_progress == ConfirmationProgress::NotStarted =>
            {
                BleExp0IdentitySignature::InitiatorConfirmation {
                    handshake_hash,
                    responder_token: state.responder_token,
                    responder_bundle: peer.bundle,
                }
            }
            MobileBleRole::Responder
                if state.confirmation_progress == ConfirmationProgress::ResponderReceived =>
            {
                BleExp0IdentitySignature::ResponderConfirmation {
                    handshake_hash,
                    responder_token: state.responder_token,
                    initiator_bundle: peer.bundle,
                }
            }
            _ => return Err(MobileError::BleRecordRejected),
        };
        let signature = self.client.sign_ble_exp0_identity_signature(&context)?;
        let mut record = Vec::with_capacity(CONFIRMATION_RECORD_BYTES);
        record.extend_from_slice(b"LBEC");
        record.push(0);
        record.push(match state.role {
            MobileBleRole::Initiator => 1,
            MobileBleRole::Responder => 2,
        });
        record.extend_from_slice(&signature);
        let packet = match state.transport.as_mut() {
            Some(transport) => transport.encrypt(&record),
            None => return Err(MobileError::BleSessionFailed),
        };
        let packet = match packet {
            Ok(packet) if packet.len() <= MAX_GATT_VALUE_BYTES => packet,
            _ => {
                poison(&mut state);
                return Err(MobileError::BleSessionFailed);
            }
        };
        state.confirmation_progress = match state.role {
            MobileBleRole::Initiator => ConfirmationProgress::InitiatorSent,
            MobileBleRole::Responder => ConfirmationProgress::ResponderWritePending,
        };
        Ok(packet)
    }

    /// Verifies the peer confirmation; responders must then write their own confirmation.
    ///
    /// # Errors
    ///
    /// Returns `BleRecordRejected` for an invalid peer proof or transition,
    /// `BlePeerNotPinned` when explicit pinning is missing, or session errors.
    #[allow(clippy::needless_pass_by_value)] // UniFFI exposes packet bytes as an owned byte array.
    pub fn read_confirmation(&self, packet: Vec<u8>) -> Result<(), MobileError> {
        let mut state = self.lock_state()?;
        if packet.is_empty() || packet.len() > MAX_GATT_VALUE_BYTES {
            poison(&mut state);
            return Err(MobileError::BleSessionFailed);
        }
        let can_read = match state.role {
            MobileBleRole::Initiator => {
                state.confirmation_progress == ConfirmationProgress::InitiatorSent
            }
            MobileBleRole::Responder => {
                state.identity_progress == IdentityProofProgress::Complete
                    && state.confirmation_progress == ConfirmationProgress::NotStarted
            }
        };
        if !can_read {
            return Err(MobileError::BleRecordRejected);
        }
        let plaintext = match state.transport.as_mut() {
            Some(transport) => transport.decrypt(&packet),
            None => return Err(MobileError::BleSessionFailed),
        };
        let Ok(mut plaintext) = plaintext else {
            poison(&mut state);
            return Err(MobileError::BleSessionFailed);
        };
        let expected_role = match state.role {
            MobileBleRole::Initiator => 2,
            MobileBleRole::Responder => 1,
        };
        if plaintext.len() != CONFIRMATION_RECORD_BYTES
            || plaintext[..4] != *b"LBEC"
            || plaintext[4] != 0
            || plaintext[5] != expected_role
        {
            plaintext.fill(0);
            poison(&mut state);
            return Err(MobileError::BleRecordRejected);
        }
        let peer = state.peer.as_ref().ok_or(MobileError::BleRecordRejected)?;
        require_peer_pin(&self.client, peer)?;
        let handshake_hash = state.handshake_hash.ok_or(MobileError::BleSessionFailed)?;
        let context = match state.role {
            MobileBleRole::Initiator => BleExp0IdentitySignature::ResponderConfirmation {
                handshake_hash,
                responder_token: state.responder_token,
                initiator_bundle: state.local_bundle,
            },
            MobileBleRole::Responder => BleExp0IdentitySignature::InitiatorConfirmation {
                handshake_hash,
                responder_token: state.responder_token,
                responder_bundle: state.local_bundle,
            },
        };
        let verified = verify_ble_exp0_signature(&peer.bundle, &context, &plaintext[6..]);
        plaintext.fill(0);
        if verified.is_err() {
            poison(&mut state);
            return Err(MobileError::BleRecordRejected);
        }
        state.confirmation_progress = match state.role {
            MobileBleRole::Initiator => ConfirmationProgress::Authenticated,
            MobileBleRole::Responder => ConfirmationProgress::ResponderReceived,
        };
        Ok(())
    }

    /// Marks the responder's confirmation as locally accepted by the GATT write callback.
    ///
    /// # Errors
    ///
    /// Returns `BleRecordRejected` unless a responder confirmation is pending,
    /// or `BleSessionFailed` if the state mutex is poisoned.
    pub fn confirmation_write_succeeded(&self) -> Result<(), MobileError> {
        let mut state = self.lock_state()?;
        if state.role != MobileBleRole::Responder
            || state.confirmation_progress != ConfirmationProgress::ResponderWritePending
        {
            return Err(MobileError::BleRecordRejected);
        }
        state.confirmation_progress = ConfirmationProgress::Authenticated;
        Ok(())
    }

    /// Reports whether the peer identity has been confirmed.
    ///
    /// # Errors
    ///
    /// Returns `BleSessionFailed` if the session state mutex is poisoned.
    pub fn is_authenticated(&self) -> Result<bool, MobileError> {
        Ok(self.lock_state()?.confirmation_progress == ConfirmationProgress::Authenticated)
    }

    /// Encrypts one authenticated application/control record after identity confirmation.
    ///
    /// # Errors
    ///
    /// Returns `BlePeerNotAuthenticated` before peer confirmation,
    /// `BleRecordRejected` for an empty or oversized record, or session errors.
    #[allow(clippy::needless_pass_by_value)] // UniFFI exposes owned record bytes as generated byte arrays.
    pub fn encrypt_record(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, MobileError> {
        let mut state = self.lock_state()?;
        if state.confirmation_progress != ConfirmationProgress::Authenticated {
            return Err(MobileError::BlePeerNotAuthenticated);
        }
        if plaintext.is_empty() || plaintext.len() > MAX_GATT_VALUE_BYTES - 16 {
            return Err(MobileError::BleRecordRejected);
        }
        let result = state
            .transport
            .as_mut()
            .ok_or(MobileError::BleSessionFailed)?
            .encrypt(&plaintext);
        match result {
            Ok(ciphertext) if ciphertext.len() <= MAX_GATT_VALUE_BYTES => Ok(ciphertext),
            _ => {
                poison(&mut state);
                Err(MobileError::BleSessionFailed)
            }
        }
    }

    /// Authenticates and decrypts one record after identity confirmation.
    ///
    /// # Errors
    ///
    /// Returns `BlePeerNotAuthenticated` before peer confirmation, or
    /// `BleSessionFailed` for an invalid, oversized, or unauthentic record.
    #[allow(clippy::needless_pass_by_value)] // UniFFI exposes owned record bytes as generated byte arrays.
    pub fn decrypt_record(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, MobileError> {
        let mut state = self.lock_state()?;
        if state.confirmation_progress != ConfirmationProgress::Authenticated {
            return Err(MobileError::BlePeerNotAuthenticated);
        }
        if ciphertext.is_empty() || ciphertext.len() > MAX_GATT_VALUE_BYTES {
            poison(&mut state);
            return Err(MobileError::BleSessionFailed);
        }
        let result = state
            .transport
            .as_mut()
            .ok_or(MobileError::BleSessionFailed)?
            .decrypt(&ciphertext);
        if let Ok(plaintext) = result {
            Ok(plaintext)
        } else {
            poison(&mut state);
            Err(MobileError::BleSessionFailed)
        }
    }

    /// Discards all handshake, transcript, peer, and transport state.
    ///
    /// # Errors
    ///
    /// Returns `BleSessionFailed` if the session state mutex is poisoned.
    pub fn terminate(&self) -> Result<(), MobileError> {
        let mut state = self.lock_state()?;
        poison(&mut state);
        Ok(())
    }
}

impl MobileBleSession {
    fn lock_state(&self) -> Result<MutexGuard<'_, BleSessionState>, MobileError> {
        self.state.lock().map_err(|_| MobileError::BleSessionFailed)
    }
    fn poison_state(&self) -> Result<(), MobileError> {
        let mut state = self.lock_state()?;
        poison(&mut state);
        Ok(())
    }
}

fn finish_noise_if_ready(state: &mut BleSessionState) -> Result<(), MobileError> {
    if !state
        .handshake
        .as_ref()
        .is_some_and(|handshake| handshake.step() == NoiseHandshakeStep::Finished)
    {
        return Ok(());
    }
    let handshake = state
        .handshake
        .take()
        .ok_or(MobileError::BleSessionFailed)?;
    let transport = handshake
        .finish_transport()
        .map_err(|_| MobileError::BleSessionFailed)?;
    state.handshake_hash = Some(*transport.session_hash());
    state.transport = Some(transport);
    Ok(())
}

fn require_peer_pin(client: &MobileClient, peer: &PeerIdentity) -> Result<(), MobileError> {
    match client.pinned_identity(peer.fingerprint.to_vec())? {
        Some(pin) if pin.public_bundle == peer.bundle => Ok(()),
        Some(_) => Err(MobileError::BlePeerIdentityMismatch),
        None => Err(MobileError::BlePeerNotPinned),
    }
}

fn peer_info(peer: &PeerIdentity) -> MobileBlePeerInfo {
    MobileBlePeerInfo {
        identity_bundle: peer.bundle.to_vec(),
        fingerprint: peer.fingerprint.to_vec(),
        safety_number: peer.safety_number.clone(),
        already_pinned: peer.already_pinned,
    }
}

fn safety_number(
    handshake_hash: &[u8; 32],
    initiator_fingerprint: &[u8; 32],
    responder_fingerprint: &[u8; 32],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"lattice:ble:exp0:sas:v0\0");
    hasher.update(handshake_hash);
    hasher.update(initiator_fingerprint);
    hasher.update(responder_fingerprint);
    let digest = hasher.finalize();
    format!(
        "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5],
    )
}

fn poison(state: &mut BleSessionState) {
    state.handshake = None;
    state.transport = None;
    state.handshake_hash = None;
    state.responder_token.fill(0);
    state.peer = None;
    state.identity_progress = IdentityProofProgress::Failed;
    state.confirmation_progress = ConfirmationProgress::Failed;
}
