//! Production OpenMLS operations over a caller-owned provider.
//!
//! This API signs with [`DeviceIdentity`] and accepts only an OpenMLS X.509
//! credential value paired with that device's Ed25519 key. The credential is
//! opaque: OpenMLS 0.9 does not validate its X.509 chain, prove that it contains
//! the device key, or bind it to a Lattice identity. Callers must supply an
//! appropriately verified credential and must separately evaluate Space
//! identity and authorization. A successful MLS operation is not authorization.
//! The signing key comes from the identity crate's in-process `DeviceIdentity`;
//! no OS-keystore implementation is provided here.
//!
//! Per-call bounds are 1 MiB for MLS wire objects, 512 KiB for application
//! plaintext, 16 KiB for `Credential::serialized_content()`, 256 bytes for a
//! loaded group ID and 4096 members per managed group.
//! Conflict evidence retains at most two bounded wire objects. These limits
//! do not bound aggregate provider storage, provider record size, or storage
//! growth; those are controlled by the caller's provider.
//!
//! The caller supplies an [`OpenMlsProvider`] for every operation. OpenMLS
//! persists secrets through that provider; this crate neither chooses a
//! storage backend nor encrypts/authenticates provider data. The incoming
//! staged-Commit/conflict boundary is process-local and is not included in
//! OpenMLS storage. Callers must protect/persist their own authenticated
//! conflict metadata and must not reload a group as operational after losing
//! that metadata. Incoming Commits are refused without validation while a
//! local Commit is pending, so that case is not classified as a conflict.
//! Distinct incoming successors are quarantined only in process memory. This
//! API does not implement ADR-001 recovery or event-log atomicity.

use std::{error::Error, fmt};

use lattice_identity::DeviceIdentity;
use openmls::prelude::tls_codec::Deserialize as TlsDeserialize;
use openmls::{
    credentials::{Credential, CredentialType, CredentialWithKey},
    group::{MlsGroup, StagedCommit},
    key_packages::KeyPackage,
    prelude::{
        Capabilities, Ciphersuite, ContentType, GroupEpoch, GroupId, KeyPackageIn,
        MlsGroupCreateConfig, MlsGroupJoinConfig, MlsMessageIn, MlsMessageOut,
        ProcessedMessageContent, ProtocolVersion,
    },
};
use openmls_traits::{
    OpenMlsProvider,
    signatures::{Signer, SignerError},
    types::SignatureScheme,
};

/// OpenMLS ciphersuite used by the current executable MLS candidate.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
/// Maximum TLS-encoded MLS object accepted or emitted by this boundary.
pub const MAX_MLS_WIRE_BYTES: usize = 1024 * 1024;
/// Maximum opaque X.509 credential content accepted by this boundary.
pub const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;
/// Maximum MLS group identifier accepted by this boundary.
pub const MAX_GROUP_ID_BYTES: usize = 256;
/// Maximum group membership count managed by this boundary.
pub const MAX_GROUP_MEMBERS: usize = 4096;
/// Maximum application plaintext accepted or returned by this boundary.
pub const MAX_APPLICATION_BYTES: usize = 512 * 1024;

/// Errors reported by the production MLS boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MlsError {
    /// An input or OpenMLS output exceeded the documented bound.
    InputTooLarge {
        /// Input category.
        kind: &'static str,
        /// Maximum permitted byte count.
        maximum: usize,
        /// Actual byte count.
        actual: usize,
    },
    /// The input is empty or has invalid framing for the requested operation.
    InvalidInput,
    /// The input is not a well-formed, exact TLS-encoded MLS message.
    MalformedMessage,
    /// The object is a valid MLS object but not one supported by this method.
    UnsupportedMessage,
    /// BasicCredential is intentionally restricted to the test harness.
    BasicCredentialForbidden,
    /// This boundary accepts only opaque OpenMLS X.509 credentials.
    UnsupportedCredentialType,
    /// The supplied credential signature key does not match the local device signer.
    CredentialKeyMismatch,
    /// A group identifier does not identify the requested local group.
    WrongGroup,
    /// No matching persisted OpenMLS group was found.
    GroupNotFound,
    /// An MLS object depends on a future epoch not yet present locally.
    MissingDependency {
        /// Current locally available epoch.
        current_epoch: u64,
        /// Epoch required by the input object.
        received_epoch: u64,
    },
    /// A message belongs to an epoch older than the current group epoch.
    StaleEpoch {
        /// Current locally available epoch.
        current_epoch: u64,
        /// Epoch carried by the input object.
        received_epoch: u64,
    },
    /// This group has an unmerged local Commit.
    OwnCommitPending,
    /// An incoming Commit is staged and must be explicitly accepted first.
    IncomingCommitPending,
    /// This group has been quarantined after detecting competing Commit branches.
    Conflicted,
    /// A second distinct valid Commit extended the same locally current epoch.
    ConflictDetected {
        /// Parent epoch shared by both observed Commit branches.
        parent_epoch: u64,
    },
    /// The exact incoming Commit bytes have already been staged.
    DuplicateStagedCommit,
    /// No incoming Commit is available to merge.
    NoStagedCommit,
    /// Caller acceptance did not name the exact prepared/staged Commit bytes.
    AcceptanceMismatch,
    /// The staged Commit no longer has the current group epoch as its parent.
    ParentEpochChanged,
    /// The operation requires a local Commit that is not pending.
    NoOwnCommitPending,
    /// The group is inactive and cannot process further messages.
    GroupInactive,
    /// The requested operation would exceed the group-state bound.
    GroupStateLimit,
    /// OpenMLS rejected an MLS operation or the caller's provider failed.
    OpenMlsFailure,
}

impl fmt::Display for MlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge {
                kind,
                maximum,
                actual,
            } => {
                write!(f, "{kind} exceeds {maximum} bytes: got {actual}")
            }
            Self::InvalidInput => f.write_str("invalid MLS API input"),
            Self::MalformedMessage => f.write_str("malformed TLS-encoded MLS message"),
            Self::UnsupportedMessage => f.write_str("unsupported MLS message type"),
            Self::BasicCredentialForbidden => {
                f.write_str("BasicCredential is restricted to the test interop API")
            }
            Self::UnsupportedCredentialType => f.write_str("unsupported MLS credential type"),
            Self::CredentialKeyMismatch => {
                f.write_str("MLS credential key does not match the device signer")
            }
            Self::WrongGroup => f.write_str("MLS object belongs to a different group"),
            Self::GroupNotFound => f.write_str("persisted OpenMLS group was not found"),
            Self::MissingDependency {
                current_epoch,
                received_epoch,
            } => write!(
                f,
                "MLS epoch dependency is missing: current {current_epoch}, received {received_epoch}"
            ),
            Self::StaleEpoch {
                current_epoch,
                received_epoch,
            } => write!(
                f,
                "MLS message is stale: current {current_epoch}, received {received_epoch}"
            ),
            Self::OwnCommitPending => f.write_str("an own MLS Commit is pending"),
            Self::IncomingCommitPending => f.write_str("an incoming MLS Commit is staged"),
            Self::Conflicted => f.write_str("MLS group is quarantined as conflicted"),
            Self::ConflictDetected { parent_epoch } => write!(
                f,
                "competing valid MLS Commits extend parent epoch {parent_epoch}"
            ),
            Self::DuplicateStagedCommit => f.write_str("MLS Commit is already staged"),
            Self::NoStagedCommit => f.write_str("there is no staged MLS Commit"),
            Self::AcceptanceMismatch => {
                f.write_str("acceptance must name the exact MLS Commit bytes")
            }
            Self::ParentEpochChanged => f.write_str("MLS Commit parent epoch changed"),
            Self::NoOwnCommitPending => f.write_str("there is no pending local MLS Commit"),
            Self::GroupInactive => f.write_str("MLS group is inactive"),
            Self::GroupStateLimit => f.write_str("MLS group state limit exceeded"),
            Self::OpenMlsFailure => {
                f.write_str("OpenMLS or the caller provider rejected the operation")
            }
        }
    }
}

impl Error for MlsError {}

/// Result type for production MLS operations.
pub type MlsResult<T> = Result<T, MlsError>;

/// Caller-supplied opaque X.509 credential paired with a local device key.
///
/// Construction checks the credential type and that `signature_key` is the
/// Ed25519 public key of `identity`. It does not parse or validate the X.509
/// content, bind that certificate to a Lattice identity, or evaluate policy.
#[derive(Clone, Debug)]
pub struct DeviceCredentialInput {
    credential_with_key: CredentialWithKey,
}

impl DeviceCredentialInput {
    /// Pairs opaque X.509 credential content with the public key of `identity`.
    ///
    /// `credential` must be an X.509 credential supplied by the caller. OpenMLS
    /// 0.9 treats it as opaque and does not authenticate its certificate chain;
    /// callers must verify that independently before relying on it.
    pub fn from_x509_credential(
        identity: &DeviceIdentity,
        credential: Credential,
    ) -> MlsResult<Self> {
        if credential.serialized_content().len() > MAX_CREDENTIAL_BYTES {
            return Err(MlsError::InputTooLarge {
                kind: "X.509 credential content",
                maximum: MAX_CREDENTIAL_BYTES,
                actual: credential.serialized_content().len(),
            });
        }
        match credential.credential_type() {
            CredentialType::X509 => {}
            CredentialType::Basic => return Err(MlsError::BasicCredentialForbidden),
            _ => return Err(MlsError::UnsupportedCredentialType),
        }

        Ok(Self {
            credential_with_key: CredentialWithKey {
                credential,
                signature_key: identity.public_key().to_vec().into(),
            },
        })
    }

    /// Returns the opaque MLS credential value for external verification.
    pub fn credential(&self) -> &Credential {
        &self.credential_with_key.credential
    }

    fn check_signer(&self, identity: &DeviceIdentity) -> MlsResult<()> {
        if self.credential_with_key.signature_key.as_slice() != identity.public_key() {
            return Err(MlsError::CredentialKeyMismatch);
        }
        Ok(())
    }
}

struct DeviceSigner<'a>(&'a DeviceIdentity);

impl Signer for DeviceSigner<'_> {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        Ok(self.0.sign(payload).to_vec())
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

/// Type of the serialized MLS object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlsWireKind {
    /// A signed MLS KeyPackage.
    KeyPackage,
    /// An MLS proposal.
    Proposal,
    /// An MLS Commit.
    Commit,
    /// An MLS Welcome.
    Welcome,
    /// MLS application data.
    Application,
}

/// Bounded TLS-encoded MLS output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsMessage {
    bytes: Vec<u8>,
    kind: MlsWireKind,
}

impl MlsMessage {
    /// Returns the TLS-encoded MLS object.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the type of the encoded MLS object.
    pub const fn kind(&self) -> MlsWireKind {
        self.kind
    }
}

/// Space authorization is not evaluated by this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpaceAuthorization {
    /// No verified Lattice identity or Space policy input was evaluated.
    NotEvaluated,
}

/// A successful result from processing an incoming MLS object.
#[derive(Debug, PartialEq, Eq)]
pub enum IncomingResult {
    /// Decrypted MLS application bytes, not yet accepted as an authorized event.
    Application {
        /// Decrypted application plaintext.
        plaintext: Vec<u8>,
        /// Space authorization has not been evaluated.
        space_authorization: SpaceAuthorization,
    },
    /// A validated MLS proposal, not yet admitted by application policy.
    Proposal {
        /// Whether the proposal used the external sender path.
        external: bool,
        /// Space authorization has not been evaluated.
        space_authorization: SpaceAuthorization,
    },
    /// A valid Commit staged against the current locally held epoch.
    StagedCommit {
        /// The Commit's parent epoch, which must remain current until merge.
        parent_epoch: u64,
        /// Space authorization has not been evaluated.
        space_authorization: SpaceAuthorization,
    },
}

/// Current state exposed by the production MLS boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupStatus {
    /// No pending transition, conflict, or inactive state is known locally.
    Operational,
    /// This member has an unmerged local Commit.
    OwnCommitPending,
    /// One authenticated incoming Commit is staged in this process.
    IncomingCommitStaged,
    /// Distinct valid Commits were observed from the same local parent epoch.
    Conflicted,
    /// OpenMLS reports that the local member is no longer active.
    Inactive,
}

struct IncomingCommit {
    staged: StagedCommit,
    encoded: Vec<u8>,
    parent_epoch: GroupEpoch,
}

/// Bounded evidence for two distinct valid successor Commits.
///
/// The value is available to the caller for authenticated persistence or
/// diagnostics. This crate retains it only in memory and does not authenticate
/// or persist it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictEvidence {
    parent_epoch: u64,
    first_commit: Vec<u8>,
    second_commit: Vec<u8>,
}

impl ConflictEvidence {
    /// Returns the epoch from which both Commit branches were validated.
    pub const fn parent_epoch(&self) -> u64 {
        self.parent_epoch
    }

    /// Returns the first locally observed branch's exact TLS bytes.
    pub fn first_commit(&self) -> &[u8] {
        &self.first_commit
    }

    /// Returns the competing branch's exact TLS bytes.
    pub fn second_commit(&self) -> &[u8] {
        &self.second_commit
    }
}

/// OpenMLS group state with explicit local commit and conflict gates.
///
/// The OpenMLS secret state is stored through the provider passed to each
/// operation. `incoming_commit` and `conflict` are process-local only and must
/// be protected/persisted separately by the caller before relying on them
/// across restarts.
pub struct GroupState {
    inner: MlsGroup,
    incoming_commit: Option<IncomingCommit>,
    conflict: Option<ConflictEvidence>,
}

/// Prepared add transition; its Welcome is withheld until exact Commit acceptance.
pub struct PreparedAdd {
    group_id: Vec<u8>,
    parent_epoch: GroupEpoch,
    commit: MlsMessage,
    welcome: MlsMessage,
}

impl PreparedAdd {
    /// Returns the exact Commit that must be accepted before the Welcome is released.
    pub fn commit(&self) -> &MlsMessage {
        &self.commit
    }

    /// Returns the parent epoch of this transition.
    pub fn parent_epoch(&self) -> u64 {
        self.parent_epoch.as_u64()
    }
}

impl GroupState {
    /// Creates an OpenMLS group with the current candidate ciphersuite.
    pub fn create<P: OpenMlsProvider>(
        provider: &P,
        identity: &DeviceIdentity,
        credential: &DeviceCredentialInput,
    ) -> MlsResult<Self> {
        credential.check_signer(identity)?;
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .capabilities(x509_capabilities())
            .use_ratchet_tree_extension(true)
            .build();
        let inner = MlsGroup::new(
            provider,
            &DeviceSigner(identity),
            &config,
            credential.credential_with_key.clone(),
        )
        .map_err(|_| MlsError::OpenMlsFailure)?;
        Ok(Self {
            inner,
            incoming_commit: None,
            conflict: None,
        })
    }

    /// Loads OpenMLS secret state from the caller's provider.
    ///
    /// This restores only OpenMLS state. It cannot recover the process-local
    /// incoming-Commit or conflict quarantine; callers must authenticate and
    /// restore their own boundary metadata or must not resume the group as
    /// operational.
    pub fn load<P: OpenMlsProvider>(provider: &P, group_id: &[u8]) -> MlsResult<Self> {
        check_group_id(group_id)?;
        let id = GroupId::from_slice(group_id);
        let inner = MlsGroup::load(provider.storage(), &id)
            .map_err(|_| MlsError::OpenMlsFailure)?
            .ok_or(MlsError::GroupNotFound)?;
        if inner.members().count() > MAX_GROUP_MEMBERS {
            return Err(MlsError::GroupStateLimit);
        }
        Ok(Self {
            inner,
            incoming_commit: None,
            conflict: None,
        })
    }

    /// Creates a TLS-encoded MLS KeyPackage for this device and credential.
    pub fn publish_key_package<P: OpenMlsProvider>(
        provider: &P,
        identity: &DeviceIdentity,
        credential: &DeviceCredentialInput,
    ) -> MlsResult<MlsMessage> {
        credential.check_signer(identity)?;
        let bundle = KeyPackage::builder()
            .leaf_node_capabilities(x509_capabilities())
            .build(
                CIPHERSUITE,
                provider,
                &DeviceSigner(identity),
                credential.credential_with_key.clone(),
            )
            .map_err(|_| MlsError::OpenMlsFailure)?;
        encode_message(
            MlsMessageOut::from(bundle.into_key_package()),
            MlsWireKind::KeyPackage,
        )
    }

    /// Joins from a Welcome only when the expected credential and signer key match.
    ///
    /// This exact expectation check does not validate the X.509 chain or establish
    /// Space authorization. Those remain caller responsibilities.
    pub fn from_welcome<P: OpenMlsProvider>(
        provider: &P,
        expected_group_id: &[u8],
        expected_credential: &DeviceCredentialInput,
        welcome_wire: &[u8],
    ) -> MlsResult<Self> {
        check_group_id(expected_group_id)?;
        check_wire_size(welcome_wire)?;
        let parsed = parse_message(welcome_wire)?;
        let welcome = parsed.into_welcome().ok_or(MlsError::UnsupportedMessage)?;
        let join_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let staged =
            openmls::group::StagedWelcome::new_from_welcome(provider, &join_config, welcome, None)
                .map_err(|_| MlsError::OpenMlsFailure)?;

        if staged.group_context().group_id().as_slice() != expected_group_id {
            return Err(MlsError::WrongGroup);
        }
        if staged.members().count() > MAX_GROUP_MEMBERS {
            return Err(MlsError::GroupStateLimit);
        }
        let sender = staged
            .welcome_sender()
            .map_err(|_| MlsError::OpenMlsFailure)?;
        let expected = &expected_credential.credential_with_key;
        if sender.credential().credential_type() != CredentialType::X509
            || sender.credential().serialized_content() != expected.credential.serialized_content()
            || sender.signature_key().as_slice() != expected.signature_key.as_slice()
        {
            return Err(MlsError::CredentialKeyMismatch);
        }

        let inner = staged
            .into_group(provider)
            .map_err(|_| MlsError::OpenMlsFailure)?;
        Ok(Self {
            inner,
            incoming_commit: None,
            conflict: None,
        })
    }

    /// Returns the MLS group identifier bytes.
    pub fn group_id(&self) -> Vec<u8> {
        self.inner.group_id().to_vec()
    }

    /// Returns the current MLS epoch.
    pub fn epoch(&self) -> u64 {
        self.inner.epoch().as_u64()
    }

    /// Returns the current MLS member count.
    pub fn member_count(&self) -> usize {
        self.inner.members().count()
    }

    /// Returns current state relevant to MLS transitions.
    pub fn status(&self) -> GroupStatus {
        if self.conflict.is_some() {
            GroupStatus::Conflicted
        } else if !self.inner.is_active() {
            GroupStatus::Inactive
        } else if self.inner.pending_commit().is_some() {
            GroupStatus::OwnCommitPending
        } else if self.incoming_commit.is_some() {
            GroupStatus::IncomingCommitStaged
        } else {
            GroupStatus::Operational
        }
    }

    /// Returns the locally retained conflict evidence, if competing branches were observed.
    pub fn conflict_evidence(&self) -> Option<&ConflictEvidence> {
        self.conflict.as_ref()
    }

    /// Prepares an add transition from one bounded, validated KeyPackage.
    pub fn prepare_add<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        identity: &DeviceIdentity,
        credential: &DeviceCredentialInput,
        key_package_wire: &[u8],
    ) -> MlsResult<PreparedAdd> {
        self.ensure_operational()?;
        credential.check_signer(identity)?;
        if self.member_count() >= MAX_GROUP_MEMBERS {
            return Err(MlsError::GroupStateLimit);
        }
        let key_package = decode_key_package(provider, key_package_wire)?;
        let (commit, welcome, _) = self
            .inner
            .add_members(provider, &DeviceSigner(identity), &[key_package])
            .map_err(|_| MlsError::OpenMlsFailure)?;
        if self.inner.pending_commit().is_none() {
            return Err(MlsError::OpenMlsFailure);
        }
        Ok(PreparedAdd {
            group_id: self.group_id(),
            parent_epoch: self.inner.epoch(),
            commit: encode_message(commit, MlsWireKind::Commit)?,
            welcome: encode_message(welcome, MlsWireKind::Welcome)?,
        })
    }

    /// Merges the exact prepared Commit and releases its Welcome.
    ///
    /// This is the caller's explicit acceptance signal only; it does not perform
    /// Space authorization or coordinate atomically with an application log.
    pub fn accept_prepared_add<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        prepared: &PreparedAdd,
        accepted_commit_wire: &[u8],
    ) -> MlsResult<MlsMessage> {
        self.ensure_not_conflicted()?;
        self.ensure_active()?;
        check_wire_size(accepted_commit_wire)?;
        if prepared.group_id != self.group_id() {
            return Err(MlsError::WrongGroup);
        }
        if prepared.parent_epoch != self.inner.epoch() {
            return Err(MlsError::ParentEpochChanged);
        }
        if prepared.commit.as_bytes() != accepted_commit_wire {
            return Err(MlsError::AcceptanceMismatch);
        }
        if self.inner.pending_commit().is_none() {
            return Err(MlsError::NoOwnCommitPending);
        }
        self.inner
            .merge_pending_commit(provider)
            .map_err(|_| MlsError::OpenMlsFailure)?;
        Ok(prepared.welcome.clone())
    }

    /// Encrypts a bounded application payload with the actual OpenMLS group state.
    pub fn encrypt_application<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        identity: &DeviceIdentity,
        credential: &DeviceCredentialInput,
        plaintext: &[u8],
    ) -> MlsResult<MlsMessage> {
        self.ensure_operational()?;
        credential.check_signer(identity)?;
        check_application_size(plaintext)?;
        let message = self
            .inner
            .create_message(provider, &DeviceSigner(identity), plaintext)
            .map_err(|_| MlsError::OpenMlsFailure)?;
        encode_message(message, MlsWireKind::Application)
    }

    /// Parses and authenticates one bounded incoming MLS protocol message.
    ///
    /// Commits are staged and never merged implicitly. A future-epoch message is
    /// returned as a typed missing-dependency error; this API has no pending queue.
    pub fn process_incoming<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        wire: &[u8],
    ) -> MlsResult<IncomingResult> {
        check_wire_size(wire)?;
        let parsed = parse_message(wire)?;
        let protocol = parsed
            .try_into_protocol_message()
            .map_err(|_| MlsError::UnsupportedMessage)?;
        if protocol.group_id() != self.inner.group_id() {
            return Err(MlsError::WrongGroup);
        }
        let kind = wire_kind(protocol.content_type());
        let current_epoch = self.inner.epoch();
        let received_epoch = protocol.epoch();
        if received_epoch > current_epoch {
            return Err(MlsError::MissingDependency {
                current_epoch: current_epoch.as_u64(),
                received_epoch: received_epoch.as_u64(),
            });
        }
        if received_epoch < current_epoch {
            return Err(MlsError::StaleEpoch {
                current_epoch: current_epoch.as_u64(),
                received_epoch: received_epoch.as_u64(),
            });
        }
        self.ensure_not_conflicted()?;
        self.ensure_active()?;

        if kind == MlsWireKind::Commit {
            if self
                .incoming_commit
                .as_ref()
                .is_some_and(|staged| staged.encoded == wire)
            {
                return Err(MlsError::DuplicateStagedCommit);
            }
            if self.inner.pending_commit().is_some() {
                return Err(MlsError::OwnCommitPending);
            }
        }

        let processed = self
            .inner
            .process_message(provider, protocol)
            .map_err(|_| MlsError::OpenMlsFailure)?;
        let content = processed.into_content();
        if kind == MlsWireKind::Commit {
            return match content {
                ProcessedMessageContent::StagedCommitMessage(staged) => {
                    if let Some(existing) = self.incoming_commit.take() {
                        let parent_epoch = existing.parent_epoch.as_u64();
                        self.conflict = Some(ConflictEvidence {
                            parent_epoch,
                            first_commit: existing.encoded,
                            second_commit: bounded_copy(wire)?,
                        });
                        Err(MlsError::ConflictDetected { parent_epoch })
                    } else {
                        let adds = staged.add_proposals().count();
                        let removes = staged.remove_proposals().count();
                        let resulting_members = self
                            .member_count()
                            .saturating_add(adds)
                            .saturating_sub(removes);
                        if resulting_members > MAX_GROUP_MEMBERS {
                            return Err(MlsError::GroupStateLimit);
                        }
                        let parent_epoch = self.inner.epoch();
                        self.incoming_commit = Some(IncomingCommit {
                            staged: *staged,
                            encoded: bounded_copy(wire)?,
                            parent_epoch,
                        });
                        Ok(IncomingResult::StagedCommit {
                            parent_epoch: parent_epoch.as_u64(),
                            space_authorization: SpaceAuthorization::NotEvaluated,
                        })
                    }
                }
                other => classify_non_commit(other),
            };
        }

        classify_non_commit(content)
    }

    /// Merges the exact staged incoming Commit after explicit caller acceptance.
    pub fn accept_incoming_commit<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        accepted_commit_wire: &[u8],
    ) -> MlsResult<()> {
        self.ensure_not_conflicted()?;
        self.ensure_active()?;
        check_wire_size(accepted_commit_wire)?;
        let staged = self
            .incoming_commit
            .as_ref()
            .ok_or(MlsError::NoStagedCommit)?;
        if staged.parent_epoch != self.inner.epoch() {
            return Err(MlsError::ParentEpochChanged);
        }
        if staged.encoded != accepted_commit_wire {
            return Err(MlsError::AcceptanceMismatch);
        }
        let staged = self
            .incoming_commit
            .take()
            .ok_or(MlsError::NoStagedCommit)?;
        self.inner
            .merge_staged_commit(provider, staged.staged)
            .map_err(|_| MlsError::OpenMlsFailure)
    }

    fn ensure_operational(&self) -> MlsResult<()> {
        match self.status() {
            GroupStatus::Operational => Ok(()),
            GroupStatus::OwnCommitPending => Err(MlsError::OwnCommitPending),
            GroupStatus::IncomingCommitStaged => Err(MlsError::IncomingCommitPending),
            GroupStatus::Conflicted => Err(MlsError::Conflicted),
            GroupStatus::Inactive => Err(MlsError::GroupInactive),
        }
    }

    fn ensure_active(&self) -> MlsResult<()> {
        if self.inner.is_active() {
            Ok(())
        } else {
            Err(MlsError::GroupInactive)
        }
    }

    fn ensure_not_conflicted(&self) -> MlsResult<()> {
        if self.conflict.is_some() {
            Err(MlsError::Conflicted)
        } else {
            Ok(())
        }
    }
}

fn check_wire_size(wire: &[u8]) -> MlsResult<()> {
    if wire.is_empty() {
        return Err(MlsError::InvalidInput);
    }
    if wire.len() > MAX_MLS_WIRE_BYTES {
        return Err(MlsError::InputTooLarge {
            kind: "MLS wire message",
            maximum: MAX_MLS_WIRE_BYTES,
            actual: wire.len(),
        });
    }
    Ok(())
}

fn check_group_id(group_id: &[u8]) -> MlsResult<()> {
    if group_id.is_empty() {
        return Err(MlsError::InvalidInput);
    }
    if group_id.len() > MAX_GROUP_ID_BYTES {
        return Err(MlsError::InputTooLarge {
            kind: "MLS group identifier",
            maximum: MAX_GROUP_ID_BYTES,
            actual: group_id.len(),
        });
    }
    Ok(())
}

fn check_application_size(plaintext: &[u8]) -> MlsResult<()> {
    if plaintext.len() > MAX_APPLICATION_BYTES {
        return Err(MlsError::InputTooLarge {
            kind: "MLS application plaintext",
            maximum: MAX_APPLICATION_BYTES,
            actual: plaintext.len(),
        });
    }
    Ok(())
}

fn bounded_copy(bytes: &[u8]) -> MlsResult<Vec<u8>> {
    check_wire_size(bytes)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(bytes.len())
        .map_err(|_| MlsError::OpenMlsFailure)?;
    output.extend_from_slice(bytes);
    Ok(output)
}

fn parse_message(wire: &[u8]) -> MlsResult<MlsMessageIn> {
    check_wire_size(wire)?;
    MlsMessageIn::tls_deserialize_exact(wire).map_err(|_| MlsError::MalformedMessage)
}

fn decode_key_package<P: OpenMlsProvider>(provider: &P, wire: &[u8]) -> MlsResult<KeyPackage> {
    let parsed = parse_message(wire)?;
    let key_package: KeyPackageIn = match parsed.extract() {
        openmls::prelude::MlsMessageBodyIn::KeyPackage(key_package) => key_package,
        _ => return Err(MlsError::UnsupportedMessage),
    };
    key_package
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|_| MlsError::OpenMlsFailure)
}

fn encode_message(message: MlsMessageOut, kind: MlsWireKind) -> MlsResult<MlsMessage> {
    let bytes = message.to_bytes().map_err(|_| MlsError::OpenMlsFailure)?;
    check_wire_size(&bytes)?;
    Ok(MlsMessage { bytes, kind })
}

fn x509_capabilities() -> Capabilities {
    Capabilities::builder()
        .credentials(vec![CredentialType::X509])
        .build()
}

fn wire_kind(content_type: ContentType) -> MlsWireKind {
    match content_type {
        ContentType::Application => MlsWireKind::Application,
        ContentType::Proposal => MlsWireKind::Proposal,
        ContentType::Commit => MlsWireKind::Commit,
    }
}

fn classify_non_commit(content: ProcessedMessageContent) -> MlsResult<IncomingResult> {
    match content {
        ProcessedMessageContent::ApplicationMessage(message) => {
            let plaintext = message.into_bytes();
            check_application_size(&plaintext)?;
            Ok(IncomingResult::Application {
                plaintext,
                space_authorization: SpaceAuthorization::NotEvaluated,
            })
        }
        ProcessedMessageContent::ProposalMessage(_) => Ok(IncomingResult::Proposal {
            external: false,
            space_authorization: SpaceAuthorization::NotEvaluated,
        }),
        ProcessedMessageContent::ExternalJoinProposalMessage(_) => Ok(IncomingResult::Proposal {
            external: true,
            space_authorization: SpaceAuthorization::NotEvaluated,
        }),
        _ => Err(MlsError::UnsupportedMessage),
    }
}
