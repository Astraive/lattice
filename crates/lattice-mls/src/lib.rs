//! Lattice group membership and epoch state.
//!
//! Production membership remains unavailable until MLS credentials are bound
//! to verified Space identities, epoch changes are integrated with the
//! authenticated event log, ADR-001 conflict handling is durable, and secure
//! persistence is available.

pub const CRATE_NAME: &str = "lattice-mls";

/// Actual OpenMLS interop code, deliberately compiled only for this crate's
/// unit tests. The BasicCredential values here are explicitly untrusted test
/// identities; an MLS signature proves possession of its key, not Space
/// identity or authorization.
#[cfg(test)]
pub mod test_interop {
    use std::{error::Error, fmt, io, path::Path};

    use openmls::prelude::tls_codec::Deserialize as TlsDeserialize;
    use openmls::prelude::{
        BasicCredential, Ciphersuite, ContentType, CredentialType, CredentialWithKey, GroupEpoch,
        GroupId, KeyPackage, KeyPackageIn, MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig,
        MlsMessageIn, MlsMessageOut, ProcessedMessageContent, ProtocolVersion, StagedCommit,
    };
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_rust_crypto::RustCrypto;
    use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
    use openmls_traits::OpenMlsProvider;
    use rusqlite::Connection;
    use serde::{Serialize, de::DeserializeOwned};

    /// The selected mandatory-to-implement MLS ciphersuite for this test
    /// interop harness.
    pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    /// Maximum TLS-encoded MLS message accepted by the harness.
    pub const MAX_MLS_WIRE_BYTES: usize = 1024 * 1024;

    /// Maximum internal JSON record accepted by the SQLite storage codec.
    ///
    /// These records are trusted provider-local persistence only when the
    /// caller protects the database externally. They are not MLS wire data.
    pub const MAX_PROVIDER_RECORD_BYTES: usize = 1024 * 1024;

    const MAX_TEST_IDENTITY_BYTES: usize = 256;

    /// Security properties deliberately not supplied by this test harness.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SecurityLimitations {
        pub test_only: bool,
        pub production_membership_enabled: bool,
        pub credential_bound_to_verified_space_identity: bool,
        pub mls_sqlite_at_rest_encrypted: bool,
        pub atomic_with_application_event_log: bool,
        pub space_authorization_evaluated: bool,
    }

    /// Machine-readable limitations for interop outputs and test callers.
    pub const SECURITY_LIMITATIONS: SecurityLimitations = SecurityLimitations {
        test_only: true,
        production_membership_enabled: false,
        credential_bound_to_verified_space_identity: false,
        mls_sqlite_at_rest_encrypted: false,
        atomic_with_application_event_log: false,
        space_authorization_evaluated: false,
    };

    /// Returns the test harness's explicit security limitations.
    pub fn security_limitations() -> SecurityLimitations {
        SECURITY_LIMITATIONS
    }

    /// Fallible result returned from this test-only interop API.
    pub type InteropResult<T> = Result<T, Box<dyn Error>>;

    pub type SqliteStorage = SqliteStorageProvider<JsonCodec, Connection>;

    /// Compose OpenMLS' RustCrypto implementation with its SQLite provider.
    ///
    /// The SQLite data is JSON-serialized OpenMLS provider state, not MLS wire
    /// encoding. It is unencrypted, and this provider makes no transaction
    /// claim about application event storage.
    pub struct TestProvider {
        crypto: RustCrypto,
        storage: SqliteStorage,
    }

    impl TestProvider {
        /// Opens the caller-selected SQLite file for interop tests.
        ///
        /// This deliberately unprotected database MUST NOT be used for
        /// production or sensitive data.
        pub fn open_unprotected_sqlite_for_interop(path: impl AsRef<Path>) -> InteropResult<Self> {
            let connection = Connection::open(path)?;
            let mut storage = SqliteStorageProvider::<JsonCodec, Connection>::new(connection);
            storage.run_migrations()?;

            Ok(Self {
                crypto: RustCrypto::default(),
                storage,
            })
        }
    }

    impl OpenMlsProvider for TestProvider {
        type CryptoProvider = RustCrypto;
        type RandProvider = RustCrypto;
        type StorageProvider = SqliteStorage;

        fn storage(&self) -> &Self::StorageProvider {
            &self.storage
        }

        fn crypto(&self) -> &Self::CryptoProvider {
            &self.crypto
        }

        fn rand(&self) -> &Self::RandProvider {
            &self.crypto
        }
    }

    #[derive(Debug)]
    pub enum JsonCodecError {
        TooLarge,
        Json(serde_json::Error),
    }

    impl fmt::Display for JsonCodecError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::TooLarge => write!(
                    f,
                    "OpenMLS SQLite JSON record exceeds {MAX_PROVIDER_RECORD_BYTES} bytes"
                ),
                Self::Json(error) => write!(f, "OpenMLS SQLite JSON codec: {error}"),
            }
        }
    }

    impl Error for JsonCodecError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            match self {
                Self::TooLarge => None,
                Self::Json(error) => Some(error),
            }
        }
    }

    /// The SQLite provider's JSON codec is application-owned persistence
    /// serialization only. Both directions enforce the byte bound.
    #[derive(Default)]
    pub struct JsonCodec;

    struct LimitedBuffer(Vec<u8>);

    impl io::Write for LimitedBuffer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let next_len = self
                .0
                .len()
                .checked_add(bytes.len())
                .filter(|length| *length <= MAX_PROVIDER_RECORD_BYTES)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::FileTooLarge, "provider record byte limit")
                })?;
            self.0
                .try_reserve(next_len - self.0.len())
                .map_err(|error| {
                    io::Error::other(format!("provider record allocation failed: {error}"))
                })?;
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Codec for JsonCodec {
        type Error = JsonCodecError;

        fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
            let mut output = LimitedBuffer(Vec::new());
            if let Err(error) = serde_json::to_writer(&mut output, value) {
                if error.io_error_kind() == Some(io::ErrorKind::FileTooLarge) {
                    return Err(JsonCodecError::TooLarge);
                }
                return Err(JsonCodecError::Json(error));
            }
            Ok(output.0)
        }

        fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Self::Error> {
            if bytes.len() > MAX_PROVIDER_RECORD_BYTES {
                return Err(JsonCodecError::TooLarge);
            }
            serde_json::from_slice(bytes).map_err(JsonCodecError::Json)
        }
    }

    /// An explicitly untrusted BasicCredential and its test signing key.
    pub struct UntrustedTestIdentity {
        identity: Vec<u8>,
        signer: SignatureKeyPair,
    }

    impl UntrustedTestIdentity {
        /// Creates a throwaway BasicCredential for MLS interop tests.
        ///
        /// This does not verify, bind, or authorize the identity bytes.
        pub fn untrusted_for_interop(identity: &[u8]) -> InteropResult<Self> {
            if identity.len() > MAX_TEST_IDENTITY_BYTES {
                return Err(invalid_input("test identity exceeds the hard size limit"));
            }

            Ok(Self {
                identity: identity.to_vec(),
                signer: SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())?,
            })
        }

        /// Returns the raw BasicCredential identity bytes.
        pub fn identity(&self) -> &[u8] {
            &self.identity
        }

        /// Returns this test identity's public signing key.
        pub fn signing_public_key(&self) -> &[u8] {
            self.signer.public()
        }

        fn credential_with_key(&self) -> CredentialWithKey {
            CredentialWithKey {
                credential: BasicCredential::new(self.identity.clone()).into(),
                signature_key: self.signer.public().into(),
            }
        }
    }

    /// Whether OpenMLS has validated a message's protocol authentication.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum MlsEvidence {
        /// TLS-encoded provider bytes have not yet been validated by a peer.
        AwaitingPeerOpenMlsValidation,
        /// OpenMLS accepted the protocol authentication and message semantics.
        ValidatedByOpenMls,
    }

    /// Space authorization is intentionally outside this harness.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SpaceAuthorization {
        /// No Space credential binding, event validation, or permission check
        /// was performed.
        NotEvaluated,
    }

    /// Type of the TLS-encoded MLS object.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum MlsWireKind {
        KeyPackage,
        Proposal,
        Commit,
        Welcome,
        Application,
    }

    /// Encoded MLS data plus its narrow protocol evidence.
    ///
    /// This is not an authenticated Space event or provider-transport
    /// signature. The `bytes` field is TLS codec output.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct InteropMessage {
        pub bytes: Vec<u8>,
        pub kind: MlsWireKind,
        pub mls_evidence: MlsEvidence,
        pub space_authorization: SpaceAuthorization,
    }

    impl InteropMessage {
        fn outgoing(bytes: Vec<u8>, kind: MlsWireKind) -> Self {
            Self {
                bytes,
                kind,
                mls_evidence: MlsEvidence::AwaitingPeerOpenMlsValidation,
                space_authorization: SpaceAuthorization::NotEvaluated,
            }
        }

        /// Returns the TLS-encoded MLS bytes.
        pub fn as_bytes(&self) -> &[u8] {
            &self.bytes
        }
    }

    /// Current state of the test group's local MLS processing.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum GroupStatus {
        Operational,
        OwnCommitPending,
        IncomingCommitStaged,
        Conflicted,
        Inactive,
    }

    /// Result of processing a bounded incoming TLS-encoded MLS message.
    #[derive(Debug, PartialEq, Eq)]
    pub enum IncomingResult {
        Application {
            plaintext: Vec<u8>,
            mls_evidence: MlsEvidence,
            space_authorization: SpaceAuthorization,
        },
        Proposal {
            external: bool,
            mls_evidence: MlsEvidence,
            space_authorization: SpaceAuthorization,
        },
        StagedCommit {
            parent_epoch: u64,
            mls_evidence: MlsEvidence,
            space_authorization: SpaceAuthorization,
        },
        OwnPendingCommit,
        OwnPrivateMessage,
        MissingDependency {
            current_epoch: u64,
            received_epoch: u64,
        },
        /// Safe refusal: the bytes were not processed or authenticated because
        /// this group already has its own pending Commit.
        RefusedWhileOwnCommitPending,
        /// The exact already-staged Commit was received again.
        DuplicateStagedCommit,
        /// Two distinct valid successor Commits were staged from the same
        /// current parent epoch; neither branch is selected.
        ConflictDetected {
            parent_epoch: u64,
        },
        UnsupportedMessage,
    }

    struct IncomingCommit {
        staged: StagedCommit,
        encoded_commit: Vec<u8>,
        parent_epoch: GroupEpoch,
    }

    /// Test-only high-level OpenMLS group wrapper with sequential commit gates.
    pub struct InteropGroup {
        inner: MlsGroup,
        incoming_commit: Option<IncomingCommit>,
        conflicted: bool,
    }

    impl InteropGroup {
        /// Creates a real OpenMLS group using the mandatory-to-implement suite.
        pub fn create(
            provider: &TestProvider,
            identity: &UntrustedTestIdentity,
        ) -> InteropResult<Self> {
            let config = MlsGroupCreateConfig::builder()
                .ciphersuite(CIPHERSUITE)
                .use_ratchet_tree_extension(true)
                .build();
            let inner = MlsGroup::new(
                provider,
                &identity.signer,
                &config,
                identity.credential_with_key(),
            )?;

            Ok(Self {
                inner,
                incoming_commit: None,
                conflicted: false,
            })
        }

        /// Loads a previously persisted OpenMLS group from this provider.
        pub fn load(provider: &TestProvider, group_id: &[u8]) -> InteropResult<Self> {
            let id = GroupId::from_slice(group_id);
            let inner = MlsGroup::load(provider.storage(), &id)?
                .ok_or_else(|| invalid_data("OpenMLS group state was not found"))?;

            Ok(Self {
                inner,
                incoming_commit: None,
                conflicted: false,
            })
        }

        /// Returns the protocol group ID bytes.
        pub fn group_id(&self) -> Vec<u8> {
            self.inner.group_id().to_vec()
        }

        /// Returns the current MLS epoch as an integer.
        pub fn epoch(&self) -> u64 {
            self.inner.epoch().as_u64()
        }

        /// Returns the current OpenMLS group state relevant to commit ordering.
        pub fn status(&self) -> GroupStatus {
            if self.conflicted {
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

        /// Returns the number of current MLS members.
        pub fn member_count(&self) -> usize {
            self.inner.members().count()
        }

        /// Publishes a signed MLS KeyPackage as a TLS-encoded MLS object.
        ///
        /// The KeyPackage signature is not proof that the BasicCredential
        /// identity belongs to a verified Space device.
        pub fn publish_key_package(
            provider: &TestProvider,
            identity: &UntrustedTestIdentity,
        ) -> InteropResult<InteropMessage> {
            let bundle = KeyPackage::builder().build(
                CIPHERSUITE,
                provider,
                &identity.signer,
                identity.credential_with_key(),
            )?;
            let message = MlsMessageOut::from(bundle.into_key_package());
            encode_message(message, MlsWireKind::KeyPackage)
        }

        /// Prepares an add Commit and Welcome from an encoded KeyPackage.
        ///
        /// This stages the local OpenMLS Commit but does not merge it and does
        /// not expose the Welcome. The caller must explicitly attest acceptance
        /// of these exact Commit bytes through
        /// [`mark_commit_accepted_and_merge`](Self::mark_commit_accepted_and_merge)
        /// before it can obtain the Welcome.
        pub fn prepare_add(
            &mut self,
            provider: &TestProvider,
            signer: &UntrustedTestIdentity,
            key_package_wire: &[u8],
        ) -> InteropResult<PreparedAdd> {
            self.ensure_operational()?;
            let key_package = decode_key_package(provider, key_package_wire)?;
            let (commit, welcome, _) =
                self.inner
                    .add_members(provider, &signer.signer, &[key_package])?;
            if self.inner.pending_commit().is_none() {
                return Err(invalid_data(
                    "OpenMLS did not retain the add operation as a pending Commit",
                ));
            }

            Ok(PreparedAdd {
                group_id: self.group_id(),
                parent_epoch: self.inner.epoch(),
                commit: encode_message(commit, MlsWireKind::Commit)?,
                welcome: encode_message(welcome, MlsWireKind::Welcome)?,
            })
        }

        /// Explicitly marks the exact prepared Commit accepted, merges it, and
        /// only then releases its Welcome.
        ///
        /// This call records the caller's assertion; it cannot atomically
        /// coordinate with an application event log or provider transport.
        pub fn mark_commit_accepted_and_merge(
            &mut self,
            provider: &TestProvider,
            prepared: PreparedAdd,
            accepted_commit_wire: &[u8],
        ) -> InteropResult<InteropMessage> {
            self.ensure_not_conflicted()?;
            check_wire_size(accepted_commit_wire)?;
            if prepared.group_id != self.group_id() {
                return Err(invalid_input(
                    "prepared Commit belongs to a different MLS group",
                ));
            }
            if prepared.parent_epoch != self.inner.epoch() {
                return Err(invalid_input(
                    "prepared Commit does not extend the current MLS epoch",
                ));
            }
            if prepared.commit.bytes != accepted_commit_wire {
                return Err(invalid_input(
                    "acceptance must name the exact prepared Commit bytes",
                ));
            }
            if self.inner.pending_commit().is_none() {
                return Err(invalid_data("there is no own pending OpenMLS Commit"));
            }

            self.inner.merge_pending_commit(provider)?;
            Ok(prepared.welcome)
        }

        /// Encrypts application content with the real OpenMLS group state.
        pub fn encrypt_application(
            &mut self,
            provider: &TestProvider,
            signer: &UntrustedTestIdentity,
            plaintext: &[u8],
        ) -> InteropResult<InteropMessage> {
            self.ensure_operational()?;
            let message = self
                .inner
                .create_message(provider, &signer.signer, plaintext)?;
            encode_message(message, MlsWireKind::Application)
        }

        /// TLS-decodes, bounds, classifies, and processes an incoming MLS
        /// protocol message without implicitly merging Commit or proposal
        /// state.
        pub fn process_incoming(
            &mut self,
            provider: &TestProvider,
            wire: &[u8],
        ) -> InteropResult<IncomingResult> {
            check_wire_size(wire)?;
            let parsed = MlsMessageIn::tls_deserialize_exact(wire)?;
            let protocol = parsed.try_into_protocol_message()?;
            if protocol.group_id() != self.inner.group_id() {
                return Err(invalid_input(
                    "incoming MLS message belongs to a different group",
                ));
            }

            let kind = wire_kind(protocol.content_type());
            let current_epoch = self.inner.epoch();
            let received_epoch = protocol.epoch();
            if received_epoch > current_epoch {
                return Ok(IncomingResult::MissingDependency {
                    current_epoch: current_epoch.as_u64(),
                    received_epoch: received_epoch.as_u64(),
                });
            }
            self.ensure_not_conflicted()?;

            if kind == MlsWireKind::Commit {
                if self
                    .incoming_commit
                    .as_ref()
                    .is_some_and(|existing| existing.encoded_commit == wire)
                {
                    return Ok(IncomingResult::DuplicateStagedCommit);
                }
                if self.inner.pending_commit().is_some() {
                    return Ok(IncomingResult::RefusedWhileOwnCommitPending);
                }
            }

            let processed = self.inner.process_message(provider, protocol)?;
            let content = processed.into_content();

            if kind == MlsWireKind::Commit {
                return match content {
                    ProcessedMessageContent::StagedCommitMessage(staged) => {
                        if let Some(existing) = self.incoming_commit.take() {
                            if existing.encoded_commit == wire {
                                self.incoming_commit = Some(existing);
                                return Ok(IncomingResult::DuplicateStagedCommit);
                            }

                            let parent_epoch = existing.parent_epoch.as_u64();
                            self.conflicted = true;
                            Ok(IncomingResult::ConflictDetected { parent_epoch })
                        } else {
                            let parent_epoch = self.inner.epoch();
                            self.incoming_commit = Some(IncomingCommit {
                                staged: *staged,
                                encoded_commit: wire.to_vec(),
                                parent_epoch,
                            });
                            Ok(IncomingResult::StagedCommit {
                                parent_epoch: parent_epoch.as_u64(),
                                mls_evidence: MlsEvidence::ValidatedByOpenMls,
                                space_authorization: SpaceAuthorization::NotEvaluated,
                            })
                        }
                    }
                    other => Ok(classify_non_staged(other)),
                };
            }

            Ok(classify_non_staged(content))
        }

        /// Explicitly attests acceptance of an exact staged incoming Commit
        /// before merging it into this group.
        pub fn mark_incoming_commit_accepted_and_merge(
            &mut self,
            provider: &TestProvider,
            accepted_commit_wire: &[u8],
        ) -> InteropResult<()> {
            self.ensure_not_conflicted()?;
            check_wire_size(accepted_commit_wire)?;
            let staged = self
                .incoming_commit
                .as_ref()
                .ok_or_else(|| invalid_data("there is no staged incoming Commit"))?;
            if staged.parent_epoch != self.inner.epoch() {
                return Err(invalid_input(
                    "staged Commit no longer extends the current MLS epoch",
                ));
            }
            if staged.encoded_commit != accepted_commit_wire {
                return Err(invalid_input(
                    "acceptance must name the exact staged Commit bytes",
                ));
            }

            let staged = self
                .incoming_commit
                .take()
                .ok_or_else(|| invalid_data("staged Commit disappeared"))?;
            self.inner.merge_staged_commit(provider, staged.staged)?;
            Ok(())
        }

        fn ensure_operational(&self) -> InteropResult<()> {
            if self.status() != GroupStatus::Operational {
                return Err(invalid_data(
                    "group mutation is disabled while an MLS Commit is pending or conflicted",
                ));
            }
            Ok(())
        }

        fn ensure_not_conflicted(&self) -> InteropResult<()> {
            if self.conflicted {
                return Err(invalid_data(
                    "group is conflicted; no MLS Commit branch is selected",
                ));
            }
            Ok(())
        }
    }

    /// An add operation whose Welcome is withheld until explicit Commit
    /// acceptance.
    pub struct PreparedAdd {
        group_id: Vec<u8>,
        parent_epoch: GroupEpoch,
        commit: InteropMessage,
        welcome: InteropMessage,
    }

    impl PreparedAdd {
        /// Returns the TLS-encoded Commit that the caller must accept first.
        pub fn commit(&self) -> &InteropMessage {
            &self.commit
        }

        /// Returns the Commit's parent epoch.
        pub fn parent_epoch(&self) -> u64 {
            self.parent_epoch.as_u64()
        }
    }

    fn decode_key_package(provider: &TestProvider, bytes: &[u8]) -> InteropResult<KeyPackage> {
        check_wire_size(bytes)?;
        let parsed = MlsMessageIn::tls_deserialize_exact(bytes)?;
        let key_package: KeyPackageIn = match parsed.extract() {
            openmls::prelude::MlsMessageBodyIn::KeyPackage(key_package) => key_package,
            _ => return Err(invalid_input("TLS message is not an MLS KeyPackage")),
        };
        Ok(key_package.validate(provider.crypto(), ProtocolVersion::Mls10)?)
    }

    fn encode_message(message: MlsMessageOut, kind: MlsWireKind) -> InteropResult<InteropMessage> {
        let bytes = message.to_bytes()?;
        check_wire_size(&bytes)?;
        Ok(InteropMessage::outgoing(bytes, kind))
    }

    fn wire_kind(content_type: ContentType) -> MlsWireKind {
        match content_type {
            ContentType::Application => MlsWireKind::Application,
            ContentType::Proposal => MlsWireKind::Proposal,
            ContentType::Commit => MlsWireKind::Commit,
        }
    }

    fn classify_non_staged(content: ProcessedMessageContent) -> IncomingResult {
        match content {
            ProcessedMessageContent::ApplicationMessage(message) => IncomingResult::Application {
                plaintext: message.into_bytes(),
                mls_evidence: MlsEvidence::ValidatedByOpenMls,
                space_authorization: SpaceAuthorization::NotEvaluated,
            },
            ProcessedMessageContent::ProposalMessage(_) => IncomingResult::Proposal {
                external: false,
                mls_evidence: MlsEvidence::ValidatedByOpenMls,
                space_authorization: SpaceAuthorization::NotEvaluated,
            },
            ProcessedMessageContent::ExternalJoinProposalMessage(_) => IncomingResult::Proposal {
                external: true,
                mls_evidence: MlsEvidence::ValidatedByOpenMls,
                space_authorization: SpaceAuthorization::NotEvaluated,
            },
            ProcessedMessageContent::OwnPendingCommit => IncomingResult::OwnPendingCommit,
            ProcessedMessageContent::OwnPrivateMessage => IncomingResult::OwnPrivateMessage,
            _ => IncomingResult::UnsupportedMessage,
        }
    }

    fn check_wire_size(bytes: &[u8]) -> InteropResult<()> {
        if bytes.len() > MAX_MLS_WIRE_BYTES {
            return Err(invalid_input("MLS wire message exceeds the 1 MiB limit"));
        }
        Ok(())
    }

    fn invalid_input(message: &'static str) -> Box<dyn Error> {
        Box::new(io::Error::new(io::ErrorKind::InvalidInput, message))
    }

    fn invalid_data(message: &'static str) -> Box<dyn Error> {
        Box::new(io::Error::new(io::ErrorKind::InvalidData, message))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{
            fs,
            path::PathBuf,
            time::{SystemTime, UNIX_EPOCH},
        };

        struct TestDatabase(PathBuf);

        impl TestDatabase {
            fn new(label: &str) -> Self {
                let nonce = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("system clock is after UNIX epoch")
                    .as_nanos();
                Self(std::env::temp_dir().join(format!(
                    "lattice-mls-{label}-{}-{nonce}.sqlite",
                    std::process::id()
                )))
            }

            fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for TestDatabase {
            fn drop(&mut self) {
                let _ = fs::remove_file(&self.0);
                for suffix in ["-wal", "-shm"] {
                    let mut sidecar = self.0.as_os_str().to_os_string();
                    sidecar.push(suffix);
                    let _ = fs::remove_file(PathBuf::from(sidecar));
                }
            }
        }

        fn assert_application(result: IncomingResult, expected: &[u8]) {
            match result {
                IncomingResult::Application {
                    plaintext,
                    mls_evidence,
                    space_authorization,
                } => {
                    assert_eq!(plaintext, expected);
                    assert_eq!(mls_evidence, MlsEvidence::ValidatedByOpenMls);
                    assert_eq!(space_authorization, SpaceAuthorization::NotEvaluated);
                }
                other => panic!("expected authenticated MLS application data, got {other:?}"),
            }
        }

        #[test]
        fn official_openmls_sequential_interop_and_sqlite_reload() -> InteropResult<()> {
            let alice_db = TestDatabase::new("alice");
            let bob_db = TestDatabase::new("bob");
            let charlie_db = TestDatabase::new("charlie");
            let eve_db = TestDatabase::new("eve");
            let frank_db = TestDatabase::new("frank");

            let alice_identity =
                UntrustedTestIdentity::untrusted_for_interop(b"untrusted test Alice")?;
            let bob_identity = UntrustedTestIdentity::untrusted_for_interop(b"untrusted test Bob")?;
            let charlie_identity =
                UntrustedTestIdentity::untrusted_for_interop(b"untrusted test Charlie")?;
            let eve_identity = UntrustedTestIdentity::untrusted_for_interop(b"untrusted test Eve")?;
            let frank_identity =
                UntrustedTestIdentity::untrusted_for_interop(b"untrusted test Frank")?;

            let provider_alice =
                TestProvider::open_unprotected_sqlite_for_interop(alice_db.path())?;
            let provider_bob = TestProvider::open_unprotected_sqlite_for_interop(bob_db.path())?;
            let provider_charlie =
                TestProvider::open_unprotected_sqlite_for_interop(charlie_db.path())?;
            let mut alice = InteropGroup::create(&provider_alice, &alice_identity)?;

            let initial_group_id = alice.group_id();
            assert_eq!(alice.epoch(), 0);
            assert_eq!(alice.member_count(), 1);

            let bob_key_package = InteropGroup::publish_key_package(&provider_bob, &bob_identity)?;
            assert_eq!(bob_key_package.kind, MlsWireKind::KeyPackage);
            assert_eq!(
                MlsMessageIn::tls_deserialize_exact(bob_key_package.as_bytes())?.wire_format(),
                openmls::prelude::WireFormat::KeyPackage
            );

            let prepared =
                alice.prepare_add(&provider_alice, &alice_identity, bob_key_package.as_bytes())?;
            let exact_add_commit = prepared.commit().as_bytes().to_vec();
            assert_eq!(prepared.commit().kind, MlsWireKind::Commit);
            assert_eq!(prepared.parent_epoch(), 0);
            assert_eq!(alice.status(), GroupStatus::OwnCommitPending);
            assert_eq!(alice.epoch(), 0);

            let parsed_commit = MlsMessageIn::tls_deserialize_exact(&exact_add_commit)?
                .try_into_protocol_message()?;
            assert_eq!(parsed_commit.content_type(), ContentType::Commit);
            assert_eq!(
                parsed_commit.group_id().as_slice(),
                initial_group_id.as_slice()
            );

            // Simulate storage/provider recreation while the own Commit is
            // still pending; OpenMLS persists this pending transition.
            drop(alice);
            drop(provider_alice);
            let provider_alice =
                TestProvider::open_unprotected_sqlite_for_interop(alice_db.path())?;
            let mut alice = InteropGroup::load(&provider_alice, &initial_group_id)?;
            assert_eq!(alice.status(), GroupStatus::OwnCommitPending);

            let welcome = alice.mark_commit_accepted_and_merge(
                &provider_alice,
                prepared,
                &exact_add_commit,
            )?;
            assert_eq!(welcome.kind, MlsWireKind::Welcome);
            assert_eq!(alice.epoch(), 1);
            assert_eq!(alice.member_count(), 2);

            let mut bob = InteropGroup::from_welcome(
                &provider_bob,
                &initial_group_id,
                alice_identity.identity(),
                welcome.as_bytes(),
            )?;
            assert_eq!(bob.epoch(), 1);
            assert_eq!(bob.member_count(), 2);

            // A genuine standalone proposal is reported as a proposal and is
            // not implicitly admitted into the application's pending policy.
            let own_leaf = bob.inner.own_leaf_index();
            let (proposal, _) =
                bob.inner
                    .propose_remove_member(&provider_bob, &bob_identity.signer, own_leaf)?;
            let proposal_wire = encode_message(proposal, MlsWireKind::Proposal)?;
            assert!(matches!(
                alice.process_incoming(&provider_alice, proposal_wire.as_bytes())?,
                IncomingResult::Proposal {
                    external: false,
                    ..
                }
            ));
            assert!(!alice.inner.has_pending_proposals());

            let first_application = alice.encrypt_application(
                &provider_alice,
                &alice_identity,
                b"message before restart",
            )?;
            assert_eq!(first_application.kind, MlsWireKind::Application);
            assert_application(
                bob.process_incoming(&provider_bob, first_application.as_bytes())?,
                b"message before restart",
            );
            assert!(
                bob.process_incoming(&provider_bob, first_application.as_bytes())
                    .is_err()
            );

            // Prepare the next real transition, deliver/stage its Commit at
            // Bob, and refuse a new-epoch application message until Bob
            // explicitly accepts the exact Commit.
            let charlie_key_package =
                InteropGroup::publish_key_package(&provider_charlie, &charlie_identity)?;
            let next_add = alice.prepare_add(
                &provider_alice,
                &alice_identity,
                charlie_key_package.as_bytes(),
            )?;
            let next_commit_wire = next_add.commit().as_bytes().to_vec();
            let next_welcome = alice.mark_commit_accepted_and_merge(
                &provider_alice,
                next_add,
                &next_commit_wire,
            )?;
            assert_eq!(next_welcome.kind, MlsWireKind::Welcome);
            assert_eq!(alice.epoch(), 2);

            assert!(matches!(
                bob.process_incoming(&provider_bob, &next_commit_wire)?,
                IncomingResult::StagedCommit {
                    parent_epoch: 1,
                    ..
                }
            ));
            assert_eq!(bob.status(), GroupStatus::IncomingCommitStaged);
            assert_eq!(
                bob.process_incoming(&provider_bob, &next_commit_wire)?,
                IncomingResult::DuplicateStagedCommit
            );

            let second_application = alice.encrypt_application(
                &provider_alice,
                &alice_identity,
                b"message waits for parent Commit",
            )?;
            assert!(matches!(
                bob.process_incoming(&provider_bob, second_application.as_bytes())?,
                IncomingResult::MissingDependency {
                    current_epoch: 1,
                    received_epoch: 2
                }
            ));
            bob.mark_incoming_commit_accepted_and_merge(&provider_bob, &next_commit_wire)?;
            assert_eq!(bob.epoch(), 2);
            assert_eq!(bob.status(), GroupStatus::Operational);
            assert_application(
                bob.process_incoming(&provider_bob, second_application.as_bytes())?,
                b"message waits for parent Commit",
            );

            // Reopen and reload both OpenMLS groups from their SQLite stores.
            // The app ratchet state and the accepted epoch survive recreation.
            let alice_group_id = alice.group_id();
            let bob_group_id = bob.group_id();
            drop(alice);
            drop(bob);
            drop(provider_alice);
            drop(provider_bob);

            let provider_alice =
                TestProvider::open_unprotected_sqlite_for_interop(alice_db.path())?;
            let provider_bob = TestProvider::open_unprotected_sqlite_for_interop(bob_db.path())?;
            let mut alice = InteropGroup::load(&provider_alice, &alice_group_id)?;
            let mut bob = InteropGroup::load(&provider_bob, &bob_group_id)?;
            assert_eq!(alice.epoch(), 2);
            assert_eq!(bob.epoch(), 2);
            assert!(
                bob.process_incoming(&provider_bob, second_application.as_bytes())
                    .is_err()
            );

            let post_reload_application = alice.encrypt_application(
                &provider_alice,
                &alice_identity,
                b"message after SQLite reload",
            )?;
            assert_application(
                bob.process_incoming(&provider_bob, post_reload_application.as_bytes())?,
                b"message after SQLite reload",
            );

            // Two real Commits from the same parent epoch are generated on
            // separate members. A pending local Commit makes the harness
            // refuse the competing Commit rather than selecting a branch.
            let eve_provider = TestProvider::open_unprotected_sqlite_for_interop(eve_db.path())?;
            let frank_provider =
                TestProvider::open_unprotected_sqlite_for_interop(frank_db.path())?;
            let eve_key_package = InteropGroup::publish_key_package(&eve_provider, &eve_identity)?;
            let frank_key_package =
                InteropGroup::publish_key_package(&frank_provider, &frank_identity)?;
            let alice_branch =
                alice.prepare_add(&provider_alice, &alice_identity, eve_key_package.as_bytes())?;
            let bob_branch =
                bob.prepare_add(&provider_bob, &bob_identity, frank_key_package.as_bytes())?;
            assert_eq!(alice_branch.parent_epoch(), 2);
            assert_eq!(bob_branch.parent_epoch(), 2);
            assert!(matches!(
                alice.process_incoming(&provider_alice, bob_branch.commit().as_bytes())?,
                IncomingResult::RefusedWhileOwnCommitPending
            ));
            assert!(matches!(
                bob.process_incoming(&provider_bob, alice_branch.commit().as_bytes())?,
                IncomingResult::RefusedWhileOwnCommitPending
            ));
            assert_eq!(alice.status(), GroupStatus::OwnCommitPending);
            assert_eq!(bob.status(), GroupStatus::OwnCommitPending);
            assert_eq!(alice.epoch(), 2);
            assert_eq!(bob.epoch(), 2);

            assert_eq!(
                security_limitations(),
                SecurityLimitations {
                    test_only: true,
                    production_membership_enabled: false,
                    credential_bound_to_verified_space_identity: false,
                    mls_sqlite_at_rest_encrypted: false,
                    atomic_with_application_event_log: false,
                    space_authorization_evaluated: false,
                }
            );

            // Oversized input is rejected before TLS parsing/allocation.
            let oversized = vec![0; MAX_MLS_WIRE_BYTES + 1];
            assert!(alice.process_incoming(&provider_alice, &oversized).is_err());
            let oversized_record = vec![b' '; MAX_PROVIDER_RECORD_BYTES + 1];
            assert!(JsonCodec::from_slice::<serde_json::Value>(&oversized_record).is_err());
            let oversized_record = "x".repeat(MAX_PROVIDER_RECORD_BYTES + 1);
            assert!(matches!(
                JsonCodec::to_vec(&oversized_record),
                Err(JsonCodecError::TooLarge)
            ));
            Ok(())
        }

        #[test]
        fn wrong_welcome_group_or_signer_is_not_joined() -> InteropResult<()> {
            let alice_db = TestDatabase::new("welcome-alice");
            let bob_db = TestDatabase::new("welcome-bob");
            let alice_identity =
                UntrustedTestIdentity::untrusted_for_interop(b"expected untrusted signer")?;
            let bob_identity = UntrustedTestIdentity::untrusted_for_interop(b"joiner identity")?;
            let second_joiner_identity =
                UntrustedTestIdentity::untrusted_for_interop(b"second joiner identity")?;
            let provider_alice =
                TestProvider::open_unprotected_sqlite_for_interop(alice_db.path())?;
            let provider_bob = TestProvider::open_unprotected_sqlite_for_interop(bob_db.path())?;
            let mut alice = InteropGroup::create(&provider_alice, &alice_identity)?;
            let group_id = alice.group_id();

            // The wrong-group attempt consumes its staged KeyPackage while
            // rejecting the expectation, so generate another Welcome for an
            // independent signer-mismatch check.
            let first_key_package =
                InteropGroup::publish_key_package(&provider_bob, &bob_identity)?;
            let first_add = alice.prepare_add(
                &provider_alice,
                &alice_identity,
                first_key_package.as_bytes(),
            )?;
            let first_commit = first_add.commit().as_bytes().to_vec();
            let first_welcome =
                alice.mark_commit_accepted_and_merge(&provider_alice, first_add, &first_commit)?;
            assert!(
                InteropGroup::from_welcome(
                    &provider_bob,
                    b"different group",
                    alice_identity.identity(),
                    first_welcome.as_bytes()
                )
                .is_err()
            );

            let second_key_package =
                InteropGroup::publish_key_package(&provider_bob, &second_joiner_identity)?;
            let second_add = alice.prepare_add(
                &provider_alice,
                &alice_identity,
                second_key_package.as_bytes(),
            )?;
            let second_commit = second_add.commit().as_bytes().to_vec();
            let second_welcome = alice.mark_commit_accepted_and_merge(
                &provider_alice,
                second_add,
                &second_commit,
            )?;
            assert!(
                InteropGroup::from_welcome(
                    &provider_bob,
                    &group_id,
                    b"another credential identity",
                    second_welcome.as_bytes()
                )
                .is_err()
            );
            Ok(())
        }

        #[test]
        fn untrusted_test_identity_has_a_hard_input_bound() {
            let oversized = vec![0; MAX_TEST_IDENTITY_BYTES + 1];
            assert!(UntrustedTestIdentity::untrusted_for_interop(&oversized).is_err());
        }
    }

    impl InteropGroup {
        /// Processes a Welcome only after checking its exact group ID and
        /// BasicCredential signer identity, then installs the joined group.
        ///
        /// Exact byte comparison is not a Space identity proof: this harness
        /// accepts only an explicit test expectation supplied by its caller.
        pub fn from_welcome(
            provider: &TestProvider,
            expected_group_id: &[u8],
            expected_signer_identity: &[u8],
            welcome_wire: &[u8],
        ) -> InteropResult<Self> {
            check_wire_size(welcome_wire)?;
            let parsed = MlsMessageIn::tls_deserialize_exact(welcome_wire)?;
            let welcome = parsed
                .into_welcome()
                .ok_or_else(|| invalid_input("TLS message is not an MLS Welcome"))?;
            let join_config = MlsGroupJoinConfig::builder()
                .use_ratchet_tree_extension(true)
                .build();
            let staged = openmls::prelude::StagedWelcome::new_from_welcome(
                provider,
                &join_config,
                welcome,
                None,
            )?;

            if staged.group_context().group_id().as_slice() != expected_group_id {
                return Err(invalid_input("Welcome group ID does not match expectation"));
            }
            let sender = staged.welcome_sender()?;
            let credential = sender.credential();
            if credential.credential_type() != CredentialType::Basic
                || credential.serialized_content() != expected_signer_identity
            {
                return Err(invalid_input(
                    "Welcome signer identity does not match the exact expected bytes",
                ));
            }

            let inner = staged.into_group(provider)?;
            Ok(Self {
                inner,
                incoming_commit: None,
                conflicted: false,
            })
        }
    }
}
