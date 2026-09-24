//! Lattice local device core.
//!
//! The facade owns one durable store and one device identity. It exposes no
//! message or Space operation until MLS validation, event authorization, and
//! their atomic persistence boundary are connected.

use std::path::Path;

use lattice_events::VerifiedSignatureOnlyEvent;
use lattice_identity::{DeviceIdentity, IdentityError, IdentityPublicBundle, PrivateKeyProtector};
use lattice_mls::api::MlsApplication;
use lattice_storage::{Store, StoreError};
use thiserror::Error;

/// Stable name of this local orchestration facade.
pub const CRATE_NAME: &str = "lattice-core";

/// Read-only public identity information safe for app and CLI display.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceIdentityInfo {
    /// Versioned 65-byte public identity bundle.
    pub public_bundle: [u8; 65],
    /// Full domain-separated SHA-256 fingerprint of `public_bundle`.
    pub fingerprint: [u8; 32],
}

/// Event payload proven to match an authenticated MLS member and ciphertext.
///
/// This proves that the verified event author key matches the MLS member key,
/// that the event body is the exact ciphertext processed by MLS, and that the
/// event epoch matches. It does not validate MLS group-reference mapping,
/// credential trust, Space/channel authorization, or application policy.
#[must_use]
#[derive(Debug)]
pub struct MlsBoundEvent {
    event: VerifiedSignatureOnlyEvent,
    plaintext: Vec<u8>,
}

impl MlsBoundEvent {
    /// Returns the signature-verified event bound to the MLS application.
    #[must_use]
    pub const fn event(&self) -> &VerifiedSignatureOnlyEvent {
        &self.event
    }

    /// Returns plaintext produced by processing that event's exact ciphertext.
    #[must_use]
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }
}

/// Binds a signature-verified event to a successful MLS application result.
///
/// The binding rejects events whose author key, protected body, or MLS epoch
/// differs from the authenticated MLS result. A successful value is not
/// authorization and must not be treated as permission to mutate a Space.
///
/// # Errors
///
/// Returns [`CoreError::MlsEventBindingFailed`] if sender identity, exact
/// ciphertext bytes, or MLS epoch do not match the signed event.
#[must_use]
pub fn bind_mls_application(
    event: VerifiedSignatureOnlyEvent,
    application: MlsApplication,
) -> Result<MlsBoundEvent, CoreError> {
    let author_key = event.identity_bundle().ed25519_public_key();
    if application.member_signature_key() != Some(&author_key)
        || !application.matches_ciphertext(event.protected_body())
        || application.epoch() != event.mls_epoch()
    {
        return Err(CoreError::MlsEventBindingFailed);
    }

    Ok(MlsBoundEvent {
        event,
        plaintext: application.into_plaintext(),
    })
}

/// Local core setup and durable-store failures.
#[derive(Debug, Error)]
pub enum CoreError {
    /// Opening or writing the durable event/identity store failed.
    #[error(transparent)]
    Storage(#[from] StoreError),
    /// Creating or reopening the protected device identity failed.
    #[error(transparent)]
    Identity(#[from] IdentityError),
    /// An existing identity was required, but this data directory has none.
    #[error("no protected device identity is initialized")]
    MissingIdentity,
    /// A verified event did not match its authenticated MLS application result.
    #[error("event does not match the authenticated MLS application")]
    MlsEventBindingFailed,
}

/// Local device core with an OS-protected identity and durable event store.
///
/// Private identity bytes never enter SQLite through this facade. Only the
/// ciphertext returned by the caller-supplied OS protector is persisted.
pub struct Client {
    store: Store,
    identity: DeviceIdentity,
}

impl Client {
    /// Opens a profile and initializes its device identity if it does not exist.
    ///
    /// Concurrent initializers are serialized by SQLite's unique identity slot;
    /// the losing initializer reopens the ciphertext committed by the winner.
    pub fn open_or_create<P: PrivateKeyProtector>(
        database_path: impl AsRef<Path>,
        protector: &P,
    ) -> Result<Self, CoreError> {
        let mut store = Store::open(database_path)?;
        if let Some(ciphertext) = store.load_protected_identity()? {
            return Ok(Self {
                identity: DeviceIdentity::load_protected(protector, &ciphertext)?,
                store,
            });
        }

        let (generated, ciphertext) = DeviceIdentity::generate_protected(protector)?;
        if store.save_protected_identity(&ciphertext)? {
            return Ok(Self {
                store,
                identity: generated,
            });
        }

        let persisted = store
            .load_protected_identity()?
            .ok_or(CoreError::MissingIdentity)?;
        Ok(Self {
            identity: DeviceIdentity::load_protected(protector, &persisted)?,
            store,
        })
    }

    /// Opens a profile only when its protected device identity already exists.
    pub fn open_existing<P: PrivateKeyProtector>(
        database_path: impl AsRef<Path>,
        protector: &P,
    ) -> Result<Self, CoreError> {
        let store = Store::open(database_path)?;
        let ciphertext = store
            .load_protected_identity()?
            .ok_or(CoreError::MissingIdentity)?;
        let identity = DeviceIdentity::load_protected(protector, &ciphertext)?;
        Ok(Self { store, identity })
    }

    /// Returns the non-secret public identity bundle and fingerprint.
    #[must_use]
    pub fn identity_info(&self) -> DeviceIdentityInfo {
        let bundle: IdentityPublicBundle = self.identity.public_bundle();
        DeviceIdentityInfo {
            public_bundle: bundle.to_bytes(),
            fingerprint: bundle.fingerprint(),
        }
    }

    /// Returns the next local author sequence reserved by the durable store.
    pub fn next_author_sequence(&self) -> Result<u64, CoreError> {
        Ok(self
            .store
            .next_author_sequence(&self.identity.fingerprint())?)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{Client, CoreError, bind_mls_application};
    use lattice_events::{EventDraft, EventKind, VerifiedSignatureOnlyEvent};
    use lattice_identity::{DeviceIdentity, PrivateKeyProtectionError, PrivateKeyProtector};
    use lattice_mls::api::{DeviceCredentialInput, GroupState, IncomingResult};
    use openmls::credentials::Credential;
    use openmls::prelude::CredentialType;
    use openmls::prelude::tls_codec::{Serialize as TlsSerialize, VLBytes};
    use openmls_rust_crypto::OpenMlsRustCrypto;

    static NEXT_TEST_PATH: AtomicU64 = AtomicU64::new(0);

    struct TestDatabase(std::path::PathBuf);

    impl TestDatabase {
        fn new() -> Self {
            let sequence = NEXT_TEST_PATH.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "lattice-core-{}-{sequence}.sqlite",
                std::process::id()
            )))
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            let _ = std::fs::remove_file(format!("{}-wal", self.0.display()));
            let _ = std::fs::remove_file(format!("{}-shm", self.0.display()));
        }
    }

    /// Test-only passthrough; it is not suitable for real identity persistence.
    struct TestProtector;

    impl PrivateKeyProtector for TestProtector {
        fn wrap(&self, private_material: &[u8]) -> Result<Vec<u8>, PrivateKeyProtectionError> {
            Ok(private_material.to_vec())
        }

        fn unwrap(&self, ciphertext: &[u8]) -> Result<Vec<u8>, PrivateKeyProtectionError> {
            Ok(ciphertext.to_vec())
        }
    }

    fn test_credential(identity: &DeviceIdentity) -> DeviceCredentialInput {
        let credential = Credential::new(
            CredentialType::X509,
            VLBytes::new(b"test-only untrusted X.509 placeholder".to_vec())
                .tls_serialize_detached()
                .expect("test credential encodes"),
        );
        DeviceCredentialInput::from_x509_credential(identity, credential)
            .expect("device signer matches test credential")
    }

    fn event(identity: &DeviceIdentity, body: Vec<u8>, epoch: u64) -> VerifiedSignatureOnlyEvent {
        VerifiedSignatureOnlyEvent::create(
            identity,
            EventDraft {
                space_id: [1; 16],
                channel_id: None,
                author_sequence: 1,
                lamport: 1,
                wall_time_hint: 0,
                parents: Vec::new(),
                kind: EventKind::Message,
                protected_body: body,
                mls_group_reference: [2; 32],
                mls_epoch: epoch,
            },
        )
        .expect("event signature created")
    }

    #[test]
    fn mls_binding_rejects_wrong_author_and_ciphertext_before_releasing_plaintext() {
        let provider_alice = OpenMlsRustCrypto::default();
        let provider_bob = OpenMlsRustCrypto::default();
        let alice_identity = DeviceIdentity::generate().expect("Alice identity");
        let bob_identity = DeviceIdentity::generate().expect("Bob identity");
        let alice_credential = test_credential(&alice_identity);
        let bob_credential = test_credential(&bob_identity);
        let mut alice = GroupState::create(&provider_alice, &alice_identity, &alice_credential)
            .expect("create group");
        let bob_key_package =
            GroupState::publish_key_package(&provider_bob, &bob_identity, &bob_credential)
                .expect("publish Bob key package");
        let prepared = alice
            .prepare_add(
                &provider_alice,
                &alice_identity,
                &alice_credential,
                bob_key_package.as_bytes(),
            )
            .expect("prepare Bob add");
        let commit = prepared.commit().as_bytes().to_vec();
        let welcome = alice
            .accept_prepared_add(&provider_alice, &prepared, &commit)
            .expect("merge accepted add");
        let mut bob = GroupState::from_welcome(
            &provider_bob,
            &alice.group_id(),
            &alice_credential,
            welcome.as_bytes(),
        )
        .expect("join group");
        let wire = alice
            .encrypt_application(
                &provider_alice,
                &alice_identity,
                &alice_credential,
                b"authenticated event plaintext",
            )
            .expect("encrypt event payload")
            .as_bytes()
            .to_vec();
        let proof = match bob
            .process_incoming(&provider_bob, &wire)
            .expect("process MLS application")
        {
            IncomingResult::Application(proof) => proof,
            other => panic!("expected application result, got {other:?}"),
        };

        let mut altered_wire = wire.clone();
        altered_wire[0] ^= 1;
        assert!(matches!(
            bind_mls_application(event(&alice_identity, altered_wire, 1), proof.clone()),
            Err(CoreError::MlsEventBindingFailed)
        ));
        assert!(matches!(
            bind_mls_application(event(&bob_identity, wire.clone(), 1), proof.clone()),
            Err(CoreError::MlsEventBindingFailed)
        ));
        assert!(matches!(
            bind_mls_application(event(&alice_identity, wire.clone(), 2), proof.clone()),
            Err(CoreError::MlsEventBindingFailed)
        ));

        let bound = bind_mls_application(event(&alice_identity, wire, 1), proof)
            .expect("matching event and MLS proof bind");
        assert_eq!(bound.plaintext(), b"authenticated event plaintext");
        assert_eq!(
            bound.event().identity_bundle().ed25519_public_key(),
            alice_identity.public_key()
        );
    }

    #[test]
    fn identity_initialization_persists_ciphertext_and_reopens_same_public_identity() {
        let database = TestDatabase::new();
        let protector = TestProtector;
        let first_info = {
            let client =
                Client::open_or_create(&database.0, &protector).expect("initialize identity");
            assert_eq!(client.next_author_sequence().expect("first sequence"), 1);
            client.identity_info()
        };

        let reopened = Client::open_existing(&database.0, &protector).expect("reopen identity");
        assert_eq!(reopened.identity_info(), first_info);
        assert_eq!(reopened.next_author_sequence().expect("sequence"), 1);
    }

    #[test]
    fn existing_profile_open_fails_closed_when_identity_is_missing() {
        let database = TestDatabase::new();
        assert!(matches!(
            Client::open_existing(&database.0, &TestProtector),
            Err(CoreError::MissingIdentity)
        ));
    }
}
