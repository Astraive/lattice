use lattice_events::{EventKind, VerifiedSignatureOnlyEvent};
use lattice_identity::{DeviceIdentity, IdentityPublicBundle, verify};
use lattice_mls::api::{DeviceCredentialInput, GroupState, IncomingResult};
use lattice_protocol::{Value, decode_canonical, encode_canonical};
use lattice_storage::{SpaceGenesisSnapshot, SpaceWelcomeBootstrapSnapshot, Store};
use openmls::credentials::Credential;
use openmls::prelude::CredentialType;

use crate::{Client, CoreError, CreatedSpace, space, store_received_event};

pub const MAX_SPACE_WELCOME_BOOTSTRAP_BYTES: usize = 1_048_576;
const MAX_GROUP_ID_BYTES: usize = 256;
const BOOTSTRAP_SIGNATURE_DOMAIN: &[u8] = b"lattice:space-welcome-bootstrap:v1\0";

/// Version-one application package binding a validated MLS Welcome to a signed
/// Space policy checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpaceWelcomeBootstrapV1 {
    pub(crate) space_id: space::SpaceId,
    pub(crate) group_id: Vec<u8>,
    pub(crate) group_reference: space::GroupReference,
    pub(crate) epoch: u64,
    pub(crate) welcome: Vec<u8>,
    pub(crate) root_event: Vec<u8>,
    pub(crate) genesis_plaintext: Vec<u8>,
    pub(crate) policy_snapshot: Vec<u8>,
    pub(crate) invite_event: Vec<u8>,
    pub(crate) invite_plaintext: Vec<u8>,
    pub(crate) head_events: Vec<Vec<u8>>,
    pub(crate) last_control_event: Option<Vec<u8>>,
    pub(crate) inviter_bundle: [u8; 65],
    pub(crate) signature: [u8; 64],
}

impl SpaceWelcomeBootstrapV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sign(
        identity: &DeviceIdentity,
        space_id: space::SpaceId,
        group_id: Vec<u8>,
        group_reference: space::GroupReference,
        epoch: u64,
        welcome: Vec<u8>,
        root_event: Vec<u8>,
        genesis_plaintext: Vec<u8>,
        policy_snapshot: Vec<u8>,
        invite_event: Vec<u8>,
        invite_plaintext: Vec<u8>,
        head_events: Vec<Vec<u8>>,
        last_control_event: Option<Vec<u8>>,
    ) -> Result<Self, CoreError> {
        let inviter_bundle = identity.public_bundle().to_bytes();
        let mut package = Self {
            space_id,
            group_id,
            group_reference,
            epoch,
            welcome,
            root_event,
            genesis_plaintext,
            policy_snapshot,
            invite_event,
            invite_plaintext,
            head_events,
            last_control_event,
            inviter_bundle,
            signature: [0; 64],
        };
        package.validate_bounds()?;
        package.signature = identity.sign(&package.signature_input()?);
        let encoded = package.to_bytes()?;
        if encoded.len() > MAX_SPACE_WELCOME_BOOTSTRAP_BYTES {
            return Err(CoreError::SpaceWelcomeBootstrapInvalid);
        }
        Ok(package)
    }

    /// Decodes the exact version-one canonical CBOR package and verifies its
    /// inviter signature. Semantic MLS and Space validation is performed by
    /// `Client::join_space_from_welcome_bootstrap`.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::SpaceWelcomeBootstrapInvalid`] for malformed,
    /// non-canonical, oversized, or incorrectly signed packages.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.is_empty() || bytes.len() > MAX_SPACE_WELCOME_BOOTSTRAP_BYTES {
            return Err(CoreError::SpaceWelcomeBootstrapInvalid);
        }
        let Value::Map(mut fields) =
            decode_canonical(bytes).map_err(|_| CoreError::SpaceWelcomeBootstrapInvalid)?
        else {
            return Err(CoreError::SpaceWelcomeBootstrapInvalid);
        };
        if fields.len() != 14
            || fields
                .iter()
                .enumerate()
                .any(|(index, (key, _))| *key != index as u64)
        {
            return Err(CoreError::SpaceWelcomeBootstrapInvalid);
        }
        if take_unsigned(fields.first().map(|(_, value)| value))? != 1 {
            return Err(CoreError::SpaceWelcomeBootstrapInvalid);
        }
        let signature = take_fixed::<64>(fields.pop().map(|(_, value)| value))?;
        let preimage = encode_canonical(&Value::Map(fields.clone()))
            .map_err(|_| CoreError::SpaceWelcomeBootstrapInvalid)?;
        let package = Self {
            space_id: take_fixed(fields.get(1).map(|(_, value)| value.clone()))?,
            group_id: take_bytes(fields.get(2).map(|(_, value)| value.clone()))?,
            group_reference: take_fixed(fields.get(3).map(|(_, value)| value.clone()))?,
            epoch: take_unsigned(fields.get(4).map(|(_, value)| value))?,
            welcome: take_bytes(fields.get(5).map(|(_, value)| value.clone()))?,
            root_event: take_bytes(fields.get(6).map(|(_, value)| value.clone()))?,
            genesis_plaintext: take_bytes(fields.get(7).map(|(_, value)| value.clone()))?,
            policy_snapshot: take_bytes(fields.get(8).map(|(_, value)| value.clone()))?,
            invite_event: take_invite_bytes(fields.get(9).map(|(_, value)| value.clone()))?,
            invite_plaintext: take_invite_plaintext(fields.get(9).map(|(_, value)| value.clone()))?,
            head_events: take_byte_array(fields.get(10).map(|(_, value)| value.clone()))?,
            last_control_event: take_optional_bytes(
                fields.get(11).map(|(_, value)| value.clone()),
            )?,
            inviter_bundle: take_fixed(fields.get(12).map(|(_, value)| value.clone()))?,
            signature,
        };
        package.validate_bounds()?;
        let bundle = IdentityPublicBundle::from_bytes(&package.inviter_bundle)
            .map_err(|_| CoreError::SpaceWelcomeBootstrapInvalid)?;
        let mut message = Vec::with_capacity(BOOTSTRAP_SIGNATURE_DOMAIN.len() + preimage.len());
        message.extend_from_slice(BOOTSTRAP_SIGNATURE_DOMAIN);
        message.extend_from_slice(&preimage);
        verify(&bundle.ed25519_public_key(), &message, &package.signature)
            .map_err(|_| CoreError::SpaceWelcomeBootstrapInvalid)?;
        if package.to_bytes()?.as_slice() != bytes {
            return Err(CoreError::SpaceWelcomeBootstrapInvalid);
        }
        Ok(package)
    }

    /// Encodes this package as one bounded canonical version-one CBOR map.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::SpaceWelcomeBootstrapInvalid`] when a field or the
    /// resulting package violates the version-one bounds.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CoreError> {
        self.validate_bounds()?;
        let mut fields = self.unsigned_fields();
        fields.push((13, Value::Bytes(self.signature.to_vec())));
        let encoded = encode_canonical(&Value::Map(fields))
            .map_err(|_| CoreError::SpaceWelcomeBootstrapInvalid)?;
        if encoded.len() > MAX_SPACE_WELCOME_BOOTSTRAP_BYTES {
            return Err(CoreError::SpaceWelcomeBootstrapInvalid);
        }
        Ok(encoded)
    }

    fn signature_input(&self) -> Result<Vec<u8>, CoreError> {
        let encoded = encode_canonical(&Value::Map(self.unsigned_fields()))
            .map_err(|_| CoreError::SpaceWelcomeBootstrapInvalid)?;
        if encoded
            .len()
            .saturating_add(BOOTSTRAP_SIGNATURE_DOMAIN.len())
            > MAX_SPACE_WELCOME_BOOTSTRAP_BYTES
        {
            return Err(CoreError::SpaceWelcomeBootstrapInvalid);
        }
        let mut input = Vec::with_capacity(BOOTSTRAP_SIGNATURE_DOMAIN.len() + encoded.len());
        input.extend_from_slice(BOOTSTRAP_SIGNATURE_DOMAIN);
        input.extend_from_slice(&encoded);
        Ok(input)
    }

    fn unsigned_fields(&self) -> Vec<(u64, Value)> {
        vec![
            (0, Value::Unsigned(1)),
            (1, Value::Bytes(self.space_id.to_vec())),
            (2, Value::Bytes(self.group_id.clone())),
            (3, Value::Bytes(self.group_reference.to_vec())),
            (4, Value::Unsigned(self.epoch)),
            (5, Value::Bytes(self.welcome.clone())),
            (6, Value::Bytes(self.root_event.clone())),
            (7, Value::Bytes(self.genesis_plaintext.clone())),
            (8, Value::Bytes(self.policy_snapshot.clone())),
            (
                9,
                Value::Array(vec![
                    Value::Bytes(self.invite_event.clone()),
                    Value::Bytes(self.invite_plaintext.clone()),
                ]),
            ),
            (
                10,
                Value::Array(self.head_events.iter().cloned().map(Value::Bytes).collect()),
            ),
            (
                11,
                self.last_control_event
                    .as_ref()
                    .map_or(Value::Null, |event| Value::Bytes(event.clone())),
            ),
            (12, Value::Bytes(self.inviter_bundle.to_vec())),
        ]
    }

    fn validate_bounds(&self) -> Result<(), CoreError> {
        if self.group_id.is_empty()
            || self.group_id.len() > MAX_GROUP_ID_BYTES
            || self.welcome.is_empty()
            || self.root_event.is_empty()
            || self.genesis_plaintext.is_empty()
            || self.policy_snapshot.is_empty()
            || self.invite_event.is_empty()
            || self.invite_plaintext.is_empty()
            || self.head_events.is_empty()
            || self.head_events.len() > 64
            || self.head_events.iter().any(Vec::is_empty)
            || self.last_control_event.as_ref().is_some_and(Vec::is_empty)
        {
            return Err(CoreError::SpaceWelcomeBootstrapInvalid);
        }
        Ok(())
    }

    pub(crate) fn inviter_fingerprint(&self) -> Result<[u8; 32], CoreError> {
        let bundle = IdentityPublicBundle::from_bytes(&self.inviter_bundle)
            .map_err(|_| CoreError::SpaceWelcomeBootstrapInvalid)?;
        Ok(bundle.fingerprint())
    }
}

fn take_bytes(value: Option<Value>) -> Result<Vec<u8>, CoreError> {
    match value {
        Some(Value::Bytes(bytes)) if !bytes.is_empty() => Ok(bytes),
        _ => Err(CoreError::SpaceWelcomeBootstrapInvalid),
    }
}

fn take_unsigned(value: Option<&Value>) -> Result<u64, CoreError> {
    match value {
        Some(Value::Unsigned(number)) => Ok(*number),
        _ => Err(CoreError::SpaceWelcomeBootstrapInvalid),
    }
}

fn take_fixed<const N: usize>(value: Option<Value>) -> Result<[u8; N], CoreError> {
    match value {
        Some(Value::Bytes(bytes)) => bytes
            .try_into()
            .map_err(|_| CoreError::SpaceWelcomeBootstrapInvalid),
        _ => Err(CoreError::SpaceWelcomeBootstrapInvalid),
    }
}

fn take_optional_bytes(value: Option<Value>) -> Result<Option<Vec<u8>>, CoreError> {
    match value {
        Some(Value::Null) => Ok(None),
        Some(Value::Bytes(bytes)) if !bytes.is_empty() => Ok(Some(bytes)),
        _ => Err(CoreError::SpaceWelcomeBootstrapInvalid),
    }
}

fn take_invite_bytes(value: Option<Value>) -> Result<Vec<u8>, CoreError> {
    match value {
        Some(Value::Array(values)) if values.len() == 2 => match &values[0] {
            Value::Bytes(bytes) if !bytes.is_empty() => Ok(bytes.clone()),
            _ => Err(CoreError::SpaceWelcomeBootstrapInvalid),
        },
        _ => Err(CoreError::SpaceWelcomeBootstrapInvalid),
    }
}

fn take_invite_plaintext(value: Option<Value>) -> Result<Vec<u8>, CoreError> {
    match value {
        Some(Value::Array(values)) if values.len() == 2 => match &values[1] {
            Value::Bytes(bytes) if !bytes.is_empty() => Ok(bytes.clone()),
            _ => Err(CoreError::SpaceWelcomeBootstrapInvalid),
        },
        _ => Err(CoreError::SpaceWelcomeBootstrapInvalid),
    }
}

fn take_byte_array(value: Option<Value>) -> Result<Vec<Vec<u8>>, CoreError> {
    let Some(Value::Array(values)) = value else {
        return Err(CoreError::SpaceWelcomeBootstrapInvalid);
    };
    if values.is_empty() || values.len() > 64 {
        return Err(CoreError::SpaceWelcomeBootstrapInvalid);
    }
    values
        .into_iter()
        .map(|value| match value {
            Value::Bytes(bytes) if !bytes.is_empty() => Ok(bytes),
            _ => Err(CoreError::SpaceWelcomeBootstrapInvalid),
        })
        .collect()
}

impl Client {
    #[allow(clippy::too_many_lines)] // Keeps inviter attestation checks atomic and auditable.
    /// Creates a signed policy checkpoint for one already accepted Welcome.
    ///
    /// The inviter's local reducer and MLS roster must already show the exact
    /// invite target as active. The receiver validates the opaque Welcome before
    /// persisting the package.
    ///
    /// # Errors
    ///
    /// Returns an error when the inviter's reducer, stored events, MLS roster,
    /// or package fields do not agree.
    pub fn create_space_welcome_bootstrap(
        &mut self,
        joined_space: &CreatedSpace,
        welcome_wire: &[u8],
        invite_event: &VerifiedSignatureOnlyEvent,
        invite_plaintext: &[u8],
    ) -> Result<Vec<u8>, CoreError> {
        let policy = joined_space
            .reducer
            .policy()
            .ok_or(CoreError::SpaceWelcomeBootstrapInvalid)?;
        let inviter = self.identity.fingerprint();
        let invite_id = *invite_event.event_id().as_bytes();
        let invite = policy
            .invites
            .iter()
            .find(|candidate| candidate.event_id == invite_id)
            .ok_or(CoreError::SpaceWelcomeBootstrapInvalid)?;
        let target = invite.target;
        let stored_invite = self
            .store
            .load_event(&invite_id)?
            .ok_or(CoreError::SpaceWelcomeBootstrapInvalid)?;
        if stored_invite.canonical_bytes != invite_event.encoded_bytes()
            || invite_event.author_fingerprint() != &inviter
            || invite.uses == 0
            || !policy.members.iter().any(|member| {
                member.fingerprint == target && member.status == space::MemberStatus::Active
            })
        {
            return Err(CoreError::SpaceWelcomeBootstrapInvalid);
        }
        let root_snapshot = self
            .store
            .load_space_genesis_snapshot(&joined_space.space_id, &joined_space.group_reference)?
            .ok_or(CoreError::SpaceGenesisSnapshotNotFound)?;
        if root_snapshot.event_id != *joined_space.genesis_event.event_id().as_bytes() {
            return Err(CoreError::SpaceWelcomeBootstrapInvalid);
        }
        let root_context = crate::space_genesis_context(
            &root_snapshot.space_id,
            &root_snapshot.group_reference,
            &root_snapshot.event_id,
        );
        let encrypted_state = root_snapshot.encrypted_state.clone();
        let genesis_plaintext = self.with_mls_transaction(move |_, _, _| {
            lattice_mls::unprotect_local_record(&root_context, &encrypted_state)
                .map_err(CoreError::from)
        })?;
        let mut head_events = Vec::with_capacity(policy.heads.len());
        for head in &policy.heads {
            let record = self
                .store
                .load_event(head)?
                .ok_or(CoreError::SpaceWelcomeBootstrapInvalid)?;
            let event = VerifiedSignatureOnlyEvent::decode_verify(&record.canonical_bytes)?;
            if event.event_id().as_bytes() != head
                || event.space_id() != &joined_space.space_id
                || event.mls_group_reference() != &joined_space.group_reference
            {
                return Err(CoreError::SpaceWelcomeBootstrapInvalid);
            }
            head_events.push(event);
        }
        let transition_snapshots = self.store.list_space_membership_transition_snapshots(
            &joined_space.space_id,
            &joined_space.group_reference,
        )?;
        let last_control_event = if let Some(transition) = transition_snapshots.last() {
            let record = self
                .store
                .load_event(&transition.control_event_id)?
                .ok_or(CoreError::SpaceWelcomeBootstrapInvalid)?;
            Some(VerifiedSignatureOnlyEvent::decode_verify(
                &record.canonical_bytes,
            )?)
        } else {
            None
        };
        let expected_epoch = u64::try_from(transition_snapshots.len())
            .map_err(|_| CoreError::SpaceWelcomeBootstrapInvalid)?;
        let group_id = joined_space.group_id.clone();
        self.with_mls_transaction(move |identity, provider, _| {
            let group = GroupState::load(provider, &group_id)?;
            Self::build_space_welcome_bootstrap(
                identity,
                joined_space,
                &group,
                welcome_wire,
                &genesis_plaintext,
                invite_event,
                invite_plaintext,
                &head_events,
                last_control_event.as_ref(),
                target,
                expected_epoch,
            )
        })
    }

    pub(crate) fn build_space_welcome_bootstrap(
        identity: &DeviceIdentity,
        joined_space: &CreatedSpace,
        group: &GroupState,
        welcome_wire: &[u8],
        genesis_plaintext: &[u8],
        invite_event: &VerifiedSignatureOnlyEvent,
        invite_plaintext: &[u8],
        head_events: &[VerifiedSignatureOnlyEvent],
        last_control_event: Option<&VerifiedSignatureOnlyEvent>,
        target: [u8; 32],
        epoch: u64,
    ) -> Result<Vec<u8>, CoreError> {
        if welcome_wire.is_empty() || welcome_wire.len() > MAX_SPACE_WELCOME_BOOTSTRAP_BYTES {
            return Err(CoreError::SpaceWelcomeBootstrapInvalid);
        }
        let policy = joined_space
            .reducer
            .policy()
            .ok_or(CoreError::SpaceWelcomeBootstrapInvalid)?;
        let inviter = identity.fingerprint();
        if group.group_reference() != joined_space.group_reference
            || group.epoch() != epoch
            || !group.contains_member_identity(&target)
        {
            return Err(CoreError::SpaceWelcomeBootstrapInvalid);
        }
        validate_group_roster(group, policy)?;
        let reducer = space::SpaceReducer::from_welcome_bootstrap(
            &joined_space.genesis_event,
            genesis_plaintext,
            policy.clone(),
            invite_event,
            invite_plaintext,
            head_events,
            last_control_event,
            &inviter,
            &target,
            epoch,
        )
        .map_err(|_| CoreError::SpaceWelcomeBootstrapInvalid)?;
        if reducer.policy() != Some(policy) {
            return Err(CoreError::SpaceWelcomeBootstrapInvalid);
        }
        let package = SpaceWelcomeBootstrapV1::sign(
            identity,
            joined_space.space_id,
            joined_space.group_id.clone(),
            joined_space.group_reference,
            epoch,
            welcome_wire.to_vec(),
            joined_space.genesis_event.encoded_bytes().to_vec(),
            genesis_plaintext.to_vec(),
            crate::bootstrap_snapshot::encode_policy_snapshot(policy)?,
            invite_event.encoded_bytes().to_vec(),
            invite_plaintext.to_vec(),
            head_events
                .iter()
                .map(|event| event.encoded_bytes().to_vec())
                .collect(),
            last_control_event.map(|event| event.encoded_bytes().to_vec()),
        )?;
        package.to_bytes()
    }

    #[allow(clippy::too_many_lines)] // Validates and persists one all-or-nothing MLS join.
    /// Accepts a Welcome only with a locally pinned inviter and signed policy
    /// checkpoint, then commits the MLS group and protected package atomically.
    ///
    /// # Errors
    ///
    /// Returns an error for an unpinned inviter, invalid checkpoint or Welcome,
    /// identity mismatch, rejected credentials, or durable storage failure.
    pub fn join_space_from_welcome_bootstrap(
        &mut self,
        package_bytes: &[u8],
        expected_inviter: [u8; 32],
        credential: &DeviceCredentialInput,
    ) -> Result<CreatedSpace, CoreError> {
        let package = SpaceWelcomeBootstrapV1::from_bytes(package_bytes)?;
        let inviter = package.inviter_fingerprint()?;
        let Some(pinned) = self.pinned_identity(&expected_inviter)? else {
            return Err(CoreError::SpaceWelcomeBootstrapUntrustedInviter);
        };
        if inviter != expected_inviter || pinned.bundle().to_bytes() != package.inviter_bundle {
            return Err(CoreError::SpaceWelcomeBootstrapUntrustedInviter);
        }
        let target = *credential.identity_fingerprint();
        if target != self.identity.fingerprint() {
            return Err(CoreError::SpaceCredentialInvalid);
        }
        let policy = crate::bootstrap_snapshot::decode_policy_snapshot(
            &package.policy_snapshot,
            package.space_id,
            package.group_reference,
        )?;
        let root_event = VerifiedSignatureOnlyEvent::decode_verify(&package.root_event)?;
        let invite_event = VerifiedSignatureOnlyEvent::decode_verify(&package.invite_event)?;
        let head_events = package
            .head_events
            .iter()
            .map(|bytes| VerifiedSignatureOnlyEvent::decode_verify(bytes))
            .collect::<Result<Vec<_>, _>>()?;
        let last_control_event = package
            .last_control_event
            .as_deref()
            .map(VerifiedSignatureOnlyEvent::decode_verify)
            .transpose()?;
        let invite_target = policy
            .invites
            .iter()
            .find(|invite| invite.event_id == *invite_event.event_id().as_bytes())
            .map(|invite| invite.target)
            .ok_or(CoreError::SpaceWelcomeBootstrapInvalid)?;
        if invite_target != target
            || root_event.encoded_bytes() != package.root_event
            || root_event.space_id() != &package.space_id
            || root_event.mls_group_reference() != &package.group_reference
            || invite_event.space_id() != &package.space_id
            || invite_event.mls_group_reference() != &package.group_reference
        {
            return Err(CoreError::SpaceWelcomeBootstrapInvalid);
        }
        let package_bytes = package.to_bytes()?;
        let protected_package_context = welcome_bootstrap_context(
            &package.space_id,
            &package.group_reference,
            root_event.event_id().as_bytes(),
        );
        let protected_genesis_context = crate::space_genesis_context(
            &package.space_id,
            &package.group_reference,
            root_event.event_id().as_bytes(),
        );
        let group_id = package.group_id.clone();
        let welcome = package.welcome.clone();
        let genesis_plaintext = package.genesis_plaintext.clone();
        let package_for_transaction = package.clone();
        let policy_for_transaction = policy.clone();
        let inviter_fingerprint = inviter;
        let root_event_for_transaction = root_event.clone();
        let (group_reference, reducer) =
            self.with_mls_transaction(move |identity, provider, transaction| {
                if identity.fingerprint() != target {
                    return Err(CoreError::SpaceCredentialInvalid);
                }
                let consumed_key_package =
                    lattice_mls::api::welcome_key_package_reference(provider, &welcome)?;
                let group = GroupState::from_welcome(provider, &group_id, credential, &welcome)?;
                if group.group_reference() != package_for_transaction.group_reference
                    || group.epoch() != package_for_transaction.epoch
                    || !group.contains_member_identity(&target)
                    || !group.contains_member_identity(&inviter_fingerprint)
                {
                    return Err(CoreError::SpaceWelcomeBootstrapInvalid);
                }
                validate_group_roster(&group, &policy_for_transaction)?;
                let reducer = space::SpaceReducer::from_welcome_bootstrap(
                    &root_event_for_transaction,
                    &genesis_plaintext,
                    policy_for_transaction,
                    &invite_event,
                    &package_for_transaction.invite_plaintext,
                    &head_events,
                    last_control_event.as_ref(),
                    &inviter_fingerprint,
                    &target,
                    package_for_transaction.epoch,
                )
                .map_err(|_| CoreError::SpaceWelcomeBootstrapInvalid)?;
                store_received_event(transaction, &root_event_for_transaction)?;
                if let Some(control) = &last_control_event {
                    store_received_event(transaction, control)?;
                }
                store_received_event(transaction, &invite_event)?;
                for head in &head_events {
                    if head.event_id() != invite_event.event_id() {
                        store_received_event(transaction, head)?;
                    }
                }
                if let Some(reference) = consumed_key_package {
                    Store::consume_key_package_in_transaction(transaction, &reference)?;
                }
                let encrypted_genesis = lattice_mls::protect_local_record(
                    &protected_genesis_context,
                    &genesis_plaintext,
                )?;
                let encrypted_package =
                    lattice_mls::protect_local_record(&protected_package_context, &package_bytes)?;
                Store::save_space_genesis_snapshot_in_transaction(
                    transaction,
                    &SpaceGenesisSnapshot {
                        space_id: package_for_transaction.space_id,
                        group_reference: package_for_transaction.group_reference,
                        group_id: package_for_transaction.group_id.clone(),
                        event_id: *root_event_for_transaction.event_id().as_bytes(),
                        encrypted_state: encrypted_genesis,
                    },
                )?;
                Store::save_space_welcome_bootstrap_snapshot_in_transaction(
                    transaction,
                    &SpaceWelcomeBootstrapSnapshot {
                        space_id: package_for_transaction.space_id,
                        group_reference: package_for_transaction.group_reference,
                        root_event_id: *root_event_for_transaction.event_id().as_bytes(),
                        encrypted_package,
                    },
                )?;
                Ok((group.group_reference(), reducer))
            })?;
        Ok(CreatedSpace {
            space_id: package.space_id,
            group_id: package.group_id,
            group_reference,
            genesis_event: root_event,
            reducer,
        })
    }
    /// Joins one signed Welcome package after validating an RFC 9420 X.509
    /// credential vector against the local device identity and trust policy.
    ///
    /// # Errors
    ///
    /// Returns `SpaceCredentialInvalid` for malformed or untrusted credential
    /// content, or the original join error for any rejected package or profile
    /// transaction.
    pub fn join_space_from_welcome_bootstrap_from_x509_credential(
        &mut self,
        package_bytes: &[u8],
        expected_inviter: [u8; 32],
        credential_content: Vec<u8>,
    ) -> Result<CreatedSpace, CoreError> {
        if credential_content.is_empty()
            || credential_content.len() > crate::MAX_SPACE_CREDENTIAL_BYTES
        {
            return Err(CoreError::SpaceCredentialInvalid);
        }
        let credential = Credential::new(CredentialType::X509, credential_content);
        let credential = DeviceCredentialInput::from_x509_credential(&self.identity, credential)
            .map_err(|_| CoreError::SpaceCredentialInvalid)?;
        self.join_space_from_welcome_bootstrap(package_bytes, expected_inviter, &credential)
    }

    #[allow(clippy::too_many_lines)] // Restore keeps package, replay, and MLS checks fail-closed.
    pub(crate) fn restore_joined_space(
        &mut self,
        local_snapshot: &SpaceGenesisSnapshot,
        event: VerifiedSignatureOnlyEvent,
        joined_snapshot: &SpaceWelcomeBootstrapSnapshot,
    ) -> Result<CreatedSpace, CoreError> {
        if joined_snapshot.root_event_id != local_snapshot.event_id
            || joined_snapshot.space_id != local_snapshot.space_id
            || joined_snapshot.group_reference != local_snapshot.group_reference
            || event.event_id().as_bytes() != &local_snapshot.event_id
        {
            return Err(CoreError::SpaceWelcomeBootstrapInvalid);
        }
        let package_context = welcome_bootstrap_context(
            &local_snapshot.space_id,
            &local_snapshot.group_reference,
            &local_snapshot.event_id,
        );
        let encrypted_package = joined_snapshot.encrypted_package.clone();
        let genesis_context = crate::space_genesis_context(
            &local_snapshot.space_id,
            &local_snapshot.group_reference,
            &local_snapshot.event_id,
        );
        let encrypted_genesis = local_snapshot.encrypted_state.clone();
        let (package_bytes, genesis_plaintext) = self.with_mls_transaction(move |_, _, _| {
            let package =
                lattice_mls::unprotect_local_record(&package_context, &encrypted_package)?;
            let genesis =
                lattice_mls::unprotect_local_record(&genesis_context, &encrypted_genesis)?;
            Ok::<_, CoreError>((package, genesis))
        })?;
        let package = SpaceWelcomeBootstrapV1::from_bytes(&package_bytes)?;
        if package.space_id != local_snapshot.space_id
            || package.group_reference != local_snapshot.group_reference
            || package.group_id != local_snapshot.group_id
            || package.root_event != event.encoded_bytes()
            || package.genesis_plaintext != genesis_plaintext
        {
            return Err(CoreError::SpaceWelcomeBootstrapInvalid);
        }
        let inviter = package.inviter_fingerprint()?;
        let Some(pinned) = self.pinned_identity(&inviter)? else {
            return Err(CoreError::SpaceWelcomeBootstrapUntrustedInviter);
        };
        if pinned.bundle().to_bytes() != package.inviter_bundle {
            return Err(CoreError::SpaceWelcomeBootstrapUntrustedInviter);
        }
        let policy = crate::bootstrap_snapshot::decode_policy_snapshot(
            &package.policy_snapshot,
            package.space_id,
            package.group_reference,
        )?;
        let invite_event = VerifiedSignatureOnlyEvent::decode_verify(&package.invite_event)?;
        let target = policy
            .invites
            .iter()
            .find(|invite| invite.event_id == *invite_event.event_id().as_bytes())
            .map(|invite| invite.target)
            .ok_or(CoreError::SpaceWelcomeBootstrapInvalid)?;
        let head_events = package
            .head_events
            .iter()
            .map(|bytes| VerifiedSignatureOnlyEvent::decode_verify(bytes))
            .collect::<Result<Vec<_>, _>>()?;
        let last_control_event = package
            .last_control_event
            .as_deref()
            .map(VerifiedSignatureOnlyEvent::decode_verify)
            .transpose()?;
        let space_id = package.space_id;
        let group_reference = package.group_reference;
        let transition_snapshots = self
            .store
            .list_space_membership_transition_snapshots(&space_id, &group_reference)?;
        let mut transition_events = Vec::with_capacity(transition_snapshots.len());
        for snapshot in transition_snapshots {
            if snapshot.space_id != space_id || snapshot.group_reference != group_reference {
                return Err(CoreError::SpaceMembershipSnapshotInvalid);
            }
            let control = self
                .store
                .load_event(&snapshot.control_event_id)?
                .ok_or(CoreError::SpaceMembershipSnapshotInvalid)?;
            let transition = self
                .store
                .load_event(&snapshot.transition_event_id)?
                .ok_or(CoreError::SpaceMembershipSnapshotInvalid)?;
            transition_events.push((
                snapshot,
                control.canonical_bytes,
                transition.canonical_bytes,
            ));
        }
        let expected_epoch = package
            .epoch
            .checked_add(transition_events.len() as u64)
            .ok_or(CoreError::SpaceMembershipSnapshotInvalid)?;
        let conflict_snapshot = self
            .store
            .load_space_membership_conflict(&space_id, &group_reference)?;
        let conflict_events = if let Some(conflict) = &conflict_snapshot {
            if conflict.space_id != space_id || conflict.group_reference != group_reference {
                return Err(CoreError::SpaceMembershipSnapshotInvalid);
            }
            let first = self
                .store
                .load_event(&conflict.first_control_event_id)?
                .ok_or(CoreError::SpaceMembershipSnapshotInvalid)?;
            let second = self
                .store
                .load_event(&conflict.second_control_event_id)?
                .ok_or(CoreError::SpaceMembershipSnapshotInvalid)?;
            Some((
                conflict.clone(),
                first.canonical_bytes,
                second.canonical_bytes,
            ))
        } else {
            None
        };
        let mut reducer = space::SpaceReducer::from_welcome_bootstrap(
            &event,
            &genesis_plaintext,
            policy,
            &invite_event,
            &package.invite_plaintext,
            &head_events,
            last_control_event.as_ref(),
            &inviter,
            &target,
            package.epoch,
        )
        .map_err(|_| CoreError::SpaceWelcomeBootstrapInvalid)?;
        let group_id = package.group_id.clone();
        let reducer = self.with_mls_transaction(move |_, provider, _| {
            let mut group = GroupState::load(provider, &group_id)?;
            if group.group_reference() != group_reference || group.epoch() != expected_epoch {
                return Err(CoreError::SpaceMembershipSnapshotInvalid);
            }
            crate::replay_space_membership_transitions(&mut reducer, transition_events)?;
            let policy = reducer
                .policy()
                .ok_or(CoreError::SpaceMembershipSnapshotInvalid)?;
            validate_group_roster(&group, policy)?;
            crate::validate_restored_membership_state(&group, &reducer, expected_epoch)?;
            if let Some((conflict, first_bytes, second_bytes)) = conflict_events {
                if group.epoch() != conflict.parent_epoch {
                    return Err(CoreError::SpaceMembershipSnapshotInvalid);
                }
                let first = VerifiedSignatureOnlyEvent::decode_verify(&first_bytes)?;
                let second = VerifiedSignatureOnlyEvent::decode_verify(&second_bytes)?;
                if first.event_id().as_bytes() != &conflict.first_control_event_id
                    || second.event_id().as_bytes() != &conflict.second_control_event_id
                    || [&first, &second].into_iter().any(|control| {
                        control.space_id() != &space_id
                            || control.mls_group_reference() != &group_reference
                            || control.mls_epoch() != conflict.parent_epoch
                            || control.kind() != EventKind::MlsControl
                            || control.channel_id().is_some()
                    })
                {
                    return Err(CoreError::SpaceMembershipSnapshotInvalid);
                }
                if !matches!(
                    group.process_incoming(provider, first.protected_body())?,
                    IncomingResult::StagedCommit { parent_epoch, .. }
                        if parent_epoch == conflict.parent_epoch
                ) || !matches!(
                    group.process_incoming(provider, second.protected_body()),
                    Err(lattice_mls::api::MlsError::ConflictDetected { parent_epoch })
                        if parent_epoch == conflict.parent_epoch
                ) {
                    return Err(CoreError::SpaceMembershipSnapshotInvalid);
                }
                let evidence = group
                    .conflict_evidence()
                    .ok_or(CoreError::SpaceMembershipSnapshotInvalid)?;
                if evidence.parent_epoch() != conflict.parent_epoch
                    || evidence.first_commit() != first.protected_body()
                    || evidence.second_commit() != second.protected_body()
                {
                    return Err(CoreError::SpaceMembershipSnapshotInvalid);
                }
                let first_proof = evidence
                    .first_membership_change()
                    .cloned()
                    .ok_or(CoreError::SpaceMembershipSnapshotInvalid)?;
                let second_proof = evidence
                    .second_membership_change()
                    .cloned()
                    .ok_or(CoreError::SpaceMembershipSnapshotInvalid)?;
                reducer
                    .observe_validated_control_event(&first, first_proof)
                    .map_err(CoreError::SpaceControlRejected)?;
                reducer
                    .observe_validated_control_event(&second, second_proof)
                    .map_err(CoreError::SpaceControlRejected)?;
                reducer.mark_membership_conflicted(&first, &second);
            }
            Ok(reducer)
        })?;
        Ok(CreatedSpace {
            space_id,
            group_id: package.group_id,
            group_reference,
            genesis_event: event,
            reducer,
        })
    }
}

fn validate_group_roster(group: &GroupState, policy: &space::SpacePolicy) -> Result<(), CoreError> {
    let active_count = policy
        .members
        .iter()
        .filter(|member| member.status == space::MemberStatus::Active)
        .count();
    if active_count != group.member_count()
        || policy
            .members
            .iter()
            .filter(|member| member.status == space::MemberStatus::Active)
            .any(|member| !group.contains_member_identity(&member.fingerprint))
    {
        return Err(CoreError::SpaceWelcomeBootstrapInvalid);
    }
    Ok(())
}

fn welcome_bootstrap_context(
    space_id: &space::SpaceId,
    group_reference: &space::GroupReference,
    root_event_id: &[u8; 32],
) -> Vec<u8> {
    let mut context = Vec::with_capacity(42 + 16 + 32 + 32);
    context.extend_from_slice(b"lattice-space-welcome-bootstrap-local-v1\0");
    context.extend_from_slice(space_id);
    context.extend_from_slice(group_reference);
    context.extend_from_slice(root_event_id);
    context
}

#[cfg(test)]
mod vector_tests {
    use super::{BOOTSTRAP_SIGNATURE_DOMAIN, SpaceWelcomeBootstrapV1};

    #[test]
    fn version_one_package_interoperability_vector_is_canonical_and_signed() {
        let vector = include_str!("../../../protocol/vectors/space-welcome-bootstrap-v1.json");
        let package_hex = vector
            .lines()
            .find_map(|line| {
                line.trim()
                    .strip_prefix("\"package_hex\": \"")
                    .and_then(|value| value.strip_suffix('"'))
            })
            .expect("package hex in protocol vector");
        let package_bytes = decode_hex(package_hex);
        let package =
            SpaceWelcomeBootstrapV1::from_bytes(&package_bytes).expect("verify signed vector");
        assert_eq!(
            package.to_bytes().expect("canonical package"),
            package_bytes
        );
        assert_eq!(package.space_id, [0x11; 16]);
        assert_eq!(package.group_id, b"test-group");
        assert_eq!(
            package.group_reference,
            [
                0xbf, 0xc5, 0x8f, 0xc3, 0x2f, 0x3a, 0x43, 0xd8, 0xf8, 0xb2, 0x0e, 0xd9, 0xfa, 0x48,
                0x0a, 0xb8, 0xec, 0x45, 0x6d, 0x90, 0x87, 0x7e, 0x48, 0x6c, 0xcf, 0x3c, 0x0e, 0x0e,
                0x0e, 0x34, 0x4a, 0x02,
            ]
        );
        assert_eq!(package.epoch, 0);
        assert_eq!(package.welcome, [0x44]);
        assert_eq!(package.root_event, [0x55]);
        assert_eq!(package.genesis_plaintext, [0x66]);
        assert_eq!(package.policy_snapshot, [0x77]);
        assert_eq!(package.invite_event, [0x88]);
        assert_eq!(package.invite_plaintext, [0x99]);
        assert_eq!(package.head_events, [vec![0xaa]]);
        assert_eq!(package.last_control_event, None);
    }

    #[test]
    fn rejects_a_signed_unsupported_package_version() {
        use lattice_identity::DeviceIdentity;
        use lattice_protocol::{Value, encode_canonical};

        let identity = DeviceIdentity::generate().expect("generate inviter identity");
        let package = SpaceWelcomeBootstrapV1::sign(
            &identity,
            [0x11; 16],
            b"group".to_vec(),
            [0x22; 32],
            0,
            vec![1],
            vec![2],
            vec![3],
            vec![4],
            vec![5],
            vec![6],
            vec![vec![7]],
            None,
        )
        .expect("sign version-one package");
        let mut fields = package.unsigned_fields();
        fields[0].1 = Value::Unsigned(2);
        let preimage =
            encode_canonical(&Value::Map(fields.clone())).expect("encode unsupported package");
        let mut message = BOOTSTRAP_SIGNATURE_DOMAIN.to_vec();
        message.extend_from_slice(&preimage);
        fields.push((13, Value::Bytes(identity.sign(&message).to_vec())));
        let encoded = encode_canonical(&Value::Map(fields)).expect("encode signed package");

        assert!(matches!(
            SpaceWelcomeBootstrapV1::from_bytes(&encoded),
            Err(crate::CoreError::SpaceWelcomeBootstrapInvalid)
        ));
    }

    fn decode_hex(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|digits| {
                let digit = |value: u8| match value {
                    b'0'..=b'9' => value - b'0',
                    b'a'..=b'f' => value - b'a' + 10,
                    _ => panic!("invalid lowercase hex digit"),
                };
                digit(digits[0]) * 16 + digit(digits[1])
            })
            .collect()
    }
}
