use lattice_events::{EventKind, VerifiedSignatureOnlyEvent};
use thiserror::Error;

use lattice_identity::{DeviceIdentity, IdentityPublicBundle, verify};
use lattice_protocol::{Value, decode_canonical, encode_canonical};

use crate::space::effective_space;
use crate::space::{SpaceId, SpacePolicy};

/// Maximum canonical version-one invitation payload size.
pub const MAX_SPACE_INVITE_BYTES: usize = 16_384;
const SIGNATURE_DOMAIN: &[u8] = b"lattice:space-invite:v1\0";

/// Failure while decoding or checking a signed Space invitation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SpaceInviteError {
    /// The invite is malformed, non-canonical, oversized, or has an invalid signature.
    #[error("Space invitation is invalid")]
    Invalid,
    /// The signed wall-clock expiry has passed, or the policy revision expired it.
    #[error("Space invitation has expired")]
    Expired,
    /// The invitation does not match the supplied active Space policy or inviter.
    #[error("Space invitation does not match the active Space policy")]
    WrongPolicy,
    /// The accepted policy has already consumed the permitted invitation uses.
    #[error("Space invitation use limit has been reached")]
    Exhausted,
}

/// Type of an untrusted rendezvous hint carried by an invite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpaceInviteHintKind {
    /// Nearby Bluetooth discovery hint.
    Ble,
    /// Suggested WebSocket relay URL; installation policy still decides whether to use it.
    RelayUrl,
    /// Local-network discovery hint.
    Lan,
}

/// Untrusted, bounded connectivity hint included in a signed invite.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpaceInviteHint {
    /// Transport family.
    pub kind: SpaceInviteHintKind,
    /// Hint bytes represented as UTF-8 text; never grants membership or trust.
    pub value: String,
}

/// Maximum rendezvous hints in one invitation.
pub const MAX_SPACE_INVITE_HINTS: usize = 8;
const MAX_SPACE_INVITE_HINT_BYTES: usize = 256;

/// Bounded signed invitation token bound to one accepted policy invite record.
///
/// Signature validity alone does not authorize membership. Consumers must pin
/// `inviter_fingerprint`, verify the inviter's current `MEMBER_INVITE` authority,
/// and validate this token against the current reducer policy. The policy's
/// revision expiry and use counter are authoritative during peer synchronization;
/// wall-clock expiry is an additional local rejection check. Rendezvous hints
/// are untrusted and do not override local network settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpaceInviteV1 {
    space_id: SpaceId,
    genesis_event_id: [u8; 32],
    invite_event_id: [u8; 32],
    invite_id: [u8; 16],
    target: [u8; 32],
    key_package_hash: [u8; 32],
    expires_at_unix_seconds: u64,
    max_uses: Option<u16>,
    nonce: [u8; 16],
    rendezvous_hints: Vec<SpaceInviteHint>,
    inviter_bundle: [u8; 65],
    signature: [u8; 64],
}

impl SpaceInviteV1 {
    /// Signs a token for a policy invite record; policy authorization remains
    /// checked by [`Self::validate_for_policy`] at import and before admission.
    ///
    /// `expires_at_unix_seconds` is a signed local expiry hint, while the
    /// referenced policy record's revision expiry and use count provide the
    /// deterministic peer-synchronized limits.
    ///
    /// # Errors
    ///
    /// Returns [`SpaceInviteError::Invalid`] for a zero expiry, invalid use
    /// limit, or malformed rendezvous hint.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        identity: &DeviceIdentity,
        space_id: SpaceId,
        genesis_event_id: [u8; 32],
        invite_event_id: [u8; 32],
        invite_id: [u8; 16],
        target: [u8; 32],
        key_package_hash: [u8; 32],
        expires_at_unix_seconds: u64,
        max_uses: Option<u16>,
        nonce: [u8; 16],
        rendezvous_hints: Vec<SpaceInviteHint>,
    ) -> Result<Self, SpaceInviteError> {
        if expires_at_unix_seconds == 0 || max_uses == Some(0) || !valid_hints(&rendezvous_hints) {
            return Err(SpaceInviteError::Invalid);
        }
        let mut invite = Self {
            space_id,
            genesis_event_id,
            invite_event_id,
            invite_id,
            target,
            key_package_hash,
            expires_at_unix_seconds,
            max_uses,
            nonce,
            rendezvous_hints,
            inviter_bundle: identity.public_bundle().to_bytes(),
            signature: [0; 64],
        };
        invite.signature = identity.sign(&invite.signature_input()?);
        Ok(invite)
    }

    /// Decodes canonical version-one bytes and verifies the inviter signature.
    ///
    /// # Errors
    ///
    /// Returns [`SpaceInviteError::Invalid`] for any malformed, unsupported,
    /// non-canonical, oversized, or incorrectly signed token.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SpaceInviteError> {
        if bytes.is_empty() || bytes.len() > MAX_SPACE_INVITE_BYTES {
            return Err(SpaceInviteError::Invalid);
        }
        let Value::Map(fields) = decode_canonical(bytes).map_err(|_| SpaceInviteError::Invalid)?
        else {
            return Err(SpaceInviteError::Invalid);
        };
        if fields.len() != 14
            || fields
                .iter()
                .enumerate()
                .any(|(index, (key, _))| *key != index as u64)
            || number(&fields[0].1)? != 1
            || number(&fields[10].1)? != 0
        {
            return Err(SpaceInviteError::Invalid);
        }
        let invite = Self {
            space_id: fixed(&fields[1].1)?,
            genesis_event_id: fixed(&fields[2].1)?,
            invite_event_id: fixed(&fields[3].1)?,
            invite_id: fixed(&fields[4].1)?,
            target: fixed(&fields[5].1)?,
            key_package_hash: fixed(&fields[6].1)?,
            expires_at_unix_seconds: number(&fields[7].1)?,
            max_uses: optional_limit(&fields[8].1)?,
            nonce: fixed(&fields[9].1)?,
            rendezvous_hints: parse_hints(&fields[11].1)?,
            inviter_bundle: fixed(&fields[12].1)?,
            signature: fixed(&fields[13].1)?,
        };
        if invite.expires_at_unix_seconds == 0 {
            return Err(SpaceInviteError::Invalid);
        }
        let bundle = IdentityPublicBundle::from_bytes(&invite.inviter_bundle)
            .map_err(|_| SpaceInviteError::Invalid)?;
        verify(
            &bundle.ed25519_public_key(),
            &invite.signature_input()?,
            &invite.signature,
        )
        .map_err(|_| SpaceInviteError::Invalid)?;
        if invite.to_bytes()?.as_slice() != bytes {
            return Err(SpaceInviteError::Invalid);
        }
        Ok(invite)
    }

    /// Encodes the exact canonical version-one invitation.
    ///
    /// # Errors
    ///
    /// Returns [`SpaceInviteError::Invalid`] if canonical encoding fails or the
    /// encoded token exceeds [`MAX_SPACE_INVITE_BYTES`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, SpaceInviteError> {
        let mut fields = self.unsigned_fields();
        fields.push((13, Value::Bytes(self.signature.to_vec())));
        let bytes = encode_canonical(&Value::Map(fields)).map_err(|_| SpaceInviteError::Invalid)?;
        if bytes.len() > MAX_SPACE_INVITE_BYTES {
            return Err(SpaceInviteError::Invalid);
        }
        Ok(bytes)
    }

    /// Checks signer, Space genesis, wall-clock expiry, and current policy limits.
    ///
    /// A relay never supplies authority: `policy` must be the reducer's current
    /// authenticated projection, and `expected_inviter` must be a locally pinned
    /// identity whose current invite permission the caller has checked.
    ///
    /// # Errors
    ///
    /// Returns `WrongPolicy`, `Expired`, or `Exhausted` when current state rejects
    /// the token.
    pub fn validate_for_policy(
        &self,
        policy: &SpacePolicy,
        invite_event: &VerifiedSignatureOnlyEvent,
        expected_inviter: &[u8; 32],
        now_unix_seconds: u64,
    ) -> Result<(), SpaceInviteError> {
        let inviter = self.inviter_fingerprint()?;
        if inviter != *expected_inviter
            || invite_event.author_fingerprint() != expected_inviter
            || invite_event.event_id().as_bytes() != &self.invite_event_id
            || invite_event.kind() != EventKind::Membership
            || invite_event.channel_id().is_some()
            || invite_event.space_id() != &policy.space_id
            || invite_event.mls_group_reference() != &policy.group_reference
            || self.space_id != policy.space_id
            || self.genesis_event_id != policy.root_event_id
            || effective_space(policy, expected_inviter)
                & crate::space::INVITE_PERMISSION_REQUIREMENTS
                != crate::space::INVITE_PERMISSION_REQUIREMENTS
        {
            return Err(SpaceInviteError::WrongPolicy);
        }
        if now_unix_seconds >= self.expires_at_unix_seconds
            || policy
                .invites
                .iter()
                .find(|record| record.event_id == self.invite_event_id)
                .is_some_and(|record| {
                    record
                        .expires_at_revision
                        .is_some_and(|expiry| policy.revision >= expiry)
                })
        {
            return Err(SpaceInviteError::Expired);
        }
        let Some(record) = policy
            .invites
            .iter()
            .find(|record| record.event_id == self.invite_event_id)
        else {
            return Err(SpaceInviteError::WrongPolicy);
        };
        if record.id != self.invite_id
            || record.target != self.target
            || record.key_package_hash != self.key_package_hash
            || record.max_uses != self.max_uses
        {
            return Err(SpaceInviteError::WrongPolicy);
        }
        if record
            .max_uses
            .is_some_and(|maximum| record.uses >= maximum)
        {
            return Err(SpaceInviteError::Exhausted);
        }
        Ok(())
    }

    /// Returns the inviter's full public-identity fingerprint.
    ///
    /// # Errors
    ///
    /// Returns [`SpaceInviteError::Invalid`] if the embedded public identity
    /// bundle is malformed.
    pub fn inviter_fingerprint(&self) -> Result<[u8; 32], SpaceInviteError> {
        Ok(IdentityPublicBundle::from_bytes(&self.inviter_bundle)
            .map_err(|_| SpaceInviteError::Invalid)?
            .fingerprint())
    }

    /// Returns the event ID of the accepted MLS-authenticated invite policy.
    #[must_use]
    pub const fn invite_event_id(&self) -> &[u8; 32] {
        &self.invite_event_id
    }

    /// Returns the target device fingerprint.
    #[must_use]
    pub const fn target(&self) -> &[u8; 32] {
        &self.target
    }

    /// Returns the signed single-use token nonce.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; 16] {
        &self.nonce
    }
    /// Returns the invitation's rendezvous hints in signed order.
    #[must_use]
    pub fn rendezvous_hints(&self) -> &[SpaceInviteHint] {
        &self.rendezvous_hints
    }

    /// Returns the signed Unix expiry time.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }

    /// Returns the optional accepted-use limit.
    #[must_use]
    pub const fn max_uses(&self) -> Option<u16> {
        self.max_uses
    }

    fn signature_input(&self) -> Result<Vec<u8>, SpaceInviteError> {
        let encoded = encode_canonical(&Value::Map(self.unsigned_fields()))
            .map_err(|_| SpaceInviteError::Invalid)?;
        if encoded.len().saturating_add(SIGNATURE_DOMAIN.len()) > MAX_SPACE_INVITE_BYTES {
            return Err(SpaceInviteError::Invalid);
        }
        let mut input = Vec::with_capacity(SIGNATURE_DOMAIN.len() + encoded.len());
        input.extend_from_slice(SIGNATURE_DOMAIN);
        input.extend_from_slice(&encoded);
        Ok(input)
    }

    fn unsigned_fields(&self) -> Vec<(u64, Value)> {
        vec![
            (0, Value::Unsigned(1)),
            (1, Value::Bytes(self.space_id.to_vec())),
            (2, Value::Bytes(self.genesis_event_id.to_vec())),
            (3, Value::Bytes(self.invite_event_id.to_vec())),
            (4, Value::Bytes(self.invite_id.to_vec())),
            (5, Value::Bytes(self.target.to_vec())),
            (6, Value::Bytes(self.key_package_hash.to_vec())),
            (7, Value::Unsigned(self.expires_at_unix_seconds)),
            (
                8,
                self.max_uses
                    .map_or(Value::Null, |limit| Value::Unsigned(u64::from(limit))),
            ),
            (9, Value::Bytes(self.nonce.to_vec())),
            (10, Value::Unsigned(0)),
            (
                11,
                Value::Array(
                    self.rendezvous_hints
                        .iter()
                        .map(|hint| {
                            Value::Array(vec![
                                Value::Unsigned(hint_kind_code(hint.kind)),
                                Value::Text(hint.value.clone()),
                            ])
                        })
                        .collect(),
                ),
            ),
            (12, Value::Bytes(self.inviter_bundle.to_vec())),
        ]
    }
}

fn valid_hints(hints: &[SpaceInviteHint]) -> bool {
    hints.len() <= MAX_SPACE_INVITE_HINTS
        && hints.iter().all(|hint| {
            !hint.value.is_empty()
                && hint.value.len() <= MAX_SPACE_INVITE_HINT_BYTES
                && !hint.value.chars().any(char::is_control)
        })
}

fn parse_hints(value: &Value) -> Result<Vec<SpaceInviteHint>, SpaceInviteError> {
    let Value::Array(values) = value else {
        return Err(SpaceInviteError::Invalid);
    };
    if values.len() > MAX_SPACE_INVITE_HINTS {
        return Err(SpaceInviteError::Invalid);
    }
    let mut hints = Vec::with_capacity(values.len());
    for value in values {
        let Value::Array(fields) = value else {
            return Err(SpaceInviteError::Invalid);
        };
        if fields.len() != 2 {
            return Err(SpaceInviteError::Invalid);
        }
        let kind = match number(&fields[0])? {
            0 => SpaceInviteHintKind::Ble,
            1 => SpaceInviteHintKind::RelayUrl,
            2 => SpaceInviteHintKind::Lan,
            _ => return Err(SpaceInviteError::Invalid),
        };
        let Value::Text(value) = &fields[1] else {
            return Err(SpaceInviteError::Invalid);
        };
        hints.push(SpaceInviteHint {
            kind,
            value: value.clone(),
        });
    }
    if valid_hints(&hints) {
        Ok(hints)
    } else {
        Err(SpaceInviteError::Invalid)
    }
}

fn hint_kind_code(kind: SpaceInviteHintKind) -> u64 {
    match kind {
        SpaceInviteHintKind::Ble => 0,
        SpaceInviteHintKind::RelayUrl => 1,
        SpaceInviteHintKind::Lan => 2,
    }
}

fn number(value: &Value) -> Result<u64, SpaceInviteError> {
    match value {
        Value::Unsigned(value) => Ok(*value),
        _ => Err(SpaceInviteError::Invalid),
    }
}

fn optional_limit(value: &Value) -> Result<Option<u16>, SpaceInviteError> {
    match value {
        Value::Null => Ok(None),
        Value::Unsigned(value) if (1..=u64::from(u16::MAX)).contains(value) => Ok(Some(
            u16::try_from(*value).map_err(|_| SpaceInviteError::Invalid)?,
        )),
        _ => Err(SpaceInviteError::Invalid),
    }
}

fn fixed<const N: usize>(value: &Value) -> Result<[u8; N], SpaceInviteError> {
    let Value::Bytes(bytes) = value else {
        return Err(SpaceInviteError::Invalid);
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| SpaceInviteError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::space::{Invite, Member, MemberStatus};
    use lattice_events::EventDraft;
    use lattice_protocol::EventId;

    fn fixture(
        max_uses: Option<u16>,
    ) -> (
        DeviceIdentity,
        SpaceInviteV1,
        SpacePolicy,
        VerifiedSignatureOnlyEvent,
    ) {
        let identity = DeviceIdentity::generate().expect("generate inviter");
        let inviter = identity.fingerprint();
        let space_id = [1; 16];
        let genesis_event_id = [2; 32];
        let group_reference = [8; 32];
        let target = [4; 32];
        let key_package_hash = [5; 32];
        let invite_id = [6; 16];
        let invite_event = VerifiedSignatureOnlyEvent::create(
            &identity,
            EventDraft {
                space_id,
                channel_id: None,
                author_sequence: 1,
                lamport: 1,
                wall_time_hint: 0,
                parents: vec![EventId::from_bytes(genesis_event_id)],
                kind: EventKind::Membership,
                protected_body: vec![1],
                mls_group_reference: group_reference,
                mls_epoch: 1,
            },
        )
        .expect("create signed invite policy event");
        let invite_event_id = *invite_event.event_id().as_bytes();
        let invite = SpaceInviteV1::sign(
            &identity,
            space_id,
            genesis_event_id,
            invite_event_id,
            invite_id,
            target,
            key_package_hash,
            100,
            max_uses,
            [7; 16],
            vec![SpaceInviteHint {
                kind: SpaceInviteHintKind::RelayUrl,
                value: "wss://relay.example".to_owned(),
            }],
        )
        .expect("sign invite token");
        let policy = SpacePolicy {
            space_id,
            group_reference,
            root_event_id: genesis_event_id,
            root_author: inviter,
            revision: 1,
            heads: vec![invite_event_id],
            channels: Vec::new(),
            channel_order: Vec::new(),
            custom_roles: Vec::new(),
            members: vec![Member {
                fingerprint: inviter,
                status: MemberStatus::Active,
                assigned_roles: Vec::new(),
            }],
            invites: vec![Invite {
                id: invite_id,
                event_id: invite_event_id,
                target,
                key_package_hash,
                expires_at_revision: Some(4),
                max_uses,
                uses: 0,
            }],
        };
        (identity, invite, policy, invite_event)
    }

    #[test]
    fn signed_invite_roundtrips_and_binds_policy_identity_and_target() {
        let (_identity, invite, policy, invite_event) = fixture(Some(1));
        let bytes = invite.to_bytes().expect("encode token");
        let decoded = SpaceInviteV1::from_bytes(&bytes).expect("verify signed token");
        assert_eq!(decoded, invite);
        assert_eq!(decoded.inviter_fingerprint(), Ok(policy.root_author));
        assert_eq!(decoded.rendezvous_hints(), invite.rendezvous_hints());
        decoded
            .validate_for_policy(&policy, &invite_event, &policy.root_author, 99)
            .expect("validate active policy invite");

        let mut other_policy = policy.clone();
        other_policy.root_event_id[0] ^= 1;
        assert_eq!(
            decoded.validate_for_policy(&other_policy, &invite_event, &policy.root_author, 99),
            Err(SpaceInviteError::WrongPolicy)
        );
        assert_eq!(
            decoded.validate_for_policy(&policy, &invite_event, &[9; 32], 99),
            Err(SpaceInviteError::WrongPolicy)
        );

        let mut tampered = bytes;
        let final_byte = tampered.len() - 1;
        tampered[final_byte] ^= 1;
        assert_eq!(
            SpaceInviteV1::from_bytes(&tampered),
            Err(SpaceInviteError::Invalid)
        );
    }

    #[test]
    fn signed_invite_expiry_and_use_limits_are_enforced_against_current_policy() {
        let (_identity, invite, policy, invite_event) = fixture(Some(1));
        assert_eq!(
            invite.validate_for_policy(&policy, &invite_event, &policy.root_author, 100),
            Err(SpaceInviteError::Expired)
        );

        let mut expired_policy = policy.clone();
        expired_policy.revision = 4;
        assert_eq!(
            invite.validate_for_policy(&expired_policy, &invite_event, &policy.root_author, 99),
            Err(SpaceInviteError::Expired)
        );

        let mut consumed_policy = policy;
        consumed_policy.invites[0].uses = 1;
        assert_eq!(
            invite.validate_for_policy(
                &consumed_policy,
                &invite_event,
                &consumed_policy.root_author,
                99,
            ),
            Err(SpaceInviteError::Exhausted)
        );
    }
}
