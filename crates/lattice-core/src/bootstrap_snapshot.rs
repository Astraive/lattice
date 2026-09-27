use std::collections::BTreeSet;

use lattice_protocol::{Value, decode_canonical, encode_canonical};

use crate::{CoreError, space};

const BUILTIN_ROLE_IDS: [[u8; 16]; 4] = [
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4],
];
const SPACE_PERMISSION_MASK: u64 = 0x0000_0000_0001_ffff;
const CONTENT_CHANNEL_MASK: u64 = 0x0000_0000_0000_0fc0;
const VOICE_CHANNEL_MASK: u64 = 0x0000_0000_0000_7000;

/// Encodes the exact version-one policy snapshot map used by Welcome bootstrap.
///
/// `space_id` and `group_reference` are package-binding context and are not
/// fields in the version-one snapshot map; the decoder receives them from the
/// surrounding package context.
pub(crate) fn encode_policy_snapshot(policy: &space::SpacePolicy) -> Result<Vec<u8>, CoreError> {
    validate_policy(policy, false)?;

    let mut heads = policy.heads.iter().collect::<Vec<_>>();
    heads.sort_unstable();
    let mut channels = policy.channels.iter().collect::<Vec<_>>();
    channels.sort_unstable_by_key(|channel| channel.id);
    let mut custom_roles = policy.custom_roles.iter().collect::<Vec<_>>();
    custom_roles.sort_unstable_by_key(|role| role.id);
    let mut members = policy.members.iter().collect::<Vec<_>>();
    members.sort_unstable_by_key(|member| member.fingerprint);
    let mut invites = policy.invites.iter().collect::<Vec<_>>();
    invites.sort_unstable_by_key(|invite| invite.id);

    let value = Value::Map(vec![
        (0, bytes(&policy.root_event_id)),
        (1, bytes(&policy.root_author)),
        (2, Value::Unsigned(policy.revision)),
        (
            3,
            Value::Array(heads.iter().map(|head| bytes(*head)).collect()),
        ),
        (
            4,
            Value::Array(channels.into_iter().map(encode_channel).collect()),
        ),
        (
            5,
            Value::Array(
                policy
                    .channel_order
                    .iter()
                    .map(|channel_id| bytes(channel_id))
                    .collect(),
            ),
        ),
        (
            6,
            Value::Array(custom_roles.into_iter().map(encode_custom_role).collect()),
        ),
        (
            7,
            Value::Array(members.into_iter().map(encode_member).collect()),
        ),
        (
            8,
            Value::Array(invites.into_iter().map(encode_invite).collect()),
        ),
    ]);
    let encoded = encode_canonical(&value).map_err(|_| invalid_error())?;
    if encoded.len() > space::MAX_SPACE_PAYLOAD_BYTES {
        return Err(invalid_error());
    }
    Ok(encoded)
}

/// Decodes and validates one canonical version-one policy snapshot using its
/// package-bound Space ID and MLS group reference.
pub(crate) fn decode_policy_snapshot(
    bytes: &[u8],
    space_id: space::SpaceId,
    group_reference: space::GroupReference,
) -> Result<space::SpacePolicy, CoreError> {
    if bytes.len() > space::MAX_SPACE_PAYLOAD_BYTES {
        return Err(invalid_error());
    }
    let value = decode_canonical(bytes).map_err(|_| invalid_error())?;
    let fields = exact_map(&value, &[0, 1, 2, 3, 4, 5, 6, 7, 8])?;

    let root_event_id = fixed_bytes::<32>(&fields[0].1)?;
    let root_author = fixed_bytes::<32>(&fields[1].1)?;
    let revision = unsigned(&fields[2].1)?;
    let heads = array(&fields[3].1)?;
    check_count(heads.len(), 1, space::MAX_PARENTS)?;
    let heads = heads
        .iter()
        .map(fixed_bytes::<32>)
        .collect::<Result<Vec<_>, _>>()?;

    let channel_values = array(&fields[4].1)?;
    check_count(channel_values.len(), 1, space::MAX_CHANNELS)?;
    let channels = channel_values
        .iter()
        .map(parse_channel)
        .collect::<Result<Vec<_>, _>>()?;

    let order_values = array(&fields[5].1)?;
    check_count(order_values.len(), 1, space::MAX_CHANNELS)?;
    let channel_order = order_values
        .iter()
        .map(fixed_bytes::<16>)
        .collect::<Result<Vec<_>, _>>()?;

    let role_values = array(&fields[6].1)?;
    check_count(role_values.len(), 0, space::MAX_CUSTOM_ROLES)?;
    let custom_roles = role_values
        .iter()
        .map(parse_custom_role)
        .collect::<Result<Vec<_>, _>>()?;

    let member_values = array(&fields[7].1)?;
    check_count(member_values.len(), 1, space::MAX_MEMBERS)?;
    let members = member_values
        .iter()
        .map(parse_member)
        .collect::<Result<Vec<_>, _>>()?;

    let invite_values = array(&fields[8].1)?;
    check_count(invite_values.len(), 0, space::MAX_INVITES)?;
    let invites = invite_values
        .iter()
        .map(parse_invite)
        .collect::<Result<Vec<_>, _>>()?;

    let policy = space::SpacePolicy {
        space_id,
        group_reference,
        root_event_id,
        root_author,
        revision,
        heads,
        channels,
        channel_order,
        custom_roles,
        members,
        invites,
    };
    validate_policy(&policy, true)?;
    Ok(policy)
}

fn encode_channel(channel: &space::Channel) -> Value {
    let mut overrides = channel.role_overrides.iter().collect::<Vec<_>>();
    overrides.sort_unstable_by_key(|item| item.role_id);
    Value::Map(vec![
        (0, bytes(&channel.id)),
        (1, Value::Unsigned(channel_type_code(channel.channel_type))),
        (2, Value::Text(channel.name.clone())),
        (3, Value::Bool(channel.archived)),
        (4, Value::Unsigned(channel.default_allow)),
        (5, Value::Unsigned(channel.default_deny)),
        (
            6,
            Value::Array(
                overrides
                    .into_iter()
                    .map(|item| {
                        Value::Map(vec![
                            (0, bytes(&item.role_id)),
                            (1, Value::Unsigned(item.allow)),
                            (2, Value::Unsigned(item.deny)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

fn parse_channel(value: &Value) -> Result<space::Channel, CoreError> {
    let fields = exact_map(value, &[0, 1, 2, 3, 4, 5, 6])?;
    let id = fixed_bytes::<16>(&fields[0].1)?;
    let channel_type = match unsigned(&fields[1].1)? {
        0 => space::ChannelType::Text,
        1 => space::ChannelType::Announcement,
        2 => space::ChannelType::Voice,
        _ => return Err(invalid_error()),
    };
    let name = text_name(&fields[2].1)?;
    let archived = boolean(&fields[3].1)?;
    let default_allow = unsigned(&fields[4].1)?;
    let default_deny = unsigned(&fields[5].1)?;
    let override_values = array(&fields[6].1)?;
    check_count(override_values.len(), 0, space::MAX_CHANNEL_OVERRIDES)?;
    let mut role_overrides = Vec::with_capacity(override_values.len());
    for value in override_values {
        let fields = exact_map(value, &[0, 1, 2])?;
        role_overrides.push(space::RoleOverride {
            role_id: fixed_bytes::<16>(&fields[0].1)?,
            allow: unsigned(&fields[1].1)?,
            deny: unsigned(&fields[2].1)?,
        });
    }
    Ok(space::Channel {
        id,
        channel_type,
        name,
        archived,
        default_allow,
        default_deny,
        role_overrides,
    })
}

fn encode_custom_role(role: &space::CustomRole) -> Value {
    Value::Map(vec![
        (0, bytes(&role.id)),
        (1, Value::Text(role.name.clone())),
        (2, Value::Unsigned(role.allow)),
        (3, Value::Unsigned(role.deny)),
    ])
}

fn parse_custom_role(value: &Value) -> Result<space::CustomRole, CoreError> {
    let fields = exact_map(value, &[0, 1, 2, 3])?;
    Ok(space::CustomRole {
        id: fixed_bytes::<16>(&fields[0].1)?,
        name: text_name(&fields[1].1)?,
        allow: unsigned(&fields[2].1)?,
        deny: unsigned(&fields[3].1)?,
    })
}

fn encode_member(member: &space::Member) -> Value {
    let mut assigned_roles = member.assigned_roles.iter().collect::<Vec<_>>();
    assigned_roles.sort_unstable();
    Value::Map(vec![
        (0, bytes(&member.fingerprint)),
        (1, Value::Unsigned(member_status_code(member.status))),
        (
            2,
            Value::Array(
                assigned_roles
                    .iter()
                    .map(|role_id| bytes(*role_id))
                    .collect(),
            ),
        ),
    ])
}

fn parse_member(value: &Value) -> Result<space::Member, CoreError> {
    let fields = exact_map(value, &[0, 1, 2])?;
    let fingerprint = fixed_bytes::<32>(&fields[0].1)?;
    let status = match unsigned(&fields[1].1)? {
        0 => space::MemberStatus::Active,
        1 => space::MemberStatus::Invited,
        2 => space::MemberStatus::Removed,
        3 => space::MemberStatus::Banned,
        _ => return Err(invalid_error()),
    };
    let role_values = array(&fields[2].1)?;
    check_count(role_values.len(), 0, space::MAX_ASSIGNED_ROLES_PER_MEMBER)?;
    let assigned_roles = role_values
        .iter()
        .map(fixed_bytes::<16>)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(space::Member {
        fingerprint,
        status,
        assigned_roles,
    })
}

fn encode_invite(invite: &space::Invite) -> Value {
    Value::Map(vec![
        (0, bytes(&invite.id)),
        (1, bytes(&invite.event_id)),
        (2, bytes(&invite.target)),
        (3, bytes(&invite.key_package_hash)),
        (
            4,
            invite
                .expires_at_revision
                .map_or(Value::Null, Value::Unsigned),
        ),
        (
            5,
            invite
                .max_uses
                .map_or(Value::Null, |uses| Value::Unsigned(u64::from(uses))),
        ),
        (6, Value::Unsigned(u64::from(invite.uses))),
    ])
}

fn parse_invite(value: &Value) -> Result<space::Invite, CoreError> {
    let fields = exact_map(value, &[0, 1, 2, 3, 4, 5, 6])?;
    let expires_at_revision = optional_unsigned(&fields[4].1)?;
    let max_uses = optional_unsigned(&fields[5].1)?
        .map(u16::try_from)
        .transpose()
        .map_err(|_| invalid_error())?;
    let uses = u16::try_from(unsigned(&fields[6].1)?).map_err(|_| invalid_error())?;
    Ok(space::Invite {
        id: fixed_bytes::<16>(&fields[0].1)?,
        event_id: fixed_bytes::<32>(&fields[1].1)?,
        target: fixed_bytes::<32>(&fields[2].1)?,
        key_package_hash: fixed_bytes::<32>(&fields[3].1)?,
        expires_at_revision,
        max_uses,
        uses,
    })
}

#[allow(clippy::too_many_lines)] // Keep the exact snapshot invariants together.
fn validate_policy(policy: &space::SpacePolicy, require_sorted: bool) -> Result<(), CoreError> {
    check_count(policy.heads.len(), 1, space::MAX_PARENTS)?;
    check_count(policy.channels.len(), 1, space::MAX_CHANNELS)?;
    check_count(policy.custom_roles.len(), 0, space::MAX_CUSTOM_ROLES)?;
    check_count(policy.members.len(), 1, space::MAX_MEMBERS)?;
    check_count(policy.invites.len(), 0, space::MAX_INVITES)?;

    validate_ordered_ids(&policy.heads, require_sorted)?;
    let mut channel_ids = BTreeSet::new();
    for pair in policy.channels.windows(2) {
        if require_sorted && pair[0].id >= pair[1].id {
            return Err(invalid_error());
        }
    }
    for channel in &policy.channels {
        if !channel_ids.insert(channel.id) || !valid_name(&channel.name) {
            return Err(invalid_error());
        }
        let channel_mask = match channel.channel_type {
            space::ChannelType::Text | space::ChannelType::Announcement => CONTENT_CHANNEL_MASK,
            space::ChannelType::Voice => VOICE_CHANNEL_MASK,
        };
        validate_masks(channel.default_allow, channel.default_deny, channel_mask)?;
        check_count(
            channel.role_overrides.len(),
            0,
            space::MAX_CHANNEL_OVERRIDES,
        )?;
        let mut prior_role = None;
        let mut override_ids = BTreeSet::new();
        for item in &channel.role_overrides {
            if require_sorted && prior_role.is_some_and(|prior| prior >= item.role_id) {
                return Err(invalid_error());
            }
            prior_role = Some(item.role_id);
            if !override_ids.insert(item.role_id) || !is_known_role(policy, &item.role_id) {
                return Err(invalid_error());
            }
            validate_masks(item.allow, item.deny, channel_mask)?;
        }
    }

    if policy.channel_order.len() != policy.channels.len() {
        return Err(invalid_error());
    }
    let mut ordered_channel_ids = BTreeSet::new();
    if policy
        .channel_order
        .iter()
        .any(|id| !channel_ids.contains(id) || !ordered_channel_ids.insert(*id))
    {
        return Err(invalid_error());
    }

    let mut custom_role_ids = BTreeSet::new();
    for pair in policy.custom_roles.windows(2) {
        if require_sorted && pair[0].id >= pair[1].id {
            return Err(invalid_error());
        }
    }
    for role in &policy.custom_roles {
        if is_builtin_role(&role.id) || !custom_role_ids.insert(role.id) || !valid_name(&role.name)
        {
            return Err(invalid_error());
        }
        validate_masks(role.allow, role.deny, SPACE_PERMISSION_MASK)?;
    }

    let mut member_ids = BTreeSet::new();
    let mut root_is_active = false;
    for pair in policy.members.windows(2) {
        if require_sorted && pair[0].fingerprint >= pair[1].fingerprint {
            return Err(invalid_error());
        }
    }
    for member in &policy.members {
        if !member_ids.insert(member.fingerprint) {
            return Err(invalid_error());
        }
        let mut assigned = BTreeSet::new();
        validate_ordered_ids(&member.assigned_roles, require_sorted)?;
        check_count(
            member.assigned_roles.len(),
            0,
            space::MAX_ASSIGNED_ROLES_PER_MEMBER,
        )?;
        for role_id in &member.assigned_roles {
            if (*role_id == BUILTIN_ROLE_IDS[0] && member.fingerprint != policy.root_author)
                || *role_id == BUILTIN_ROLE_IDS[3]
                || !is_known_role(policy, role_id)
                || !assigned.insert(*role_id)
            {
                return Err(invalid_error());
            }
        }
        if member.fingerprint == policy.root_author {
            root_is_active = member.status == space::MemberStatus::Active
                && (member.assigned_roles.is_empty()
                    || member.assigned_roles == [BUILTIN_ROLE_IDS[0]]);
        }
    }
    if !root_is_active {
        return Err(invalid_error());
    }

    let mut invite_ids = BTreeSet::new();
    let mut invite_events = BTreeSet::new();
    for pair in policy.invites.windows(2) {
        if require_sorted && pair[0].id >= pair[1].id {
            return Err(invalid_error());
        }
    }
    for invite in &policy.invites {
        if !invite_ids.insert(invite.id)
            || !invite_events.insert(invite.event_id)
            || invite.max_uses == Some(0)
            || invite.max_uses.is_some_and(|maximum| invite.uses > maximum)
        {
            return Err(invalid_error());
        }
    }
    Ok(())
}

fn validate_ordered_ids<const N: usize>(
    ids: &[[u8; N]],
    require_sorted: bool,
) -> Result<(), CoreError> {
    if require_sorted && ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid_error());
    }
    if ids.iter().copied().collect::<BTreeSet<_>>().len() != ids.len() {
        return Err(invalid_error());
    }
    Ok(())
}

fn is_known_role(policy: &space::SpacePolicy, role_id: &[u8; 16]) -> bool {
    is_builtin_role(role_id) || policy.custom_roles.iter().any(|role| role.id == *role_id)
}

fn is_builtin_role(role_id: &[u8; 16]) -> bool {
    BUILTIN_ROLE_IDS.contains(role_id)
}

fn validate_masks(allow: u64, deny: u64, mask: u64) -> Result<(), CoreError> {
    if (allow | deny) & !mask != 0 || allow & deny != 0 {
        return Err(invalid_error());
    }
    Ok(())
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 128 && !name.contains('\0')
}

fn channel_type_code(channel_type: space::ChannelType) -> u64 {
    match channel_type {
        space::ChannelType::Text => 0,
        space::ChannelType::Announcement => 1,
        space::ChannelType::Voice => 2,
    }
}

fn member_status_code(status: space::MemberStatus) -> u64 {
    match status {
        space::MemberStatus::Active => 0,
        space::MemberStatus::Invited => 1,
        space::MemberStatus::Removed => 2,
        space::MemberStatus::Banned => 3,
    }
}

fn exact_map<'a>(value: &'a Value, keys: &[u64]) -> Result<&'a [(u64, Value)], CoreError> {
    let Value::Map(entries) = value else {
        return Err(invalid_error());
    };
    if entries.len() != keys.len()
        || entries
            .iter()
            .zip(keys)
            .any(|((actual, _), expected)| actual != expected)
    {
        return Err(invalid_error());
    }
    Ok(entries)
}

fn array(value: &Value) -> Result<&[Value], CoreError> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err(invalid_error()),
    }
}

fn unsigned(value: &Value) -> Result<u64, CoreError> {
    match value {
        Value::Unsigned(value) => Ok(*value),
        _ => Err(invalid_error()),
    }
}

fn optional_unsigned(value: &Value) -> Result<Option<u64>, CoreError> {
    match value {
        Value::Null => Ok(None),
        Value::Unsigned(value) => Ok(Some(*value)),
        _ => Err(invalid_error()),
    }
}

fn boolean(value: &Value) -> Result<bool, CoreError> {
    match value {
        Value::Bool(value) => Ok(*value),
        _ => Err(invalid_error()),
    }
}

fn text_name(value: &Value) -> Result<String, CoreError> {
    match value {
        Value::Text(name) if valid_name(name) => Ok(name.clone()),
        _ => Err(invalid_error()),
    }
}

fn fixed_bytes<const N: usize>(value: &Value) -> Result<[u8; N], CoreError> {
    match value {
        Value::Bytes(bytes) => bytes.as_slice().try_into().map_err(|_| invalid_error()),
        _ => Err(invalid_error()),
    }
}

fn check_count(actual: usize, minimum: usize, maximum: usize) -> Result<(), CoreError> {
    if actual < minimum || actual > maximum {
        return Err(invalid_error());
    }
    Ok(())
}

fn bytes(bytes: &[u8]) -> Value {
    Value::Bytes(bytes.to_vec())
}

fn invalid_error() -> CoreError {
    CoreError::SpaceWelcomeBootstrapInvalid
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn entity(byte: u8) -> [u8; 16] {
        [byte; 16]
    }

    fn valid_policy() -> space::SpacePolicy {
        let custom_role = space::CustomRole {
            id: entity(5),
            name: "writer".to_owned(),
            allow: 1 << 6,
            deny: 0,
        };
        space::SpacePolicy {
            space_id: entity(14),
            group_reference: event(15),
            root_event_id: event(9),
            root_author: event(2),
            revision: 3,
            heads: vec![event(7), event(8)],
            channels: vec![space::Channel {
                id: entity(10),
                channel_type: space::ChannelType::Text,
                name: "general".to_owned(),
                archived: false,
                default_allow: 0,
                default_deny: 0,
                role_overrides: vec![space::RoleOverride {
                    role_id: entity(5),
                    allow: 1 << 6,
                    deny: 0,
                }],
            }],
            channel_order: vec![entity(10)],
            custom_roles: vec![custom_role],
            members: vec![
                space::Member {
                    fingerprint: event(1),
                    status: space::MemberStatus::Invited,
                    assigned_roles: vec![],
                },
                space::Member {
                    fingerprint: event(2),
                    status: space::MemberStatus::Active,
                    assigned_roles: vec![],
                },
                space::Member {
                    fingerprint: event(3),
                    status: space::MemberStatus::Active,
                    assigned_roles: vec![entity(5)],
                },
            ],
            invites: vec![space::Invite {
                id: entity(11),
                event_id: event(12),
                target: event(1),
                key_package_hash: event(13),
                expires_at_revision: Some(20),
                max_uses: Some(2),
                uses: 1,
            }],
        }
    }

    #[test]
    fn policy_snapshot_roundtrips_canonical_state() {
        let policy = valid_policy();
        let encoded = encode_policy_snapshot(&policy).expect("valid policy encodes");
        let decoded = decode_policy_snapshot(&encoded, policy.space_id, policy.group_reference)
            .expect("encoded policy decodes");
        assert_eq!(decoded, policy);
        assert_eq!(encode_policy_snapshot(&decoded).unwrap(), encoded);
    }

    #[test]
    fn encoder_sorts_unordered_policy_collections_deterministically() {
        let mut policy = valid_policy();
        policy.heads.reverse();
        policy.members.reverse();
        let encoded = encode_policy_snapshot(&policy).expect("valid policy encodes");
        let decoded = decode_policy_snapshot(&encoded, policy.space_id, policy.group_reference)
            .expect("canonical snapshot decodes");
        assert!(decoded.heads.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(
            decoded
                .members
                .windows(2)
                .all(|pair| pair[0].fingerprint < pair[1].fingerprint)
        );
        assert_eq!(encode_policy_snapshot(&decoded).unwrap(), encoded);
    }

    #[test]
    fn decoder_rejects_unsorted_and_duplicate_identifiers() {
        let encoded = encode_policy_snapshot(&valid_policy()).expect("valid policy encodes");
        let mut value = decode_canonical(&encoded).expect("canonical encoding");
        let Value::Map(entries) = &mut value else {
            panic!("snapshot map");
        };
        let Value::Array(heads) = &mut entries[3].1 else {
            panic!("head array");
        };
        heads.swap(0, 1);
        let unsorted = encode_canonical(&value).expect("still canonical CBOR");
        assert!(decode_policy_snapshot(&unsorted, [0; 16], [0; 32]).is_err());

        let mut value = decode_canonical(&encoded).expect("canonical encoding");
        let Value::Map(entries) = &mut value else {
            panic!("snapshot map");
        };
        let Value::Array(members) = &mut entries[7].1 else {
            panic!("member array");
        };
        let first_member = members[0].clone();
        members.push(first_member);
        let duplicate = encode_canonical(&value).expect("still canonical CBOR");
        assert!(decode_policy_snapshot(&duplicate, [0; 16], [0; 32]).is_err());
    }

    #[test]
    fn decoder_rejects_wrong_snapshot_key_set() {
        let encoded = encode_policy_snapshot(&valid_policy()).expect("valid policy encodes");
        let mut value = decode_canonical(&encoded).expect("canonical encoding");
        let Value::Map(entries) = &mut value else {
            panic!("snapshot map");
        };
        entries.pop();
        let malformed = encode_canonical(&value).expect("canonical malformed map");
        assert!(decode_policy_snapshot(&malformed, [0; 16], [0; 32]).is_err());
    }
}
