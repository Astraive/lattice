//! Versioned, bounded offers for direct LAN and Wi-Fi path upgrades.
//!
//! Offers contain only supported payload limits. They do not discover peers,
//! create a route, or prove that either platform can currently reach the path.
//! Exchange them only after peer authentication; route planning still uses live
//! path availability and health.

use core::fmt;
use std::error::Error as StdError;

use crate::{Error as CborError, Value, decode_canonical, encode_canonical};

/// Wire version for the direct-path capability offer.
pub const PATH_UPGRADE_VERSION: u8 = 1;
/// Maximum path payload advertised by this profile.
pub const MAX_PATH_UPGRADE_FRAME_BYTES: u32 = 16 * 1024 * 1024;
const OFFER_FIELDS: usize = 4;

/// The local maximum encrypted frame size supported on each path.
///
/// `None` means the adapter is unsupported; a nonzero value advertises a
/// capability, not current reachability.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PathUpgradeCapabilities {
    lan: Option<u32>,
    wifi_aware: Option<u32>,
    wifi_direct: Option<u32>,
}

/// Common path capabilities and the negotiated per-path payload ceilings.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NegotiatedPathUpgrades {
    lan: Option<u32>,
    wifi_aware: Option<u32>,
    wifi_direct: Option<u32>,
}

/// Failure to encode or negotiate a path capability offer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathUpgradeError {
    /// The canonical CBOR document was malformed or exceeded the profile limit.
    Encoding(CborError),
    /// The offer is not exactly the version-1 four-field map.
    InvalidFormat,
    /// The peer advertised a version this implementation cannot negotiate.
    UnsupportedVersion,
    /// A supported path advertised a zero or excessive frame size.
    InvalidFrameLimit,
}

impl fmt::Display for PathUpgradeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding(error) => write!(formatter, "invalid canonical path offer: {error}"),
            Self::InvalidFormat => formatter.write_str("path offer has an invalid field set"),
            Self::UnsupportedVersion => formatter.write_str("path offer version is unsupported"),
            Self::InvalidFrameLimit => formatter.write_str("path offer frame limit is invalid"),
        }
    }
}

impl StdError for PathUpgradeError {}

impl PathUpgradeCapabilities {
    /// Constructs an offer after checking every advertised frame limit.
    ///
    /// # Errors
    ///
    /// Returns [`PathUpgradeError::InvalidFrameLimit`] if any supported path
    /// advertises zero or more than [`MAX_PATH_UPGRADE_FRAME_BYTES`].
    pub fn new(
        lan_max_frame_bytes: Option<u32>,
        wifi_aware_max_frame_bytes: Option<u32>,
        wifi_direct_max_frame_bytes: Option<u32>,
    ) -> Result<Self, PathUpgradeError> {
        validate_frame_limit(lan_max_frame_bytes)?;
        validate_frame_limit(wifi_aware_max_frame_bytes)?;
        validate_frame_limit(wifi_direct_max_frame_bytes)?;
        Ok(Self {
            lan: lan_max_frame_bytes,
            wifi_aware: wifi_aware_max_frame_bytes,
            wifi_direct: wifi_direct_max_frame_bytes,
        })
    }

    /// Returns the local LAN frame limit, if supported.
    #[must_use]
    pub const fn lan_max_frame_bytes(self) -> Option<u32> {
        self.lan
    }

    /// Returns the local Wi-Fi Aware frame limit, if supported.
    #[must_use]
    pub const fn wifi_aware_max_frame_bytes(self) -> Option<u32> {
        self.wifi_aware
    }

    /// Returns the local Wi-Fi Direct/P2P frame limit, if supported.
    #[must_use]
    pub const fn wifi_direct_max_frame_bytes(self) -> Option<u32> {
        self.wifi_direct
    }

    /// Encodes this offer as canonical versioned CBOR.
    ///
    /// # Errors
    ///
    /// Returns [`PathUpgradeError::Encoding`] if the canonical encoder rejects
    /// the generated bounded value.
    pub fn encode(self) -> Result<Vec<u8>, PathUpgradeError> {
        let value = Value::Map(vec![
            (0, Value::Unsigned(u64::from(PATH_UPGRADE_VERSION))),
            (1, frame_limit_value(self.lan)),
            (2, frame_limit_value(self.wifi_aware)),
            (3, frame_limit_value(self.wifi_direct)),
        ]);
        encode_canonical(&value).map_err(PathUpgradeError::Encoding)
    }

    /// Decodes exactly one canonical version-1 capability offer.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed/non-canonical CBOR, unknown fields or
    /// versions, or an invalid path limit.
    pub fn decode(bytes: &[u8]) -> Result<Self, PathUpgradeError> {
        let Value::Map(fields) = decode_canonical(bytes).map_err(PathUpgradeError::Encoding)?
        else {
            return Err(PathUpgradeError::InvalidFormat);
        };
        if fields.len() != OFFER_FIELDS
            || fields
                .iter()
                .enumerate()
                .any(|(expected, (key, _))| u64::try_from(expected).ok() != Some(*key))
        {
            return Err(PathUpgradeError::InvalidFormat);
        }
        let version = unsigned_field(&fields[0].1)?;
        if version != u64::from(PATH_UPGRADE_VERSION) {
            return Err(PathUpgradeError::UnsupportedVersion);
        }
        Self::new(
            parse_frame_limit(&fields[1].1)?,
            parse_frame_limit(&fields[2].1)?,
            parse_frame_limit(&fields[3].1)?,
        )
    }

    /// Intersects peer offers and takes the smaller safe frame limit per path.
    ///
    /// This result is a capability intersection only. Callers must still check
    /// live reachability, consent, traffic class, health, and route policy.
    #[must_use]
    pub const fn negotiate(self, peer: Self) -> NegotiatedPathUpgrades {
        NegotiatedPathUpgrades {
            lan: min_shared_limit(self.lan, peer.lan),
            wifi_aware: min_shared_limit(self.wifi_aware, peer.wifi_aware),
            wifi_direct: min_shared_limit(self.wifi_direct, peer.wifi_direct),
        }
    }
}

impl NegotiatedPathUpgrades {
    /// Returns the mutually supported LAN frame limit.
    #[must_use]
    pub const fn lan_max_frame_bytes(self) -> Option<u32> {
        self.lan
    }

    /// Returns the mutually supported Wi-Fi Aware frame limit.
    #[must_use]
    pub const fn wifi_aware_max_frame_bytes(self) -> Option<u32> {
        self.wifi_aware
    }

    /// Returns the mutually supported Wi-Fi Direct/P2P frame limit.
    #[must_use]
    pub const fn wifi_direct_max_frame_bytes(self) -> Option<u32> {
        self.wifi_direct
    }

    /// Returns whether both peers advertised at least one direct upgrade.
    #[must_use]
    pub const fn has_upgrade(self) -> bool {
        self.lan.is_some() || self.wifi_aware.is_some() || self.wifi_direct.is_some()
    }
}

const fn min_shared_limit(local: Option<u32>, peer: Option<u32>) -> Option<u32> {
    match (local, peer) {
        (Some(local), Some(peer)) => Some(if local < peer { local } else { peer }),
        _ => None,
    }
}

fn validate_frame_limit(limit: Option<u32>) -> Result<(), PathUpgradeError> {
    if limit.is_some_and(|bytes| bytes == 0 || bytes > MAX_PATH_UPGRADE_FRAME_BYTES) {
        return Err(PathUpgradeError::InvalidFrameLimit);
    }
    Ok(())
}

fn frame_limit_value(limit: Option<u32>) -> Value {
    Value::Unsigned(u64::from(limit.unwrap_or_default()))
}

fn unsigned_field(value: &Value) -> Result<u64, PathUpgradeError> {
    match value {
        Value::Unsigned(number) => Ok(*number),
        _ => Err(PathUpgradeError::InvalidFormat),
    }
}

fn parse_frame_limit(value: &Value) -> Result<Option<u32>, PathUpgradeError> {
    let bytes = unsigned_field(value)?;
    let bytes = u32::try_from(bytes).map_err(|_| PathUpgradeError::InvalidFrameLimit)?;
    if bytes == 0 {
        return Ok(None);
    }
    validate_frame_limit(Some(bytes))?;
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use super::{MAX_PATH_UPGRADE_FRAME_BYTES, PathUpgradeCapabilities, PathUpgradeError};
    use crate::{Value, encode_canonical};

    #[test]
    fn offer_roundtrips_and_negotiates_the_smallest_common_limits() {
        let local = PathUpgradeCapabilities::new(Some(65_536), Some(512_000), None)
            .expect("valid local offer");
        let peer = PathUpgradeCapabilities::new(Some(32_768), None, Some(131_072))
            .expect("valid peer offer");
        let encoded = local.encode().expect("encode local offer");
        assert_eq!(
            encoded,
            [
                0xa4, 0x00, 0x01, 0x01, 0x1a, 0x00, 0x01, 0x00, 0x00, 0x02, 0x1a, 0x00, 0x07, 0xd0,
                0x00, 0x03, 0x00,
            ]
        );

        assert_eq!(PathUpgradeCapabilities::decode(&encoded), Ok(local));
        let negotiated = local.negotiate(peer);
        assert_eq!(negotiated.lan_max_frame_bytes(), Some(32_768));
        assert_eq!(negotiated.wifi_aware_max_frame_bytes(), None);
        assert_eq!(negotiated.wifi_direct_max_frame_bytes(), None);
        assert!(local.negotiate(peer).has_upgrade());
    }

    #[test]
    fn unsupported_hardware_keeps_baseline_without_claiming_an_upgrade() {
        let baseline = PathUpgradeCapabilities::default();
        let capable = PathUpgradeCapabilities::new(Some(65_536), Some(262_144), Some(131_072))
            .expect("valid peer offer");

        assert!(!baseline.negotiate(capable).has_upgrade());
        assert!(!capable.negotiate(baseline).has_upgrade());
    }

    #[test]
    fn rejects_unknown_versions_fields_and_frame_limits() {
        let unknown_version = Value::Map(vec![
            (0, Value::Unsigned(2)),
            (1, Value::Unsigned(0)),
            (2, Value::Unsigned(0)),
            (3, Value::Unsigned(0)),
        ]);
        let unknown_field = Value::Map(vec![
            (0, Value::Unsigned(1)),
            (1, Value::Unsigned(0)),
            (2, Value::Unsigned(0)),
            (3, Value::Unsigned(0)),
            (4, Value::Unsigned(0)),
        ]);
        let oversized = Value::Map(vec![
            (0, Value::Unsigned(1)),
            (
                1,
                Value::Unsigned(u64::from(MAX_PATH_UPGRADE_FRAME_BYTES) + 1),
            ),
            (2, Value::Unsigned(0)),
            (3, Value::Unsigned(0)),
        ]);
        let encode = |value: &Value| encode_canonical(value).expect("canonical test value");

        assert_eq!(
            PathUpgradeCapabilities::decode(&encode(&unknown_version)),
            Err(PathUpgradeError::UnsupportedVersion)
        );
        assert_eq!(
            PathUpgradeCapabilities::decode(&encode(&unknown_field)),
            Err(PathUpgradeError::InvalidFormat)
        );
        assert_eq!(
            PathUpgradeCapabilities::decode(&encode(&oversized)),
            Err(PathUpgradeError::InvalidFrameLimit)
        );
        assert_eq!(
            PathUpgradeCapabilities::new(Some(0), None, None),
            Err(PathUpgradeError::InvalidFrameLimit)
        );
    }
}
