use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use serde::Serialize;
use uuid::Uuid;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LocalPathCapabilities {
    local_ip_address_observed: bool,
}

/// Report coarse local IP availability without enumerating peers or interfaces.
#[tauri::command]
pub(crate) fn scan_local_path_capabilities() -> Result<LocalPathCapabilities, String> {
    let interfaces = if_addrs::get_if_addrs().map_err(|error| error.to_string())?;
    Ok(LocalPathCapabilities {
        local_ip_address_observed: interfaces
            .iter()
            .any(|interface| is_local_ip_candidate(interface.ip())),
    })
}

fn is_local_ip_candidate(address: IpAddr) -> bool {
    !address.is_loopback() && !address.is_unspecified()
}

const LATTICE_SERVICE_TYPE: &str = "_lattice._tcp.local.";
const LAN_SCAN_WINDOW: Duration = Duration::from_secs(3);
const MAX_LAN_SERVICES: usize = 32;
const MAX_SERVICE_ADDRESSES: usize = 4;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LocalLanEndpoint {
    address: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LocalLanDiscovery {
    state: &'static str,
    network_contacted: bool,
    identity_authenticated: bool,
    reachability_verified: bool,
    endpoints: Vec<LocalLanEndpoint>,
}

/// Scans briefly for the generic Lattice DNS-SD service.
///
/// An observed SRV/A/AAAA record is an unauthenticated endpoint candidate, not
/// evidence of peer identity or reachability. The command returns only bounded
/// socket endpoints; it never exposes an mDNS instance name or TXT data.
#[tauri::command]
pub(crate) async fn discover_local_lan_endpoints() -> Result<LocalLanDiscovery, String> {
    tokio::task::spawn_blocking(discover_local_lan_endpoints_blocking)
        .await
        .map_err(|error| format!("LAN endpoint scan task failed: {error}"))?
}

fn discover_local_lan_endpoints_blocking() -> Result<LocalLanDiscovery, String> {
    let daemon =
        ServiceDaemon::new().map_err(|error| format!("start LAN endpoint scan: {error}"))?;
    let events = daemon
        .browse(LATTICE_SERVICE_TYPE)
        .map_err(|error| format!("browse Lattice LAN service: {error}"))?;
    let deadline = Instant::now() + LAN_SCAN_WINDOW;
    let mut services = BTreeMap::<String, BTreeSet<SocketAddr>>::new();

    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        if remaining.is_zero() {
            break;
        }
        match events.recv_timeout(remaining) {
            Ok(ServiceEvent::ServiceResolved(service))
                if service.is_valid()
                    && service.get_port() != 0
                    && service.get_fullname().len() <= 255 =>
            {
                let full_name = service.get_fullname();
                if !services.contains_key(full_name) && services.len() >= MAX_LAN_SERVICES {
                    continue;
                }
                let endpoints = bounded_service_endpoints(
                    service
                        .get_addresses()
                        .iter()
                        .map(mdns_sd::ScopedIp::to_ip_addr),
                    service.get_port(),
                );
                if !endpoints.is_empty() {
                    services.insert(full_name.to_owned(), endpoints);
                }
            }
            Ok(ServiceEvent::ServiceRemoved(service_type, full_name))
                if service_type == LATTICE_SERVICE_TYPE =>
            {
                services.remove(&full_name);
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }

    let _ = daemon.stop_browse(LATTICE_SERVICE_TYPE);
    let _ = daemon.shutdown();
    let endpoints = services
        .into_values()
        .flatten()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(MAX_LAN_SERVICES)
        .map(|address| LocalLanEndpoint {
            address: address.to_string(),
        })
        .collect::<Vec<_>>();

    Ok(LocalLanDiscovery {
        state: if endpoints.is_empty() {
            "no_endpoint_observed"
        } else {
            "endpoint_observed"
        },
        network_contacted: true,
        identity_authenticated: false,
        reachability_verified: false,
        endpoints,
    })
}

fn endpoint_from_ip(address: IpAddr, port: u16) -> Option<SocketAddr> {
    let usable = match address {
        IpAddr::V4(address) => {
            !address.is_loopback()
                && !address.is_unspecified()
                && !address.is_multicast()
                && address != std::net::Ipv4Addr::BROADCAST
        }
        IpAddr::V6(address) => {
            !address.is_loopback()
                && !address.is_unspecified()
                && !address.is_multicast()
                && !address.is_unicast_link_local()
        }
    };
    (usable && port != 0).then_some(SocketAddr::new(address, port))
}

fn bounded_service_endpoints(
    addresses: impl IntoIterator<Item = IpAddr>,
    port: u16,
) -> BTreeSet<SocketAddr> {
    addresses
        .into_iter()
        .take(MAX_SERVICE_ADDRESSES)
        .filter_map(|address| endpoint_from_ip(address, port))
        .collect()
}

pub(crate) struct LanServiceAdvertisement {
    daemon: ServiceDaemon,
    full_name: String,
}

impl Drop for LanServiceAdvertisement {
    fn drop(&mut self) {
        let _ = self.daemon.unregister(&self.full_name);
        let _ = self.daemon.shutdown();
    }
}

/// Advertises an explicitly enabled non-loopback TCP listener without identity
/// or Space metadata. Loopback and link-local-only endpoints are not announced.
pub(crate) fn advertise_peer_listener(
    listen_address: SocketAddr,
) -> Result<Option<LanServiceAdvertisement>, String> {
    let address = listen_address.ip();
    if address.is_loopback()
        || matches!(address, IpAddr::V6(address) if address.is_unicast_link_local())
    {
        return Ok(None);
    }

    let instance_name = format!("Lattice-{}", Uuid::new_v4().simple());
    let hostname = format!("lattice-{}.local.", Uuid::new_v4().simple());
    let address_text = if address.is_unspecified() {
        String::new()
    } else {
        address.to_string()
    };
    let mut service = ServiceInfo::new(
        LATTICE_SERVICE_TYPE,
        &instance_name,
        &hostname,
        address_text.as_str(),
        listen_address.port(),
        &[] as &[(&str, &str)],
    )
    .map_err(|error| format!("create generic Lattice LAN service: {error}"))?;
    if address.is_unspecified() {
        service = service.enable_addr_auto();
    }
    let full_name = service.get_fullname().to_owned();
    let daemon =
        ServiceDaemon::new().map_err(|error| format!("start LAN service announcement: {error}"))?;
    daemon
        .register(service)
        .map_err(|error| format!("announce generic Lattice LAN service: {error}"))?;
    Ok(Some(LanServiceAdvertisement { daemon, full_name }))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::{bounded_service_endpoints, endpoint_from_ip, is_local_ip_candidate};

    #[test]
    fn local_ip_candidate_excludes_loopback_and_unspecified_addresses() {
        assert!(!is_local_ip_candidate(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!is_local_ip_candidate(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        assert!(is_local_ip_candidate(IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 10
        ))));
        assert!(is_local_ip_candidate(IpAddr::V6(
            "fe80::1".parse().expect("valid link-local address")
        )));
    }

    #[test]
    fn discovered_endpoints_reject_non_unicast_and_zero_port_values() {
        assert_eq!(
            endpoint_from_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 7331),
            Some(SocketAddr::from(([192, 168, 1, 10], 7331)))
        );
        assert!(endpoint_from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 7331).is_none());
        assert!(endpoint_from_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 7331).is_none());
        assert!(endpoint_from_ip(IpAddr::V4(Ipv4Addr::BROADCAST), 7331).is_none());
        assert!(endpoint_from_ip(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)), 7331).is_none());
        assert!(endpoint_from_ip(IpAddr::V6(Ipv6Addr::LOCALHOST), 7331).is_none());
        assert!(endpoint_from_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 7331).is_none());
        assert!(
            endpoint_from_ip("fe80::1".parse().expect("valid link-local address"), 7331).is_none()
        );
        assert!(endpoint_from_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 0).is_none());
    }

    #[test]
    fn discovery_caps_raw_service_addresses_before_filtering() {
        let invalid = std::iter::repeat_n(IpAddr::V4(Ipv4Addr::LOCALHOST), 4);
        let valid_after_cap = std::iter::once(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
        assert!(
            bounded_service_endpoints(invalid.chain(valid_after_cap), 7331).is_empty(),
            "addresses past the raw per-service cap must not be inspected"
        );
    }
}
