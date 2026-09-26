use std::net::IpAddr;

use serde::Serialize;

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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::is_local_ip_candidate;

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
}
