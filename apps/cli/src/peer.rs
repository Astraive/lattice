use clap::Subcommand;
use std::{error::Error, net::IpAddr};

#[derive(Clone, Copy, Debug, Subcommand)]
pub(super) enum PeerCommand {
    /// Report coarse local path readiness without contacting peers or relays.
    Scan,
}

pub(super) fn execute(command: PeerCommand, json: bool) -> Result<(), Box<dyn Error>> {
    match command {
        PeerCommand::Scan => execute_scan(json),
    }
}

fn execute_scan(json: bool) -> Result<(), Box<dyn Error>> {
    let interfaces = if_addrs::get_if_addrs()?;
    let local_ip_address_observed = interfaces
        .iter()
        .any(|interface| is_local_ip_candidate(interface.ip()));
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "command": "peer_scan",
                "scan_scope": "local_interface_capabilities",
                "network_contacted": false,
                "peer_discovery_started": false,
                "private_key_exposed": false,
                "peer_identities_included": false,
                "space_identifiers_included": false,
                "interface_details_included": false,
                "paths": {
                    "lan_ip": {
                        "status": if local_ip_address_observed { "address_observed" } else { "no_address_observed" },
                        "reachability": "not_checked",
                    },
                    "ble": { "status": "not_probed", "reason": "no_cli_ble_adapter" },
                    "wifi_aware": { "status": "not_probed", "reason": "no_cli_wifi_aware_adapter" },
                    "wifi_direct": { "status": "not_probed", "reason": "no_cli_wifi_direct_adapter" },
                    "internet_relay": { "status": "not_probed", "reason": "peer_scan_is_local_only" },
                },
            })
        );
    } else {
        println!("Path capability scan: local interface observations only.");
        println!("No peer discovery or network contact was started.");
        println!(
            "LAN IP address: {} (reachability not checked)",
            if local_ip_address_observed {
                "observed"
            } else {
                "not observed"
            }
        );
        println!("BLE, Wi-Fi Aware, and Wi-Fi Direct: not probed by this CLI.");
        println!("Internet relay: not probed.");
        println!("Interface names, addresses, peer identities, Space IDs, and keys are omitted.");
    }
    Ok(())
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
        ),));
    }
}
