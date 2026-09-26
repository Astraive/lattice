use std::{
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;

#[test]
fn about_json_reports_versioned_capability_boundaries() {
    let output = Command::new(env!("CARGO_BIN_EXE_lattice"))
        .args(["--json", "about"])
        .output()
        .expect("lattice about should start");

    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).expect("stdout should be JSON");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "about");
    assert!(
        value["available"]
            .as_array()
            .expect("available capabilities should be an array")
            .iter()
            .any(|capability| capability == "protected_device_identity")
    );
    let available = value["available"]
        .as_array()
        .expect("available capabilities should be an array");
    assert!(
        available
            .iter()
            .any(|capability| capability == "local_pinned_welcome_bootstrap_import")
    );
    assert!(
        available
            .iter()
            .any(|capability| capability == "local_space_leave_request")
    );
    assert!(
        available
            .iter()
            .any(|capability| capability == "local_space_key_package_publication")
    );
    assert!(
        available
            .iter()
            .any(|capability| capability == "local_space_invitation_creation")
    );
    let unavailable = value["unavailable"]
        .as_array()
        .expect("unavailable capabilities should be an array");
    assert!(
        unavailable
            .iter()
            .any(|capability| capability == "peer_membership_commit")
    );
    assert!(
        unavailable
            .iter()
            .any(|capability| capability == "remote_identity_revocation")
    );
    assert!(
        unavailable
            .iter()
            .any(|capability| capability == "network_message_forwarding_or_delivery")
    );
}

#[test]
fn peer_scan_json_omits_identifying_details_and_does_not_create_a_profile() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should follow the Unix epoch")
        .as_nanos();
    let data_dir = std::env::temp_dir().join(format!(
        "lattice-cli-peer-scan-{}-{unique}",
        std::process::id()
    ));
    let output = Command::new(env!("CARGO_BIN_EXE_lattice"))
        .args(["--json", "--data-dir"])
        .arg(&data_dir)
        .args(["peer", "scan"])
        .output()
        .expect("lattice peer scan should start");

    assert!(output.status.success());
    assert!(!data_dir.exists(), "peer scan must not create a profile");
    let value: Value = serde_json::from_slice(&output.stdout).expect("stdout should be JSON");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "peer_scan");
    assert_eq!(value["network_contacted"], false);
    assert_eq!(value["peer_discovery_started"], false);
    assert_eq!(value["private_key_exposed"], false);
    assert_eq!(value["peer_identities_included"], false);
    assert_eq!(value["space_identifiers_included"], false);
    assert_eq!(value["interface_details_included"], false);
    assert_eq!(value["paths"]["lan_ip"]["reachability"], "not_checked");
    assert_eq!(value["paths"]["ble"]["status"], "not_probed");
    assert!(value.get("fingerprint").is_none());
    assert!(value.get("space_id").is_none());
    assert!(value.get("group_reference").is_none());
}

#[test]
fn peer_scan_human_default_reports_only_coarse_local_state() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should follow the Unix epoch")
        .as_nanos();
    let data_dir = std::env::temp_dir().join(format!(
        "lattice-cli-peer-scan-human-{}-{unique}",
        std::process::id()
    ));
    let output = Command::new(env!("CARGO_BIN_EXE_lattice"))
        .args(["--data-dir"])
        .arg(&data_dir)
        .args(["peer", "scan"])
        .output()
        .expect("lattice peer scan should start");

    assert!(output.status.success());
    assert!(!data_dir.exists(), "peer scan must not create a profile");
    let stdout = String::from_utf8(output.stdout).expect("human output should be UTF-8");
    assert!(stdout.contains("No peer discovery or network contact was started."));
    assert!(
        stdout.contains(
            "Interface names, addresses, peer identities, Space IDs, and keys are omitted."
        )
    );
    assert!(!stdout.contains("127.0.0.1"));
    assert!(!stdout.contains("192.168."));
}

#[test]
fn doctor_json_reports_corrupt_database_without_migrating_or_reading_keys() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should follow the Unix epoch")
        .as_nanos();
    let data_dir = std::env::temp_dir().join(format!(
        "lattice-cli-doctor-corrupt-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir(&data_dir).expect("create isolated profile directory");
    std::fs::write(data_dir.join("lattice.sqlite"), b"not a SQLite database")
        .expect("write corrupt database fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_lattice"))
        .args(["--json", "--data-dir"])
        .arg(&data_dir)
        .arg("doctor")
        .output()
        .expect("lattice doctor should start");

    let cleanup = std::fs::remove_dir_all(&data_dir);
    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).expect("stdout should be JSON");
    assert_eq!(value["command"], "doctor");
    assert_eq!(value["overall"], "attention_required");
    assert_eq!(value["database"]["status"], "corrupt_or_unsupported");
    assert_eq!(value["database"]["integrity_check"], false);
    assert_eq!(value["database"]["storage_migrations_may_run"], false);
    assert_eq!(value["identity_key"]["status"], "not_checked");
    assert!(cleanup.is_ok(), "remove isolated profile directory");
}
