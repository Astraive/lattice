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
            .any(|capability| capability == "local_peer_pin_revocation")
    );
    let unavailable = value["unavailable"]
        .as_array()
        .expect("unavailable capabilities should be an array");
    assert!(
        unavailable
            .iter()
            .any(|capability| capability == "complete_space_invite_leave_and_membership_lifecycle")
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
