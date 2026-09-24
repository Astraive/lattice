use std::process::Command;

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
    assert!(
        value["unavailable"]
            .as_array()
            .expect("unavailable capabilities should be an array")
            .iter()
            .any(|capability| capability == "authenticated_spaces")
    );
}
