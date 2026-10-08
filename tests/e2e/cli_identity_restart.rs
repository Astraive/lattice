use std::{
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;

#[test]
fn identity_and_protected_key_access_survive_a_cli_process_restart() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should follow the Unix epoch")
        .as_nanos();
    let data_dir = std::env::temp_dir().join(format!(
        "lattice-cli-restart-{}-{unique}",
        std::process::id()
    ));

    let initialize = Command::new(env!("CARGO_BIN_EXE_lattice"))
        .args(["--json", "--data-dir"])
        .arg(&data_dir)
        .args(["identity", "init"])
        .output()
        .expect("identity initialization process should start");
    let reopen = Command::new(env!("CARGO_BIN_EXE_lattice"))
        .args(["--json", "--data-dir"])
        .arg(&data_dir)
        .args(["identity", "show"])
        .output()
        .expect("identity reopen process should start");

    let cleanup = if data_dir.exists() {
        std::fs::remove_dir_all(&data_dir)
    } else {
        Ok(())
    };
    assert!(cleanup.is_ok(), "remove isolated CLI profile");

    assert!(
        initialize.status.success(),
        "identity initialization failed: {}",
        String::from_utf8_lossy(&initialize.stderr)
    );
    assert!(
        reopen.status.success(),
        "identity reopen failed: {}",
        String::from_utf8_lossy(&reopen.stderr)
    );
    let initialized: Value =
        serde_json::from_slice(&initialize.stdout).expect("initialization emits JSON");
    let reopened: Value = serde_json::from_slice(&reopen.stdout).expect("reopen emits JSON");

    assert_eq!(initialized["command"], "identity");
    assert_eq!(reopened["command"], "identity");
    assert_eq!(initialized["fingerprint"], reopened["fingerprint"]);
    assert_eq!(initialized["public_bundle"], reopened["public_bundle"]);
    assert_eq!(reopened["private_key_exposed"], false);
    assert_eq!(reopened["protected_key_access"], "available");
}
