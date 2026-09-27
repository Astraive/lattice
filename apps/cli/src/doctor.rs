use std::{fs, path::Path};

use lattice_identity::DeviceIdentity;
use lattice_platform::{OsKeyringProtectionError, OsKeyringProtector};
use lattice_storage::{Store, StoreError};

use crate::PROFILE_ID;

pub(super) fn execute_doctor(database_path: &Path, json: bool) {
    if !database_path.exists() {
        print_report(
            json,
            "attention_required",
            "not_initialized",
            None,
            "not_initialized",
            "not_checked",
            None,
        );
        return;
    }

    let (store, schema_version) = match inspect_database(database_path) {
        Ok(database) => database,
        Err(error) => {
            print_report(
                json,
                "attention_required",
                error.status,
                error.schema_version,
                "not_checked",
                "not_checked",
                read_only_attribute(database_path),
            );
            if let Some(class) = error.class
                && !json
            {
                println!("Database check category: {class}");
            }
            return;
        }
    };
    let Ok(protector) = OsKeyringProtector::new(PROFILE_ID) else {
        print_report(
            json,
            "attention_required",
            "opened",
            Some(schema_version),
            "key_protection_unavailable",
            "key_protection_unavailable",
            read_only_attribute(database_path),
        );
        return;
    };

    let identity_status = match store.load_protected_identity() {
        Ok(Some(ciphertext)) => identity_status(&protector, &ciphertext),
        Ok(None) => "not_initialized",
        Err(_) => "storage_read_failed",
    };
    let mls_key_status = match store.load_protected_mls_storage_key() {
        Ok(Some(ciphertext)) => mls_key_status(&protector, &ciphertext),
        Ok(None) => "not_initialized",
        Err(_) => "storage_read_failed",
    };
    let profile_ready = identity_status == "ok" && mls_key_status == "ok";
    print_report(
        json,
        if profile_ready {
            "local_storage_and_keys_available"
        } else {
            "attention_required"
        },
        "opened",
        Some(schema_version),
        identity_status,
        mls_key_status,
        read_only_attribute(database_path),
    );
}

struct DatabaseInspectionError {
    status: &'static str,
    schema_version: Option<i64>,
    class: Option<&'static str>,
}

fn inspect_database(database_path: &Path) -> Result<(Store, i64), DatabaseInspectionError> {
    let store = Store::open_read_only(database_path).map_err(|error| {
        let (status, class) = database_error(&error);
        DatabaseInspectionError {
            status,
            schema_version: None,
            class: Some(class),
        }
    })?;
    let schema_version = store.schema_version().map_err(|error| {
        let (status, class) = database_error(&error);
        DatabaseInspectionError {
            status,
            schema_version: None,
            class: Some(class),
        }
    })?;
    let integrity_ok = store.integrity_check().map_err(|error| {
        let (status, class) = database_error(&error);
        DatabaseInspectionError {
            status,
            schema_version: Some(schema_version),
            class: Some(class),
        }
    })?;
    if !integrity_ok {
        return Err(DatabaseInspectionError {
            status: "integrity_check_failed",
            schema_version: Some(schema_version),
            class: None,
        });
    }
    if schema_version != lattice_storage::CURRENT_SCHEMA_VERSION {
        return Err(DatabaseInspectionError {
            status: schema_status(schema_version),
            schema_version: Some(schema_version),
            class: None,
        });
    }
    Ok((store, schema_version))
}

fn schema_status(schema_version: i64) -> &'static str {
    match schema_version.cmp(&lattice_storage::CURRENT_SCHEMA_VERSION) {
        std::cmp::Ordering::Less => "migration_required",
        std::cmp::Ordering::Equal => "current",
        std::cmp::Ordering::Greater => "newer_than_supported",
    }
}

fn identity_status(protector: &OsKeyringProtector, ciphertext: &[u8]) -> &'static str {
    match protector.unwrap_detailed(ciphertext) {
        Err(error) => protector_status(error),
        Ok(_) => match DeviceIdentity::load_protected(protector, ciphertext) {
            Ok(_) => "ok",
            Err(_) => "invalid_protected_identity",
        },
    }
}

fn mls_key_status(protector: &OsKeyringProtector, ciphertext: &[u8]) -> &'static str {
    match protector.unwrap_detailed(ciphertext) {
        Ok(key) if key.len() == 32 => "ok",
        Ok(_) => "invalid_key_length",
        Err(error) => protector_status(error),
    }
}

fn protector_status(error: OsKeyringProtectionError) -> &'static str {
    match error {
        OsKeyringProtectionError::Locked => "locked",
        OsKeyringProtectionError::MissingKey => "wrapping_key_missing",
        OsKeyringProtectionError::UnsupportedPlatform => "unsupported_platform",
        OsKeyringProtectionError::InvalidFormat
        | OsKeyringProtectionError::UnsupportedVersion
        | OsKeyringProtectionError::AuthenticationFailed
        | OsKeyringProtectionError::InvalidStoredKey => "invalid_protected_data",
        OsKeyringProtectionError::StoreUnavailable
        | OsKeyringProtectionError::StoreFailure
        | OsKeyringProtectionError::SynchronizationFailure => "key_protection_unavailable",
        _ => "key_protection_error",
    }
}

fn database_error(error: &StoreError) -> (&'static str, &'static str) {
    match error {
        StoreError::CorruptData(_) => ("corrupt_or_unsupported", "corrupt_or_unsupported"),
        StoreError::Sqlite(_) => ("open_failed", "sqlite_open_failed"),
        _ => ("storage_error", "storage_error"),
    }
}

fn read_only_attribute(database_path: &Path) -> Option<bool> {
    fs::metadata(database_path)
        .ok()
        .map(|metadata| metadata.permissions().readonly())
}

fn print_report(
    json: bool,
    overall: &str,
    database: &str,
    schema_version: Option<i64>,
    identity: &str,
    mls_storage_key: &str,
    database_read_only_attribute: Option<bool>,
) {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "command": "doctor",
                "overall": overall,
                "database": {
                    "status": database,
                    "schema_version": schema_version,
                    "supported_schema_version": lattice_storage::CURRENT_SCHEMA_VERSION,
                    "schema_status": schema_version.map_or("not_available", schema_status),
                    "integrity_check": database == "opened" || database == "migration_required" || database == "newer_than_supported",
                    "storage_migrations_may_run": false,
                    "read_only_attribute": database_read_only_attribute,
                },
                "identity_key": {
                    "status": identity,
                    "private_key_exposed": false,
                },
                "mls_storage_key": { "status": mls_storage_key },
                "permissions": {
                    "effective_filesystem_permissions_checked": false,
                    "database_read_only_attribute": database_read_only_attribute,
                },
                "transport": {
                    "status": "not_configured",
                    "network_delivery_available": false,
                },
                "wire_compatibility": {
                    "status": "not_checked_no_peer_transport",
                    "local_profile_version_available": false,
                },
                "remediation_categories": {
                    "database": (database != "opened").then_some("inspect_profile_storage_and_schema"),
                    "identity_key": (identity != "ok").then_some("initialize_or_unlock_identity"),
                    "mls_storage_key": (mls_storage_key != "ok").then_some("restore_protected_mls_key_access"),
                    "transport": "transport_backend_unavailable",
                    "wire_compatibility": "requires_peer_transport",
                },
            })
        );
    } else {
        println!("Overall: {overall}");
        println!("Database: {database}");
        println!(
            "Database schema: {}/{} ({})",
            schema_version.map_or_else(|| "unavailable".to_owned(), |version| version.to_string()),
            lattice_storage::CURRENT_SCHEMA_VERSION,
            schema_version.map_or("not available", schema_status)
        );
        println!("Protected device identity: {identity} (private key never displayed)");
        println!("Protected MLS storage key: {mls_storage_key}");
        match database_read_only_attribute {
            Some(true) => println!("Database read-only attribute: set"),
            Some(false) => println!("Database read-only attribute: not set"),
            None => println!("Database read-only attribute: unavailable"),
        }
        println!("Effective filesystem permissions are not checked by current platform APIs.");
        println!("Database diagnostics never apply migrations.");
        println!("Transport: not_configured; no network delivery is enabled.");
        println!(
            "Remote wire compatibility was not checked because no peer transport is configured."
        );
        println!(
            "Remediation: inspect local profile/key protection and configure a transport for remote checks."
        );
    }
}
