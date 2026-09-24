use clap::Subcommand;

use crate::hex;

#[derive(Debug, Subcommand)]
pub(super) enum IdentityCommand {
    /// Create a device identity once, or reopen the existing one.
    Init,
    /// Show public identity data for an initialized profile.
    Show,
    /// Pin a public bundle after caller-performed full-fingerprint comparison.
    Pin {
        /// Exact 65-byte public bundle encoded as 130 hexadecimal characters.
        #[arg(long)]
        bundle_hex: String,
        /// Expected full 32-byte fingerprint encoded as 64 hexadecimal characters.
        #[arg(long)]
        fingerprint_hex: String,
    },
    /// Show a locally pinned bundle by its full fingerprint.
    Pinned {
        /// Full 32-byte fingerprint encoded as 64 hexadecimal characters.
        #[arg(long)]
        fingerprint_hex: String,
    },
}

pub(super) fn print_pinned_identity(
    pinned: Option<([u8; 32], [u8; 65])>,
    json: bool,
    command: &str,
) {
    const LIMITATION: &str = "A local full-fingerprint match only; persistence does not prove that the caller-performed comparison occurred and does not grant MLS membership.";
    match pinned {
        Some((fingerprint, public_bundle)) => {
            let fingerprint = hex(&fingerprint);
            let public_bundle = hex(&public_bundle);
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "schema_version": 1,
                        "command": command,
                        "pinned": true,
                        "fingerprint": fingerprint,
                        "public_bundle": public_bundle,
                        "meaning": "local_full_fingerprint_match",
                        "limitation": LIMITATION,
                    })
                );
            } else {
                println!("Pinned fingerprint: {fingerprint}");
                println!("Public bundle: {public_bundle}");
                println!("{LIMITATION}");
            }
        }
        None => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "schema_version": 1,
                        "command": command,
                        "pinned": false,
                        "fingerprint": null,
                        "public_bundle": null,
                        "meaning": "no_local_pin",
                        "limitation": LIMITATION,
                    })
                );
            } else {
                println!("No local pin exists for that fingerprint.");
                println!("{LIMITATION}");
            }
        }
    }
}
