#![no_main]

use lattice_core::{SpaceInviteV1, SpaceWelcomeBootstrapV1};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(invite) = SpaceInviteV1::from_bytes(data) {
        if let Ok(encoded) = invite.to_bytes() {
            assert_eq!(encoded.as_slice(), data);
        } else {
            panic!("an accepted invitation must encode");
        }
    }

    if let Ok(bootstrap) = SpaceWelcomeBootstrapV1::from_bytes(data) {
        if let Ok(encoded) = bootstrap.to_bytes() {
            assert_eq!(encoded.as_slice(), data);
        } else {
            panic!("an accepted bootstrap must encode");
        }
    }
});
