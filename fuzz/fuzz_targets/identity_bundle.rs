#![no_main]

use lattice_identity::IdentityPublicBundle;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(bundle) = IdentityPublicBundle::from_bytes(data) {
        assert_eq!(bundle.to_bytes().as_slice(), data);
    }
});
