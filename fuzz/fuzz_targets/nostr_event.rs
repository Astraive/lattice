#![no_main]

use lattice_relay::nip01::NostrEventV1;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(event) = NostrEventV1::parse_json(data) {
        assert!(event.verify());
    }
});
