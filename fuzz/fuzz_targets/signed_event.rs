#![no_main]

use lattice_events::VerifiedSignatureOnlyEvent;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(event) = VerifiedSignatureOnlyEvent::decode_verify(data) {
        assert_eq!(event.encode(), data);
    }
});
