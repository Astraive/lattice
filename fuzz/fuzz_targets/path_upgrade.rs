#![no_main]

use lattice_protocol::{MAX_PATH_UPGRADE_FRAME_BYTES, PathUpgradeCapabilities};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(offer) = PathUpgradeCapabilities::decode(data) {
        for limit in [
            offer.lan_max_frame_bytes(),
            offer.wifi_aware_max_frame_bytes(),
            offer.wifi_direct_max_frame_bytes(),
        ]
        .into_iter()
        .flatten()
        {
            assert!(limit > 0);
            assert!(limit <= MAX_PATH_UPGRADE_FRAME_BYTES);
        }

        assert_eq!(offer.encode().expect("decoded offer re-encodes"), data);

        let negotiated = offer.negotiate(offer);
        assert_eq!(negotiated.lan_max_frame_bytes(), offer.lan_max_frame_bytes());
        assert_eq!(
            negotiated.wifi_aware_max_frame_bytes(),
            offer.wifi_aware_max_frame_bytes()
        );
        assert_eq!(
            negotiated.wifi_direct_max_frame_bytes(),
            offer.wifi_direct_max_frame_bytes()
        );
    }
});
