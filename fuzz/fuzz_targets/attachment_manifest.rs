#![no_main]

use std::io::Cursor;

use lattice_files::AttachmentManifest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut reader = Cursor::new(data);
    if let Ok(manifest) = AttachmentManifest::from_reader(&mut reader, "fuzz.bin", None) {
        assert!(manifest.validate().is_ok());
        assert!(manifest.transfer_id(&[0; 32]).is_ok());
        let _ = manifest.missing_chunk_ranges(data);
    }
});
