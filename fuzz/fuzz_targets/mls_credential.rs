#![no_main]

use lattice_identity::DeviceIdentity;
use lattice_mls::api::{
    CredentialTrustPolicy, DeviceCredentialInput, MAX_CREDENTIAL_BYTES,
};
use libfuzzer_sys::fuzz_target;
use openmls::credentials::{Credential, CredentialType};

fuzz_target!(|data: &[u8]| {
    let Some((&mode, content)) = data.split_first() else {
        return;
    };
    let Ok(identity) = DeviceIdentity::generate() else {
        return;
    };
    let credential_type = if mode & 1 == 0 {
        CredentialType::X509
    } else {
        CredentialType::Basic
    };
    let credential = Credential::new(credential_type, content.to_vec());
    let trust_policy = CredentialTrustPolicy::native_system();

    if let Ok(input) = DeviceCredentialInput::from_x509_credential_with_policy(
        &identity,
        credential,
        &trust_policy,
    ) {
        assert!(content.len() <= MAX_CREDENTIAL_BYTES);
        assert_eq!(input.identity_fingerprint(), &identity.fingerprint());
        assert!(input.trust_policy().same_policy(&trust_policy));
    }
});
