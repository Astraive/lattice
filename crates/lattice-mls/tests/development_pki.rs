use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use lattice_dev_pki::{create_ca, issue_csr, issue_expired_csr};
use lattice_identity::DeviceIdentity;
use lattice_mls::api::{CredentialTrustPolicy, DeviceCredentialInput};
use openmls::credentials::{Credential, CredentialType};
use sha2::{Digest, Sha256};

fn temporary_directory(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "lattice-pki-mls-{name}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn csr_pem(identity: &DeviceIdentity) -> String {
    pem::encode(&pem::Pem::new(
        "CERTIFICATE REQUEST",
        identity.certificate_signing_request().unwrap(),
    ))
}

fn create_issuer(name: &str) -> (PathBuf, String, String, Vec<u8>, CredentialTrustPolicy) {
    let directory = temporary_directory(name);
    create_ca(&directory).unwrap();
    let certificate =
        fs::read_to_string(directory.join("lattice-development-only-ca.cert.pem")).unwrap();
    let key = fs::read_to_string(directory.join("lattice-development-only-ca.key.pem")).unwrap();
    let root_der = fs::read(directory.join("lattice-development-only-ca.cert.der")).unwrap();
    let digest: [u8; 32] = Sha256::digest(&root_der).into();
    let policy = CredentialTrustPolicy::pinned_root_der(&root_der, &digest).unwrap();
    (directory, certificate, key, root_der, policy)
}

fn validate(
    identity: &DeviceIdentity,
    vector: Vec<u8>,
    policy: &CredentialTrustPolicy,
) -> Result<DeviceCredentialInput, lattice_mls::api::MlsError> {
    DeviceCredentialInput::from_x509_credential_with_policy(
        identity,
        Credential::new(CredentialType::X509, vector),
        policy,
    )
}

#[test]
fn development_pki_uses_the_production_pinned_root_validator() {
    let (ca_dir, ca_cert, ca_key, _, policy) = create_issuer("trusted");
    let identity = DeviceIdentity::generate().unwrap();
    let request = csr_pem(&identity);
    let matching = issue_csr(&ca_cert, &ca_key, &request, "matching").unwrap();
    assert!(validate(&identity, matching.credential_vector, &policy).is_ok());

    let other_identity = DeviceIdentity::generate().unwrap();
    let mismatched = issue_csr(&ca_cert, &ca_key, &csr_pem(&other_identity), "wrong-key").unwrap();
    assert!(validate(&identity, mismatched.credential_vector, &policy).is_err());

    let altered_identity_san =
        issue_csr(&ca_cert, &ca_key, &csr_pem(&other_identity), "altered-san").unwrap();
    assert!(validate(&identity, altered_identity_san.credential_vector, &policy).is_err());

    let expired = issue_expired_csr(&ca_cert, &ca_key, &request, "expired").unwrap();
    assert!(validate(&identity, expired.credential_vector, &policy).is_err());

    let (untrusted_dir, untrusted_cert, untrusted_key, _, _) = create_issuer("untrusted");
    let untrusted = issue_csr(&untrusted_cert, &untrusted_key, &request, "untrusted").unwrap();
    assert!(validate(&identity, untrusted.credential_vector, &policy).is_err());

    let _ = fs::remove_dir_all(ca_dir);
    let _ = fs::remove_dir_all(untrusted_dir);
}
