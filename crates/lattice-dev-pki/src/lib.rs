//! Test-only certificate authority and CSR issuer. Never use these credentials in production.

use std::{
    fs,
    path::{Path, PathBuf},
};

use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PKCS_ED25519, SanType,
};
use time::OffsetDateTime;
use x509_parser::prelude::FromDer;

pub const MAX_CREDENTIAL_VECTOR_BYTES: usize = 16 * 1024;
const URI_PREFIX: &str = "urn:lattice:identity:v1:";

#[derive(Debug, thiserror::Error)]
pub enum PkiError {
    #[error("invalid device name")]
    InvalidDeviceName,
    #[error("output directory already exists or is not empty")]
    OutputExists,
    #[error("invalid certificate signing request: {0}")]
    InvalidCsr(String),
    #[error("CSR must contain exactly one canonical Lattice identity URI SAN")]
    InvalidIdentitySan,
    #[error("CSR public key must be Ed25519")]
    WrongKeyType,
    #[error("invalid CA certificate or private key: {0}")]
    InvalidCa(String),
    #[error("credential vector exceeds {MAX_CREDENTIAL_VECTOR_BYTES} bytes")]
    VectorTooLarge,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("certificate generation failed: {0}")]
    Rcgen(#[from] rcgen::Error),
}

pub struct IssuedCredential {
    pub certificate_pem: String,
    pub certificate_der: Vec<u8>,
    pub credential_vector: Vec<u8>,
}

/// Creates a fresh self-signed P-256 test CA in a previously nonexistent directory.
pub fn create_ca(output_dir: impl AsRef<Path>) -> Result<(), PkiError> {
    let output_dir = output_dir.as_ref();
    ensure_new_directory(output_dir)?;
    let result = (|| {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let now = OffsetDateTime::now_utc();
        let mut params = CertificateParams::default();
        params.not_before = now - time::Duration::minutes(5);
        params.not_after = now + time::Duration::days(365);
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let mut name = DistinguishedName::new();
        name.push(DnType::OrganizationName, "Lattice Development Only");
        name.push(
            DnType::CommonName,
            "Lattice Local Test CA DO NOT TRUST IN PRODUCTION",
        );
        params.distinguished_name = name;
        let cert = params.self_signed(&key)?;
        write_new(
            output_dir.join("lattice-development-only-ca.cert.pem"),
            cert.pem().as_bytes(),
        )?;
        write_new(
            output_dir.join("lattice-development-only-ca.cert.der"),
            cert.der().as_ref(),
        )?;
        write_new(
            output_dir.join("lattice-development-only-ca.key.pem"),
            key.serialize_pem().as_bytes(),
        )?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(output_dir);
    }
    result
}

/// Verifies and issues a CSR while retaining its Ed25519 public key and identity SAN.
pub fn issue_csr(
    ca_cert_pem: &str,
    ca_key_pem: &str,
    csr_pem: &str,
    device_name: &str,
) -> Result<IssuedCredential, PkiError> {
    let now = OffsetDateTime::now_utc();
    issue_csr_at(
        ca_cert_pem,
        ca_key_pem,
        csr_pem,
        device_name,
        now - time::Duration::minutes(5),
        now + time::Duration::days(90),
    )
}

#[cfg(feature = "test-utils")]
pub fn issue_expired_csr(
    ca_cert_pem: &str,
    ca_key_pem: &str,
    csr_pem: &str,
    device_name: &str,
) -> Result<IssuedCredential, PkiError> {
    let now = OffsetDateTime::now_utc();
    issue_csr_at(
        ca_cert_pem,
        ca_key_pem,
        csr_pem,
        device_name,
        now - time::Duration::days(30),
        now - time::Duration::days(1),
    )
}

fn issue_csr_at(
    ca_cert_pem: &str,
    ca_key_pem: &str,
    csr_pem: &str,
    device_name: &str,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
) -> Result<IssuedCredential, PkiError> {
    validate_device_name(device_name)?;
    let csr = CertificateSigningRequestParams::from_pem(csr_pem)
        .map_err(|error| PkiError::InvalidCsr(error.to_string()))?;
    if csr.public_key.algorithm() != &PKCS_ED25519 {
        return Err(PkiError::WrongKeyType);
    }
    let uri_names: Vec<_> = csr
        .params
        .subject_alt_names
        .iter()
        .filter_map(|name| match name {
            SanType::URI(uri) => Some(uri.as_str()),
            _ => None,
        })
        .collect();
    if uri_names.len() != 1 || !is_canonical_identity_uri(uri_names[0]) {
        return Err(PkiError::InvalidIdentitySan);
    }

    let ca_key =
        KeyPair::from_pem(ca_key_pem).map_err(|error| PkiError::InvalidCa(error.to_string()))?;
    validate_ca_material(ca_cert_pem, &ca_key)?;
    let issuer = Issuer::from_ca_cert_pem(ca_cert_pem, &ca_key)
        .map_err(|error| PkiError::InvalidCa(error.to_string()))?;
    let mut params = csr.params;
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages.clear();
    params.not_before = not_before;
    params.not_after = not_after;
    let cert = CertificateSigningRequestParams {
        params,
        public_key: csr.public_key,
    }
    .signed_by(&issuer)?;
    let der = cert.der().as_ref().to_vec();
    let vector = encode_credential_vector(&der)?;
    Ok(IssuedCredential {
        certificate_pem: cert.pem(),
        certificate_der: der,
        credential_vector: vector,
    })
}

/// Validates, issues, and writes a named leaf into a new output directory.
pub fn issue_to_directory(
    ca_cert_path: impl AsRef<Path>,
    ca_key_path: impl AsRef<Path>,
    csr_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    device_name: &str,
) -> Result<(), PkiError> {
    validate_device_name(device_name)?;
    let cert_pem = fs::read_to_string(ca_cert_path)?;
    let key_pem = fs::read_to_string(ca_key_path)?;
    let csr_pem = fs::read_to_string(csr_path)?;
    let issued = issue_csr(&cert_pem, &key_pem, &csr_pem, device_name)?;
    let output_dir = output_dir.as_ref();
    ensure_new_directory(output_dir)?;
    let paths = [
        (
            format!("{device_name}.test-only.cert.pem"),
            issued.certificate_pem.as_bytes(),
        ),
        (
            format!("{device_name}.test-only.cert.der"),
            issued.certificate_der.as_slice(),
        ),
        (
            format!("{device_name}.test-only.credential-vector.bin"),
            issued.credential_vector.as_slice(),
        ),
    ];
    for (name, bytes) in paths {
        if let Err(error) = write_new(output_dir.join(name), bytes) {
            let _ = fs::remove_dir_all(output_dir);
            return Err(error);
        }
    }
    Ok(())
}

/// RFC 9420 CredentialData certificate_list vector containing exactly one DER leaf.
pub fn encode_credential_vector(certificate_der: &[u8]) -> Result<Vec<u8>, PkiError> {
    let mut certificate_list = Vec::with_capacity(certificate_der.len() + 4);
    encode_varint(certificate_der.len(), &mut certificate_list)?;
    certificate_list.extend_from_slice(certificate_der);
    let mut vector = Vec::with_capacity(certificate_list.len() + 4);
    encode_varint(certificate_list.len(), &mut vector)?;
    vector.extend_from_slice(&certificate_list);
    if vector.len() > MAX_CREDENTIAL_VECTOR_BYTES {
        return Err(PkiError::VectorTooLarge);
    }
    Ok(vector)
}

fn encode_varint(value: usize, output: &mut Vec<u8>) -> Result<(), PkiError> {
    if value <= 0x3f {
        output.push(value as u8);
    } else if value <= 0x3fff {
        output.extend_from_slice(&[((value >> 8) as u8) | 0x40, value as u8]);
    } else if value <= 0x3fff_ffff {
        output.extend_from_slice(&[
            ((value >> 24) as u8) | 0x80,
            (value >> 16) as u8,
            (value >> 8) as u8,
            value as u8,
        ]);
    } else {
        return Err(PkiError::VectorTooLarge);
    }
    Ok(())
}

fn is_canonical_identity_uri(uri: &str) -> bool {
    uri.strip_prefix(URI_PREFIX).is_some_and(|fingerprint| {
        fingerprint.len() == 64
            && fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn validate_device_name(name: &str) -> Result<(), PkiError> {
    let mut bytes = name.bytes();
    let valid = bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && name.len() <= 64
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(PkiError::InvalidDeviceName)
    }
}

fn ensure_new_directory(path: &Path) -> Result<PathBuf, PkiError> {
    if path.exists() {
        return Err(PkiError::OutputExists);
    }
    fs::create_dir(path)?;
    Ok(path.to_path_buf())
}

fn write_new(path: impl AsRef<Path>, bytes: &[u8]) -> Result<(), PkiError> {
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn validate_ca_material(ca_pem: &str, ca_key: &KeyPair) -> Result<(), PkiError> {
    let pem = x509_parser::pem::parse_x509_pem(ca_pem.as_bytes())
        .map_err(|error| PkiError::InvalidCa(error.to_string()))?
        .1;
    let (_, certificate) = x509_parser::certificate::X509Certificate::from_der(&pem.contents)
        .map_err(|error| PkiError::InvalidCa(error.to_string()))?;
    let constraints = certificate
        .basic_constraints()
        .map_err(|error| PkiError::InvalidCa(error.to_string()))?
        .ok_or_else(|| PkiError::InvalidCa("certificate lacks basic constraints".into()))?;
    let usage = certificate
        .key_usage()
        .map_err(|error| PkiError::InvalidCa(error.to_string()))?
        .ok_or_else(|| PkiError::InvalidCa("certificate lacks key usage".into()))?;
    if !constraints.value.ca
        || constraints.value.path_len_constraint != Some(0)
        || !usage.value.key_cert_sign()
        || !usage.value.crl_sign()
        || certificate.public_key().subject_public_key.data.as_ref() != ca_key.public_key_raw()
        || certificate.verify_signature(None).is_err()
    {
        return Err(PkiError::InvalidCa(
            "certificate constraints, signature, or key pair are invalid".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ED25519};
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "lattice-dev-pki-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn csr(sans: &[String], algorithm: &'static rcgen::SignatureAlgorithm) -> String {
        let key = KeyPair::generate_for(algorithm).unwrap();
        let mut params = CertificateParams::default();
        params.subject_alt_names = sans
            .iter()
            .map(|uri| {
                rcgen::SanType::URI(rcgen::string::Ia5String::try_from(uri.clone()).unwrap())
            })
            .collect();
        params.serialize_request(&key).unwrap().pem().unwrap()
    }

    fn ca() -> (std::path::PathBuf, String, String) {
        let directory = temp_path("ca");
        super::create_ca(&directory).unwrap();
        let cert =
            fs::read_to_string(directory.join("lattice-development-only-ca.cert.pem")).unwrap();
        let key =
            fs::read_to_string(directory.join("lattice-development-only-ca.key.pem")).unwrap();
        (directory, cert, key)
    }

    #[test]
    fn issues_credential_from_verified_ed25519_csr() {
        let (ca_dir, cert, key) = ca();
        let request = csr(&["urn:lattice:identity:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()], &PKCS_ED25519);
        let issued = super::issue_csr(&cert, &key, &request, "cli").unwrap();
        assert_eq!(
            issued.credential_vector.len(),
            issued.certificate_der.len() + 4
        );
        let output = temp_path("issued");
        let csr_path = temp_path("request.pem");
        fs::write(&csr_path, request).unwrap();
        super::issue_to_directory(
            ca_dir.join("lattice-development-only-ca.cert.pem"),
            ca_dir.join("lattice-development-only-ca.key.pem"),
            &csr_path,
            &output,
            "cli",
        )
        .unwrap();
        let _ = fs::remove_file(csr_path);
        assert!(output.join("cli.test-only.cert.pem").is_file());
        assert!(output.join("cli.test-only.cert.der").is_file());
        assert!(output.join("cli.test-only.credential-vector.bin").is_file());
        let _ = fs::remove_dir_all(ca_dir);
        let _ = fs::remove_dir_all(output);
    }

    #[test]
    fn rejects_malformed_csr_and_invalid_ca() {
        assert!(matches!(
            super::issue_csr("bad", "bad", "not a CSR", "cli"),
            Err(super::PkiError::InvalidCsr(_))
        ));
        let uri = "urn:lattice:identity:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned();
        let request = csr(std::slice::from_ref(&uri), &PKCS_ED25519);
        let (_, cert, key) = ca();
        assert!(matches!(
            super::issue_csr("bad", &key, &request, "cli"),
            Err(super::PkiError::InvalidCa(_))
        ));
        assert!(matches!(
            super::issue_csr(&cert, "not a key", &request, "cli"),
            Err(super::PkiError::InvalidCa(_))
        ));
    }

    #[test]
    fn rejects_wrong_key_and_noncanonical_or_missing_san() {
        let (_, cert, key) = ca();
        let uri = "urn:lattice:identity:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned();
        assert!(matches!(
            super::issue_csr(
                &cert,
                &key,
                &csr(std::slice::from_ref(&uri), &PKCS_ECDSA_P256_SHA256),
                "cli"
            ),
            Err(super::PkiError::WrongKeyType)
        ));
        assert!(matches!(
            super::issue_csr(&cert, &key, &csr(&[], &PKCS_ED25519), "cli"),
            Err(super::PkiError::InvalidIdentitySan)
        ));
        assert!(matches!(
            super::issue_csr(&cert, &key, &csr(&[uri.clone(), uri], &PKCS_ED25519), "cli"),
            Err(super::PkiError::InvalidIdentitySan)
        ));
        let upper = "urn:lattice:identity:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned();
        assert!(matches!(
            super::issue_csr(&cert, &key, &csr(&[upper], &PKCS_ED25519), "cli"),
            Err(super::PkiError::InvalidIdentitySan)
        ));
    }

    #[test]
    fn refuses_conflicting_output_directories_and_names() {
        let directory = temp_path("exists");
        fs::create_dir(&directory).unwrap();
        assert!(matches!(
            super::create_ca(&directory),
            Err(super::PkiError::OutputExists)
        ));
        assert!(matches!(
            super::issue_csr("", "", "", "../bad"),
            Err(super::PkiError::InvalidDeviceName)
        ));
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn rejects_invalid_csr_signature() {
        let (_, cert, key) = ca();
        let request = csr(&["urn:lattice:identity:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()], &PKCS_ED25519);
        let mut contents = pem::parse(request).unwrap().into_contents();
        let last = contents.last_mut().unwrap();
        *last ^= 1;
        let corrupted = pem::encode(&pem::Pem::new("CERTIFICATE REQUEST", contents));
        assert!(matches!(
            super::issue_csr(&cert, &key, &corrupted, "cli"),
            Err(super::PkiError::InvalidCsr(_))
        ));
    }

    #[test]
    fn vector_rejects_oversized_input() {
        assert!(
            super::encode_credential_vector(&vec![0; super::MAX_CREDENTIAL_VECTOR_BYTES]).is_err()
        );
    }
}
