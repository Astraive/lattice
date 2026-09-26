# Development-only X.509 PKI

This tooling exists only to exercise the production RFC 9420 credential validation path during local development. Its CA is self-signed and must never be installed on production systems or used to issue production credentials. The development CA signing key is high impact: keep it in a private development workspace and delete it when no longer needed. Device signing keys remain inside each Lattice client; the issuer receives only a CSR.

The production path still requires a valid X.509 chain in the operating-system trust store, an Ed25519 leaf SPKI matching the local signing key, a valid certificate period, and exactly one canonical `urn:lattice:identity:v1:<fingerprint>` URI SAN matching the full Lattice identity. No validation switch or caller-supplied trust root is added. See [the security model](security/SECURITY_MODEL.md#cryptographic-layers).

## Requirements

- PowerShell 7 or Windows PowerShell 5.1.
- OpenSSL 3.x on `PATH`.
- A built `lattice` CLI (build from the repository with `cargo build -p lattice-cli`).

## Issue a credential for a client identity

Use one isolated CLI data directory per client. The CSR is signed by that profile's actual Lattice Ed25519 identity, and the corresponding private key stays in the client's protected profile.

```powershell
$root = Join-Path $PWD 'local-dev-pki'
$cli = (Resolve-Path '.\target\debug\lattice.exe').Path

# Create a new, test-only root. The script refuses to reuse an output directory.
.\tooling\dev-pki\New-DevelopmentCa.ps1 -OutputDirectory "$root\ca"

# Repeat with a distinct directory for each independently initialized device/client.
$profile = "$root\profiles\cli-a"
New-Item -ItemType Directory -Path $profile | Out-Null
& $cli --data-dir "$profile\data" identity init
& $cli --data-dir "$profile\data" identity csr --output "$profile\cli-a.csr.pem"
if ($LASTEXITCODE -ne 0) { throw 'Could not create the Lattice identity CSR.' }

.\tooling\dev-pki\Issue-DeviceCertificate.ps1 `
  -CaKey "$root\ca\lattice-development-only-ca.key.pem" `
  -CaCertificate "$root\ca\lattice-development-only-ca.cert.pem" `
  -Csr "$profile\cli-a.csr.pem" `
  -OutputDirectory "$profile\issued" `
  -DeviceName 'cli-a'
```

Repeat the profile and issuance steps only for client identities whose normal APIs produce CSRs. The example uses a CLI profile. Android and Desktop issuance must use their own normal CSR paths and still need client-specific acceptance. Web has no client/profile yet; do not treat the protocol inspector as a Web Lattice client. The issuer creates a short-lived leaf certificate and a binary RFC 9420 certificate vector containing the leaf certificate; the self-signed root is installed separately as a local trust anchor.

## Install and remove the development root

On Windows, install only into the current user's root store, for the duration of the test:

```powershell
.\tooling\dev-pki\Set-DevelopmentCaTrust.ps1 `
  -CaCertificate "$root\ca\lattice-development-only-ca.cert.pem" -Action Install
# After the test:
.\tooling\dev-pki\Set-DevelopmentCaTrust.ps1 `
  -CaCertificate "$root\ca\lattice-development-only-ca.cert.pem" -Action Remove
```

On Linux, use the distribution's local CA mechanism (for Debian/Ubuntu, copy the PEM to `/usr/local/share/ca-certificates/lattice-development-only-ca.crt`, run `sudo update-ca-certificates`, and remove it and refresh again after testing). On macOS, add the PEM to the System or login keychain using `security add-trusted-cert` and remove that exact certificate with Keychain Access after testing. These are explicit host trust-store changes; do not automate them in CI or install this root globally on shared machines. Restart the client process after changing the trust store so native-root loading sees the updated roots.

## Client trust-store constraints

Desktop and CLI use the host's native certificate roots through `rustls-native-certs`. On Windows, this build reads Current User `ROOT`; the checked-in helper installs and removes the development CA there. Linux and macOS tests must use the host trust-store instructions above and remove the exact test root afterward.

Android does not use the host loader. `lattice-mls` reads the Conscrypt APEX CA directory when it contains any certificate-named files, otherwise it reads `/system/etc/security/cacerts`. Ordinary user-installed Android certificates, APK network-security configuration, and Windows trust changes do not affect this custom validator. For a test-only system image, provision the development CA as a PEM or DER file with a numeric suffix (for example, `lattice-development-only-ca.0`) in the exact CA directory the loader selects, then restart the app. The loader chooses APEX whenever it contains a numeric-suffix entry; the legacy directory is only a fallback when APEX has none. This repository does not build or modify Android system images. Use a disposable emulator or test system image; do not alter a personal device. No credential-validation bypass or app-supplied root is supported.

There is no Web Lattice client or browser credential path in this repository. Do not issue or claim Web credentials until the browser client and its trust model are implemented and verified.

## Verify using the real production validator

Use the generated certificate vector with the existing production CLI command in a fresh profile. `space create` constructs an MLS credential through `DeviceCredentialInput::from_x509_credential`; success therefore exercises chain trust, certificate structure/period, key binding, and fingerprint SAN validation, not a test-only credential helper.

```powershell
& $cli --data-dir "$profile\data" space create `
  --credential "$profile\issued\cli-a.test-only.credential-vector.bin" `
  --channel 'general'
if ($LASTEXITCODE -ne 0) { throw 'Production credential validation or Space creation failed.' }
```

Use a fresh profile per identity and issue a certificate for each CSR. A wrong-key certificate, an altered fingerprint SAN, an expired certificate, or an untrusted root must be rejected by the normal validator. Do not infer peer membership or network interoperability from local Space creation; use the cross-client acceptance procedures for those claims.

## Cleanup and containment

The CLI data directories, CSR files, issued leaf certificates, vectors, CA private key, and serial file are local test material. Keep them out of version control and diagnostics. Remove the test root from the platform trust store, then delete the development PKI and profiles when finished. The checked-in tooling does not create identities by exporting or copying private keys.
