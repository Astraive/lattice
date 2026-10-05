# Development-only X.509 PKI

This tooling exercises the production RFC 9420 credential validator with local test material. The generated CA is not a production trust anchor. Do not install or use it on production systems. Each client creates and retains its own Ed25519 identity; the issuer receives only the CSR. The CA private key is generated per run and must remain local and be deleted after testing.

Production validation remains unchanged: certificate chain trust, validity period, Ed25519 public-key binding, and exactly one canonical `urn:lattice:identity:v1:<64 lowercase hex>` URI SAN matching the complete identity. Production CLI/Desktop trust remains native-system-only. Only explicitly pinned debug profiles can use this generated root. See [the security model](security/SECURITY_MODEL.md#cryptographic-layers).

## Prerequisites

- A clean checkout with the committed `Cargo.lock` and the repository's Rust toolchain (`rustc` 1.95 or newer).
- PowerShell for the command examples below.
- The relevant client identity/CSR API and a separate profile for every fixture identity.

The issuer is `lattice-dev-pki`, implemented in Rust with pinned `rcgen = 0.14.10`; OpenSSL is not required. Build and run from the repository root:

```powershell
$root = Join-Path $env:TEMP 'lattice-dev-pki-acceptance'
cargo run --locked -p lattice-dev-pki -- ca create --output-dir "$root/ca"
```

`ca create` requires a new output directory and writes:

- `lattice-development-only-ca.cert.pem`
- `lattice-development-only-ca.cert.der`
- `lattice-development-only-ca.key.pem` (private test material; never print or check in)

## Issue a client certificate

Every fixture client initializes its own identity using its ordinary client API, then exports only a CSR. It never exports its signing key. For the CLI fixture:

```powershell
cargo run --locked -p lattice-cli -- --data-dir "$root/cli/data" identity init
cargo run --locked -p lattice-cli -- --data-dir "$root/cli/data" identity csr --output "$root/cli/client.csr.pem"
cargo run --locked -p lattice-dev-pki -- issue `
  --ca-cert "$root/ca/lattice-development-only-ca.cert.pem" `
  --ca-key "$root/ca/lattice-development-only-ca.key.pem" `
  --csr "$root/cli/client.csr.pem" `
  --output-dir "$root/cli/issued" `
  --device-name cli
```

The issuer verifies the PKCS#10 signature, accepts only an Ed25519 public key and one canonical identity URI SAN, and issues a 90-day non-CA leaf with digital-signature usage only. It refuses unsupported or malformed CSR extensions, invalid CA/key pairs, invalid names, existing output directories, and vectors larger than 16 KiB. The leaf public key and identity SAN are retained. Issued files are `<name>.test-only.cert.pem`, `<name>.test-only.cert.der`, and `<name>.test-only.credential-vector.bin`; the last contains the leaf DER as an RFC 9420 TLS certificate vector. Keys and certificate times are intentionally random/per-run, so reproducibility means the same clean-checkout commands and output layout.

## Five-identity fixture matrix

Use the same CA for five independently generated identities, separate profiles, separate CSRs, and separately named issued artifacts:

| Device name | Client-created CSR/profile | Trust behavior | Acceptance status |
| --- | --- | --- | --- |
| `android-a` | Android profile A, Android identity API | Android's actual system-root loader | `BLOCKED-EXTERNAL` until tested on a disposable system image containing the test CA in the exact selected system CA directory |
| `android-b` | Android profile B, different identity and profile | Android's actual system-root loader | `BLOCKED-EXTERNAL` under the same system-image prerequisite |
| `desktop` | Isolated Tauri/Desktop profile | Exact-pinned debug profile described below | CSR generation and Rust issuance exercised; local Space acceptance remains unverified |
| `cli` | The command sequence above | Exact-pinned debug CLI profile described below | Accepted: matching profile created a local Space; wrong-key and untrusted-root inputs failed before creation |
| `web` | Fresh browser profile and Web identity API | Exact root DER/SHA-256 pinned when the profile is created | Accepted: Web-created CSR was issued by Rust tool; exact-pinned profile created a local Space |

Do not use a Core profile, test-only credential constructor, or reused identity as evidence of cross-client or physical-device acceptance. A local Space creation proves only that one profile accepted its own matching certificate.

## Pinned debug CLI profile

The CLI accepts a pinned root only in debug builds and only with an explicit absolute `--data-dir`; this keeps the trust policy bound to a dedicated profile. Compute and set the exact DER pin before invoking the CLI:

```powershell
$env:LATTICE_CLI_DEBUG_TRUST_ROOT_DER = (Resolve-Path "$root/ca/lattice-development-only-ca.cert.der").Path
$env:LATTICE_CLI_DEBUG_TRUST_ROOT_SHA256 = (Get-FileHash "$root/ca/lattice-development-only-ca.cert.der" -Algorithm SHA256).Hash.ToLowerInvariant()
cargo run --locked -p lattice-cli -- --data-dir "$root/cli/data" space create `
  --credential "$root/cli/issued/cli.test-only.credential-vector.bin" `
  --channel general
```

The expected success is one local Space for the matching `cli` profile. Wrong-key, altered-SAN, expired-leaf, and untrusted-root inputs must fail before a Space is created. Any partial, malformed, relative, mismatched, or non-isolated pin setting fails closed. Release builds reject either debug trust variable and remain native-system-only.

Desktop uses its existing isolated exact-pinned debug profile via `LATTICE_DESKTOP_PROFILE_DIR`, `LATTICE_DESKTOP_DEBUG_TRUST_ROOT_DER`, and `LATTICE_DESKTOP_DEBUG_TRUST_ROOT_SHA256`. Web pins the same root DER and SHA-256 during profile creation. Android does not use these pins: `lattice-mls` loads the system CA directory selected from Conscrypt APEX or `/system/etc/security/cacerts`; a disposable test system image must install the CA in that selected directory. Ordinary user-installed Android roots, APK network security configuration, and host trust changes do not alter this loader.

For a deliberate Windows native-root test only, `Set-DevelopmentCaTrust.ps1` may add/remove the CA in the current user's `ROOT` store. This is not required for CLI/Desktop pinned debug fixtures. Never install it on shared or production systems.

## Containment

Keep every profile, CSR, CA key/certificate, leaf, and vector under the temporary `$root`; none is a repository fixture. Check that no generated key, certificate, or vector is tracked. Remove the temporary tree and any native trust-store entry after acceptance. Do not infer cross-client, independent-implementation, or physical-device behavior from unit tests or a matching local Space.
