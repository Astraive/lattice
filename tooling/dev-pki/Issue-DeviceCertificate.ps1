[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $CaKey,
    [Parameter(Mandatory = $true)] [string] $CaCertificate,
    [Parameter(Mandatory = $true)] [string] $Csr,
    [Parameter(Mandatory = $true)] [string] $OutputDirectory,
    [Parameter(Mandatory = $true)] [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$')] [string] $DeviceName
)

$ErrorActionPreference = 'Stop'
$directory = [System.IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $directory) { throw "Output directory already exists: $directory" }
New-Item -ItemType Directory -Path $directory | Out-Null
$csrPath = [System.IO.Path]::GetFullPath($Csr)
$caKeyPath = [System.IO.Path]::GetFullPath($CaKey)
$caCertPath = [System.IO.Path]::GetFullPath($CaCertificate)
$leafPem = Join-Path $directory "$DeviceName.test-only.cert.pem"
$leafDer = Join-Path $directory "$DeviceName.test-only.cert.der"
$vector = Join-Path $directory "$DeviceName.test-only.credential-vector.bin"
$extensions = Join-Path $directory 'device-extensions.cnf'

# Copy the CSR's SAN (which is the identity fingerprint emitted by lattice identity csr),
# but constrain the issued key and purpose. The signing key never leaves the client.
@'
[device]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
'@ | Set-Content -LiteralPath $extensions -Encoding ascii
& openssl req -in $csrPath -noout -verify
if ($LASTEXITCODE -ne 0) { throw 'The device CSR signature is invalid.' }
& openssl x509 -req -in $csrPath -CA $caCertPath -CAkey $caKeyPath -CAcreateserial `
    -days 90 -sha256 -copy_extensions copy -extfile $extensions -extensions device -out $leafPem
if ($LASTEXITCODE -ne 0) { throw 'OpenSSL failed to issue the development device certificate.' }
& openssl x509 -in $leafPem -outform DER -out $leafDer
if ($LASTEXITCODE -ne 0) { throw 'OpenSSL failed to encode the issued certificate.' }

$derBytes = [System.IO.File]::ReadAllBytes($leafDer)
function Get-TlsVarIntBytes([ulong] $Value) {
    if ($Value -le 0x3f) {
        return [byte[]] @([byte] $Value)
    }
    if ($Value -le 0x3fff) {
        return [byte[]] @(
            [byte] (0x40 -bor (($Value -shr 8) -band 0x3f)),
            [byte] ($Value -band 0xff)
        )
    }
    if ($Value -le 0x3fffffff) {
        return [byte[]] @(
            [byte] (0x80 -bor (($Value -shr 24) -band 0x3f)),
            [byte] (($Value -shr 16) -band 0xff),
            [byte] (($Value -shr 8) -band 0xff),
            [byte] ($Value -band 0xff)
        )
    }
    if ($Value -gt 0x3fffffffffffffff) { throw 'TLS vector length exceeds the supported variable-length integer.' }
    $encoded = [System.BitConverter]::GetBytes($Value)
    [Array]::Reverse($encoded)
    $encoded[0] = [byte] (0xc0 -bor ($encoded[0] -band 0x3f))
    return $encoded
}
[byte[]] $certificateLengthPrefix = Get-TlsVarIntBytes ([ulong] $derBytes.Length)
$certificateVectorLength = $certificateLengthPrefix.Length + $derBytes.Length
[byte[]] $credentialLengthPrefix = Get-TlsVarIntBytes ([ulong] $certificateVectorLength)
$credentialVector = [System.Collections.Generic.List[byte]]::new()
$credentialVector.AddRange($credentialLengthPrefix)
$credentialVector.AddRange($certificateLengthPrefix)
$credentialVector.AddRange($derBytes)
$credentialVectorBytes = $credentialVector.ToArray()
if ($credentialVectorBytes.Length -gt 16 * 1024) { throw 'Credential vector exceeds the Lattice 16384-byte credential limit.' }
[System.IO.File]::WriteAllBytes($vector, $credentialVectorBytes)
Remove-Item -LiteralPath $extensions

Write-Output "Test-only device certificate: $leafPem"
Write-Output "RFC 9420 certificate vector: $vector"
Write-Output 'The certificate inherits the CSR identity SAN; verify it against the exact device profile.'
