[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $OutputDirectory
)

$ErrorActionPreference = 'Stop'
$directory = [System.IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $directory) {
    throw "Output directory already exists: $directory"
}
New-Item -ItemType Directory -Path $directory | Out-Null
$caKey = Join-Path $directory 'lattice-development-only-ca.key.pem'
$caCertificate = Join-Path $directory 'lattice-development-only-ca.cert.pem'

& openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $caKey
if ($LASTEXITCODE -ne 0) { throw 'OpenSSL failed to create the development CA key.' }
& openssl req -x509 -new -sha256 -key $caKey -days 365 -out $caCertificate `
    -subj '/O=Lattice Development Only/CN=Lattice Local Test CA DO NOT TRUST IN PRODUCTION' `
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' `
    -addext 'keyUsage=critical,keyCertSign,cRLSign' `
    -addext 'subjectKeyIdentifier=hash'
if ($LASTEXITCODE -ne 0) { throw 'OpenSSL failed to create the development CA certificate.' }

Write-Output "Development-only CA certificate: $caCertificate"
Write-Output 'Keep the CA private key offline. Never use this CA for production identities.'
