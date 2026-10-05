[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $CaCertificate,
    [Parameter(Mandatory = $true)] [ValidateSet('Install', 'Remove')] [string] $Action
)

$ErrorActionPreference = 'Stop'
$certificate = [System.IO.Path]::GetFullPath($CaCertificate)
if (-not (Test-Path -LiteralPath $certificate -PathType Leaf)) { throw "Certificate not found: $certificate" }
if ($Action -eq 'Install') {
    & certutil.exe -user -addstore Root $certificate
} else {
    $x509 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certificate)
    $thumbprint = $x509.Thumbprint
    $x509.Dispose()
    & certutil.exe -user -delstore Root $thumbprint
}
if ($LASTEXITCODE -ne 0) { throw "Windows certificate store operation failed ($Action)." }
Write-Output "Windows Current User Root store updated ($Action). Remove this test-only CA after development."
