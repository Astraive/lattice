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
    $thumbprint = (& openssl x509 -in $certificate -noout -fingerprint -sha1)
    if ($LASTEXITCODE -ne 0) { throw 'Could not read CA certificate fingerprint.' }
    $thumbprint = ($thumbprint -replace '^.*=', '') -replace ':', ''
    & certutil.exe -user -delstore Root $thumbprint
}
if ($LASTEXITCODE -ne 0) { throw "Windows certificate store operation failed ($Action)." }
Write-Output "Windows Current User Root store updated ($Action). Remove this test-only CA after development."
