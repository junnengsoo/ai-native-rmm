$ErrorActionPreference = 'Stop'
$env:PATH = "C:\rmm-test-runtime;$env:PATH"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
dotnet build tests/ProtocolHarness -c Release --nologo
if ($LASTEXITCODE) { throw 'Harness build failed' }
$certs = @()
try {
    foreach ($name in @('localhost', 'rmm-test-endpoint', 'rmm-test-wrong')) {
        $certs += New-SelfSignedCertificate -DnsName $name -CertStoreLocation Cert:\CurrentUser\My -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddDays(1) -KeyAlgorithm RSA -KeyLength 2048
    }
    dotnet build src/EndpointAgent -c Release --nologo
    if ($LASTEXITCODE) { throw 'Agent build failed' }
    dotnet tests/ProtocolHarness/bin/Release/net8.0/ProtocolHarness.dll "$root/src/EndpointAgent/bin/Release/net8.0/EndpointAgent.dll" $certs[0].Thumbprint $certs[1].Thumbprint $certs[2].Thumbprint
    if ($LASTEXITCODE) { throw 'External behavior suite failed' }
    Write-Output 'RMM_SUITE_PASSED'
} finally {
    foreach ($cert in $certs) { Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)" -DeleteKey }
}
