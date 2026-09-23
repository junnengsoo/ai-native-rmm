param(
    [Parameter(Mandatory=$true)][string]$downloadUrl,
    [Parameter(Mandatory=$true)][string]$expectedHash,
    [Parameter(Mandatory=$true)][string]$fileName,
    [Parameter(Mandatory=$true)][string]$destinationDirectory
)

$ErrorActionPreference = 'Stop'
if ($fileName -notmatch '^[A-Za-z0-9._-]+\.msi$') {
    throw 'invalid_msi_filename'
}
if ($expectedHash -notmatch '^[A-Fa-f0-9]{64}$') {
    throw 'invalid_expected_hash'
}

New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
$destination = Join-Path $destinationDirectory $fileName
$temporary = "$destination.partial-$([Guid]::NewGuid().ToString('N'))"
try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $temporary -UseBasicParsing
    $actualHash = (Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash
    if ($actualHash -ne $expectedHash) {
        throw 'msi_hash_mismatch'
    }
    Move-Item -LiteralPath $temporary -Destination $destination -Force
} finally {
    if (Test-Path -LiteralPath $temporary) {
        Remove-Item -LiteralPath $temporary -Force
    }
}

Write-Output "MSI_TRANSFERRED $destination"
Write-Output "MSI_SHA256 $expectedHash"
