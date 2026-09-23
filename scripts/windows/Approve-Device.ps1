$ErrorActionPreference = 'Stop'
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$demoDir = Join-Path $root '.demo'
$envFile = Join-Path $demoDir 'compose.env'
$adminFile = Join-Path $demoDir 'admin-key'
$operatorFile = Join-Path $demoDir 'operator-key'
$apiFile = Join-Path $demoDir 'api-url'
$utf8NoBom = New-Object Text.UTF8Encoding($false)
foreach ($required in @($envFile, $adminFile, $operatorFile, $apiFile)) {
    if (-not (Test-Path $required)) { throw 'Start the demo before approving an endpoint.' }
}
$secureCode = Read-Host 'Pairing code shown on Windows' -AsSecureString
$pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureCode)
try {
    $pairingCode = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
}
$env:RMM_ADMIN_KEY = Get-Content -Raw $adminFile
$compose = @('--project-name', 'ai-native-rmm-demo', '--file', (Join-Path $root 'compose.yaml'), '--env-file', $envFile)
try {
    $responseText = ($pairingCode | & docker compose @compose exec -T --env RMM_ADMIN_KEY --env RMM_API_URL=http://127.0.0.1:8000 control-plane python -m control_plane.demo.approve) -join "`n"
    if ($LASTEXITCODE) { throw 'Endpoint approval failed.' }
} finally {
    Remove-Item Env:RMM_ADMIN_KEY -ErrorAction SilentlyContinue
    $pairingCode = $null
}
$response = $responseText | ConvertFrom-Json
[IO.File]::WriteAllText((Join-Path $demoDir 'device-id'), [string]$response.device_id, $utf8NoBom)
$connection = [ordered]@{
    api_url = Get-Content -Raw $apiFile
    operator_api_key = Get-Content -Raw $operatorFile
    device_id = $response.device_id
}
[IO.File]::WriteAllText(
    (Join-Path $demoDir 'demo-connection.json'),
    ($connection | ConvertTo-Json),
    $utf8NoBom
)
Write-Host "Endpoint $($response.device_id) is $($response.reachability)."
Write-Host "Caller configuration: $(Join-Path $demoDir 'demo-connection.json')"
