$ErrorActionPreference = 'Stop'
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$demoDir = Join-Path $root '.demo'
$envFile = Join-Path $demoDir 'compose.env'
if (-not (Test-Path $envFile)) { throw 'No demo environment exists.' }
& docker compose --project-name ai-native-rmm-demo --file (Join-Path $root 'compose.yaml') --env-file $envFile --profile tunnel ps
if ($LASTEXITCODE) { exit $LASTEXITCODE }
$apiFile = Join-Path $demoDir 'api-url'
$deviceFile = Join-Path $demoDir 'device-id'
if (Test-Path $apiFile) { Write-Host "API URL: $(Get-Content -Raw $apiFile)" }
if (Test-Path $deviceFile) { Write-Host "Device ID: $(Get-Content -Raw $deviceFile)" }
