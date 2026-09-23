$ErrorActionPreference = 'Stop'
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$envFile = Join-Path $root '.demo\compose.env'
if (-not (Test-Path $envFile)) { Write-Host 'No demo environment exists.'; exit 0 }
& docker compose --project-name ai-native-rmm-demo --file (Join-Path $root 'compose.yaml') --env-file $envFile --profile tunnel down
if ($LASTEXITCODE) { exit $LASTEXITCODE }
Write-Host 'Demo stopped. Database and credentials were preserved.'
