[CmdletBinding(DefaultParameterSetName='Tunnel')]
param(
    [Parameter(ParameterSetName='Public', Mandatory=$true)]
    [ValidatePattern('^https://')]
    [string]$PublicUrl,
    [Parameter(ParameterSetName='Local')]
    [switch]$LocalOnly
)
$ErrorActionPreference = 'Stop'
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$demoDir = Join-Path $root '.demo'
$envFile = Join-Path $demoDir 'compose.env'
if (Test-Path $envFile) {
    & docker compose --project-name ai-native-rmm-demo --file (Join-Path $root 'compose.yaml') --env-file $envFile --profile tunnel down --volumes --remove-orphans
    if ($LASTEXITCODE) { exit $LASTEXITCODE }
}
if (Test-Path $demoDir) { Remove-Item -LiteralPath $demoDir -Recurse -Force }
Write-Host 'Removed only the ai-native-rmm-demo database and local demo credentials.'
$start = Join-Path $PSScriptRoot 'Start-Demo.ps1'
if ($PSCmdlet.ParameterSetName -eq 'Public') { & $start -PublicUrl $PublicUrl }
elseif ($PSCmdlet.ParameterSetName -eq 'Local') { & $start -LocalOnly }
else { & $start }
exit $LASTEXITCODE
