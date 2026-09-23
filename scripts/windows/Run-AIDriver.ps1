[CmdletBinding()]
param(
    [string]$Once,
    [string]$ConfigPath,
    [string]$Model,
    [int]$MaxSteps,
    [int]$MaxSeconds,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$envFile = Join-Path $root '.demo\compose.env'
if (-not $ConfigPath) {
    $ConfigPath = Join-Path $root '.demo\demo-connection.json'
}
$ConfigPath = [IO.Path]::GetFullPath($ConfigPath)
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw "Caller configuration not found: $ConfigPath. Complete demo setup and endpoint approval first."
}
if (-not (Test-Path -LiteralPath $envFile -PathType Leaf)) {
    throw 'Demo Compose configuration not found. Run .\Demo.ps1 start first.'
}
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker Desktop with Docker Compose is required on the control-plane machine.'
}
& docker compose version *> $null
if ($LASTEXITCODE) {
    throw 'Docker Compose is not available.'
}

$temporaryKey = $false
if (-not $env:OPENAI_API_KEY) {
    $secureKey = Read-Host 'OpenAI API key (not saved)' -AsSecureString
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
    try {
        $env:OPENAI_API_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
        $temporaryKey = $true
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

$driverArgs = @(
    '--config', '/app/demo-connection.json',
    '--base-url', 'http://control-plane:8000'
)
if ($Once) { $driverArgs += $Once } else { $driverArgs += '--interactive' }
if ($Model) { $driverArgs += @('--model', $Model) }
if ($PSBoundParameters.ContainsKey('MaxSteps')) { $driverArgs += @('--max-steps', [string]$MaxSteps) }
if ($PSBoundParameters.ContainsKey('MaxSeconds')) { $driverArgs += @('--max-seconds', [string]$MaxSeconds) }
if ($Quiet) { $driverArgs += '--quiet' }

try {
    $mount = "${ConfigPath}:/app/demo-connection.json:ro"
    & docker compose `
        --project-name ai-native-rmm-demo `
        --file (Join-Path $root 'compose.yaml') `
        --env-file $envFile `
        run --rm --no-deps `
        --volume $mount `
        --env OPENAI_API_KEY `
        control-plane `
        python -m control_plane.openai_driver @driverArgs
    exit $LASTEXITCODE
} finally {
    if ($temporaryKey) {
        Remove-Item Env:OPENAI_API_KEY -ErrorAction SilentlyContinue
    }
}
