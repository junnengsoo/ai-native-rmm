[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Endpoint,
    [string]$MsiPath = 'C:\ProgramData\AI-Native-RMM\staging\SquashEndpointAgent.msi'
)

$ErrorActionPreference = 'Stop'
$uri = $null
$validUri = [Uri]::TryCreate($Endpoint, [UriKind]::Absolute, [ref]$uri)
$validTransport = $validUri -and (
    $uri.Scheme -eq 'wss' -or ($uri.Scheme -eq 'ws' -and $uri.IsLoopback)
)
if (-not $validTransport -or
    $uri.AbsolutePath -ne '/agent' -or
    $uri.UserInfo -or
    $uri.Query -or
    $uri.Fragment) {
    throw 'Endpoint must be wss://host/agent, or ws://loopback/agent for a same-machine demo.'
}
if (-not (Test-Path -LiteralPath $MsiPath -PathType Leaf)) {
    throw "MSI not found: $MsiPath"
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this installer from an elevated PowerShell console.'
}

$resolvedMsi = (Resolve-Path -LiteralPath $MsiPath).Path
$logPath = Join-Path $env:TEMP 'SquashEndpointAgent-install.log'
$arguments = @(
    '/i', ('"' + $resolvedMsi + '"'),
    '/qn', '/norestart',
    '/l*v', ('"' + $logPath + '"'),
    "RMM_ENDPOINT=$Endpoint"
)
$process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $arguments -Wait -PassThru
if ($process.ExitCode -notin @(0, 3010)) {
    throw "MSI installation failed with exit code $($process.ExitCode). Log: $logPath"
}

$deadline = (Get-Date).AddSeconds(60)
$service = $null
do {
    $service = Get-Service -Name 'SquashEndpointAgent' -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq 'Running') { break }
    Start-Sleep -Seconds 1
} while ((Get-Date) -lt $deadline)
if (-not $service -or $service.Status -ne 'Running') {
    throw "SquashEndpointAgent did not reach Running. Log: $logPath"
}

$statusPath = 'C:\ProgramData\Prosper\AiNativeRmm\status.json'
$status = $null
do {
    if (Test-Path -LiteralPath $statusPath -PathType Leaf) {
        try {
            $status = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json
            if ($status.pairing_code -or $status.device_id) { break }
        } catch {
            $status = $null
        }
    }
    Start-Sleep -Seconds 1
} while ((Get-Date) -lt $deadline)
if (-not $status -or (-not $status.pairing_code -and -not $status.device_id)) {
    throw "The service is running but did not report a pairing code or device ID. Check $statusPath and $logPath"
}

Write-Output 'AGENT_INSTALLED'
Write-Output "SERVICE_STATUS $($service.Status)"
Write-Output "ENROLLMENT_STATE $($status.state)"
if ($status.pairing_code) { Write-Output "PAIRING_CODE $($status.pairing_code)" }
if ($status.device_id) { Write-Output "DEVICE_ID $($status.device_id)" }
Write-Output "STATUS_PATH $statusPath"
Write-Output "INSTALL_LOG $logPath"
