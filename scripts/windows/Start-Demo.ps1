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
$utf8NoBom = New-Object Text.UTF8Encoding($false)
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker Desktop with Docker Compose is required.'
}
& docker compose version *> $null
if ($LASTEXITCODE) { throw 'Docker Compose is not available.' }
New-Item -ItemType Directory -Path $demoDir -Force | Out-Null
if ($env:OS -eq 'Windows_NT') {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object Security.AccessControl.FileSystemAccessRule(
        $identity,
        [Security.AccessControl.FileSystemRights]::FullControl,
        ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow
    )
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $demoDir -AclObject $acl
}

if (-not (Test-Path -LiteralPath $envFile)) {
    $bytes = [byte[]]::new(36)
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $random.GetBytes($bytes) } finally { $random.Dispose() }
    $password = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    [IO.File]::WriteAllText($envFile, "RMM_POSTGRES_PASSWORD=$password`nRMM_HTTP_PORT=0", $utf8NoBom)
}

$compose = @('--project-name', 'ai-native-rmm-demo', '--file', (Join-Path $root 'compose.yaml'), '--env-file', $envFile)
& docker compose @compose up -d --build --wait --wait-timeout 60 database control-plane
if ($LASTEXITCODE) { throw 'The demo control plane did not become healthy.' }
$published = ((& docker compose @compose port control-plane 8000) -join '').Trim()
if ($LASTEXITCODE -or -not $published) { throw 'Could not determine the local control-plane port.' }
$localUrl = "http://$published"

$adminFile = Join-Path $demoDir 'admin-key'
$operatorFile = Join-Path $demoDir 'operator-key'
if (-not (Test-Path $adminFile) -or -not (Test-Path $operatorFile)) {
    $bootstrapText = (& docker compose @compose exec -T control-plane python -m control_plane.demo.setup) -join "`n"
    if ($LASTEXITCODE) { throw 'Demo credential bootstrap failed.' }
    $bootstrap = $bootstrapText | ConvertFrom-Json
    [IO.File]::WriteAllText($adminFile, [string]$bootstrap.admin_key, $utf8NoBom)
    [IO.File]::WriteAllText($operatorFile, [string]$bootstrap.operator_api_key, $utf8NoBom)
}

if ($PSCmdlet.ParameterSetName -eq 'Tunnel') {
    & docker compose @compose --profile tunnel up -d tunnel
    if ($LASTEXITCODE) { throw 'The development tunnel failed to start.' }
    $PublicUrl = $null
    foreach ($attempt in 1..30) {
        $logs = (& docker compose @compose --profile tunnel logs --no-color tunnel 2>$null) -join "`n"
        $match = [regex]::Matches($logs, 'https://[-a-z0-9]+\.trycloudflare\.com')
        if ($match.Count) {
            $PublicUrl = $match[$match.Count - 1].Value
            break
        }
        Start-Sleep -Seconds 1
    }
    if (-not $PublicUrl) { throw 'The development tunnel did not publish a URL. Inspect its Docker logs.' }
} elseif ($PSCmdlet.ParameterSetName -eq 'Local') {
    $PublicUrl = $localUrl
    & docker compose @compose --profile tunnel stop tunnel *> $null
} else {
    $PublicUrl = $PublicUrl.TrimEnd('/')
    & docker compose @compose --profile tunnel stop tunnel *> $null
}

[IO.File]::WriteAllText((Join-Path $demoDir 'api-url'), $PublicUrl, $utf8NoBom)
$deviceFile = Join-Path $demoDir 'device-id'
$deviceId = if (Test-Path $deviceFile) { Get-Content -Raw $deviceFile } else { $null }
$connection = [ordered]@{
    api_url = $PublicUrl
    operator_api_key = Get-Content -Raw $operatorFile
    device_id = $deviceId
}
[IO.File]::WriteAllText(
    (Join-Path $demoDir 'demo-connection.json'),
    ($connection | ConvertTo-Json),
    $utf8NoBom
)

Write-Host "`nAI-Native RMM demo is ready.`n"
Write-Host "Local API: $localUrl"
Write-Host "API URL:  $PublicUrl"
Write-Host "OpenAPI:  $PublicUrl/docs"
Write-Host "Caller configuration: $(Join-Path $demoDir 'demo-connection.json')"
if ($deviceId) {
    Write-Host "Device ID: $deviceId"
} else {
    Write-Host "`nInstall the bundled MSI on Windows with CONTROL_PLANE_URL=$PublicUrl"
    Write-Host 'Then run .\Demo.ps1 approve on this machine.'
}
