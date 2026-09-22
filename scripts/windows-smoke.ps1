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
    $worker = Join-Path $root 'src\EndpointAgent\bin\Release\net8.0\NativePowerShellWorker.ps1'
    if (-not (Test-Path $worker)) { throw 'Native PowerShell worker was not copied to build output' }
    $tokens = $null
    $parseErrors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($worker, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count) { throw ('Native PowerShell worker parse failed: ' + ($parseErrors.Message -join '; ')) }
    $probeName = 'rmm-' + [Guid]::NewGuid().ToString('N')
    $probePipe = New-Object IO.Pipes.NamedPipeServerStream(
        $probeName, [IO.Pipes.PipeDirection]::InOut, 1,
        [IO.Pipes.PipeTransmissionMode]::Byte,
        ([IO.Pipes.PipeOptions]::Asynchronous -bor [IO.Pipes.PipeOptions]::CurrentUserOnly)
    )
    $nativePowerShell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    $probeArguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$worker`" -PipeName $probeName"
    $probeStart = New-Object Diagnostics.ProcessStartInfo
    $probeStart.FileName = $nativePowerShell
    $probeStart.Arguments = $probeArguments
    $probeStart.UseShellExecute = $false
    $probeStart.CreateNoWindow = $true
    $probeStart.RedirectStandardError = $true
    $probeStart.RedirectStandardOutput = $true
    $allowedEnvironment = @('SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'PATH', 'PATHEXT', 'ComSpec', 'SystemDrive',
        'ProgramFiles', 'ProgramFiles(x86)', 'ProgramData', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH', 'APPDATA',
        'LOCALAPPDATA', 'PSModulePath')
    $savedEnvironment = @{}
    foreach ($key in $allowedEnvironment) { $savedEnvironment[$key] = [Environment]::GetEnvironmentVariable($key) }
    $probeStart.EnvironmentVariables.Clear()
    foreach ($key in $allowedEnvironment) {
        if ($null -ne $savedEnvironment[$key]) { $probeStart.EnvironmentVariables[$key] = $savedEnvironment[$key] }
    }
    $probeProcess = [Diagnostics.Process]::Start($probeStart)
    $probeReader = $null
    try {
        $connected = $probePipe.WaitForConnectionAsync()
        if (-not $connected.Wait(60000)) {
            if (-not $probeProcess.HasExited) { $probeProcess.Kill() }
            $diagnostic = $probeProcess.StandardError.ReadToEnd()
            throw "Native PowerShell worker did not connect: $diagnostic"
        }
        $probeReader = New-Object IO.StreamReader($probePipe, (New-Object Text.UTF8Encoding($false)), $false, 4096, $true)
        $readyPending = $probeReader.ReadLineAsync()
        if (-not $readyPending.Wait(60000)) { throw 'Native PowerShell worker connected but did not become ready' }
        $ready = $readyPending.Result
        if ($ready -notlike '{"kind":"ready"*') { throw "Native PowerShell worker was not ready: $ready" }
    } finally {
        if (-not $probeProcess.HasExited) { $probeProcess.Kill() }
        $probeProcess.WaitForExit()
        if ($null -ne $probeReader) { $probeReader.Dispose() }
        $probePipe.Dispose()
        $probeProcess.Dispose()
    }
    dotnet tests/ProtocolHarness/bin/Release/net8.0/ProtocolHarness.dll "$root/src/EndpointAgent/bin/Release/net8.0/EndpointAgent.dll" $certs[0].Thumbprint $certs[1].Thumbprint $certs[2].Thumbprint
    if ($LASTEXITCODE) { throw 'External behavior suite failed' }
} finally {
    foreach ($cert in $certs) { Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)" -DeleteKey }
}
Write-Output 'RMM_SUITE_PASSED'
