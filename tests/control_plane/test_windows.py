"""Opt-in Windows→tunnel→Mac integration. Azure only launches the real endpoint."""
import base64
import io
import json
import os
import subprocess
import time
import uuid
import zipfile
from pathlib import Path

import httpx
import pytest

from test_pairing import BASE, local_admin


def windows(script):
    result = subprocess.run([
        "az", "vm", "run-command", "invoke", "-g", "rmm-trial-win11", "-n", "rmm-win11",
        "--command-id", "RunPowerShellScript", "--scripts", "$ErrorActionPreference='Stop'; " + script,
        "--query", "value[].message", "-o", "json",
    ], capture_output=True, text=True, check=True, timeout=240)
    output = "\n".join(json.loads(result.stdout))
    if "RMM_DATA:" not in output:
        reasons = ("unexpected_agent_identity", "key_acl_too_broad", "Cannot find path", "build_failed", "unexpected_process")
        reason = next((reason for reason in reasons if reason in output), "unclassified_fixture_failure")
        pytest.fail("Windows step failed: " + reason + " (raw output suppressed to protect pairing material)")
    return output.split("RMM_DATA:", 1)[1].splitlines()[0]


@pytest.mark.skipif(not os.environ.get("RMM_WINDOWS_WSS"), reason="requires authorized Windows VM and tunnel")
def test_real_windows_pairing_heartbeat_stop_and_stable_identity():
    endpoint = os.environ["RMM_WINDOWS_WSS"]
    assert endpoint.startswith("wss://") and "'" not in endpoint
    key_name = "rmm-test-" + uuid.uuid4().hex
    root = "C:\\Windows\\Temp\\" + key_name
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        for path in Path("src/EndpointAgent").glob("*"):
            if path.is_file():
                bundle.write(path, str(path))
    payload = base64.b64encode(archive.getvalue()).decode()
    admin = local_admin()
    try:
        windows(f"""New-Item -ItemType Directory '{root}' | Out-Null
icacls '{root}' /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
[IO.File]::WriteAllBytes('{root}\\source.zip',[Convert]::FromBase64String('{payload}'))
Expand-Archive '{root}\\source.zip' '{root}\\source'
& C:\\rmm-test-runtime\\dotnet.exe build '{root}\\source\\src\\EndpointAgent' -c Release --nologo | Out-Null
if ($LASTEXITCODE) {{ throw 'build_failed' }}
Write-Output 'RMM_DATA:built'
""")
        def start():
            return windows(f"""
$launcher=@'
$p=Start-Process C:\\rmm-test-runtime\\dotnet.exe -ArgumentList @('{root}\\source\\src\\EndpointAgent\\bin\\Release\\net8.0\\EndpointAgent.dll','--enroll','{endpoint}','{key_name}') -PassThru -RedirectStandardOutput '{root}\\out.txt' -RedirectStandardError '{root}\\err.txt'
$p.Id | Set-Content '{root}\\pid.txt'
$p.WaitForExit()
'@
$launcher | Set-Content '{root}\\launch.ps1'
$action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -NonInteractive -File {root}\\launch.ps1'
$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
Register-ScheduledTask -TaskName '{key_name}' -Action $action -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName '{key_name}'
Start-Sleep 10
$agentId=Get-Content '{root}\\pid.txt'
$process=Get-CimInstance Win32_Process -Filter "ProcessId=$agentId"
$owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
if ($owner.Sid -ne 'S-1-5-18') {{ throw 'unexpected_agent_identity' }}
$key=[Security.Cryptography.CngKey]::Open('{key_name}')
# SYSTEM has a distinct CNG key directory from ordinary user accounts.
$keyPath=Join-Path $env:ProgramData ('Microsoft\\Crypto\\SystemKeys\\' + $key.UniqueName)
$untrusted=@('S-1-1-0','S-1-5-11','S-1-5-32-545')
foreach ($entry in (Get-Acl $keyPath).Access) {{
    $sid=$entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    if ($entry.AccessControlType -eq 'Allow' -and $sid -in $untrusted) {{ throw 'key_acl_too_broad' }}
}}
$key.Dispose()
Write-Output ('RMM_DATA:' + (Get-Content '{root}\\out.txt' -Raw))
""")
        observed = start()
        assert observed.startswith("PAIRING_CODE "), "Windows must display a one-time pairing code"
        code = observed.split()[1]
        response = httpx.post(BASE + "/pairings/approve", headers=admin, json={"code": code})
        assert response.status_code == 200
        device = response.json()["device_id"]
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            row = httpx.get(BASE + "/devices", headers=admin).json()["devices"][0]
            if row["reachability"] == "online":
                break
            time.sleep(1)
        assert row["reachability"] == "online"
        first_seen = row["last_seen"]
        time.sleep(17)
        row = httpx.get(BASE + "/devices", headers=admin).json()["devices"][0]
        assert row["last_seen"] > first_seen
        windows(f"""
$agentId=Get-Content '{root}\\pid.txt'
$process=Get-CimInstance Win32_Process -Filter "ProcessId=$agentId"
if ($process.CommandLine -notlike '*{key_name}*') {{ throw 'unexpected_process' }}
Stop-Process -Id $agentId
Write-Output 'RMM_DATA:stopped'
""")
        time.sleep(46)
        assert httpx.get(BASE + "/devices", headers=admin).json()["devices"][0]["reachability"] == "stale"
        start()
        row = httpx.get(BASE + "/devices", headers=admin).json()["devices"][0]
        assert row["id"] == device and row["reachability"] == "online"
        print("Windows: observed code → approved → online → heartbeat → stopped/stale → same device on restart")
    finally:
        windows(f"""
if (Test-Path '{root}\\pid.txt') {{
    $agentId=Get-Content '{root}\\pid.txt'
    $process=Get-CimInstance Win32_Process -Filter "ProcessId=$agentId" -ErrorAction SilentlyContinue
    if ($process.CommandLine -like '*{key_name}*') {{ Stop-Process -Id $agentId -ErrorAction SilentlyContinue }}
}}
Unregister-ScheduledTask -TaskName '{key_name}' -Confirm:$false -ErrorAction SilentlyContinue
if ([Security.Cryptography.CngKey]::Exists('{key_name}')) {{ $key=[Security.Cryptography.CngKey]::Open('{key_name}'); $key.Delete(); $key.Dispose() }}
Remove-Item '{root}\\out.txt','{root}\\err.txt' -ErrorAction SilentlyContinue
Write-Output 'RMM_DATA:cleaned'
""")
