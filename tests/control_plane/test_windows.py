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

BASE = os.environ.get("RMM_API_URL", "http://127.0.0.1:18080")


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
    credential = os.environ.get("RMM_ADMIN_KEY")
    assert credential, "Set RMM_ADMIN_KEY to the workspace admin credential from local setup"
    admin = {"Authorization": "Bearer " + credential}
    assert httpx.get(BASE + "/devices", headers=admin).status_code == 200, "Check RMM_API_URL and RMM_ADMIN_KEY"
    caller = httpx.post(BASE + "/callers", headers=admin, json={
        "name": "windows-smoke-" + uuid.uuid4().hex, "role": "operator",
    })
    caller.raise_for_status()
    operator = {"Authorization": "Bearer " + caller.json()["api_key"]}
    key_name = "rmm-test-" + uuid.uuid4().hex
    root = "C:\\Windows\\Temp\\" + key_name
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        for path in Path("src/EndpointAgent").glob("*"):
            if path.is_file():
                bundle.write(path, str(path))
    payload = base64.b64encode(archive.getvalue()).decode()
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

        def enrolled_device():
            # The existing workspace can contain prior smoke devices. Locate this
            # run's UUID, following the public pagination contract when necessary.
            params = {}
            while True:
                listing = httpx.get(BASE + "/devices", headers=admin, params=params)
                listing.raise_for_status()
                page = listing.json()
                for row in page["devices"]:
                    if row["id"] == device:
                        return row
                assert page["next_cursor"], "Approved device missing from its workspace"
                params = {"after": page["next_cursor"]}

        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            row = enrolled_device()
            if row["reachability"] == "online":
                break
            time.sleep(1)
        assert row["reachability"] == "online"
        first_seen = row["last_seen"]

        opened = httpx.post(BASE + "/sessions", headers=operator, json={"device_id": device}, timeout=30)
        opened.raise_for_status()
        session = opened.json()["session_id"]

        def execute(script, idempotency_key, timeout_ms=5000, wait_seconds=20):
            submitted = httpx.post(BASE + f"/sessions/{session}/executions", headers={
                **operator, "Idempotency-Key": idempotency_key,
            }, json={"script": script, "timeout_ms": timeout_ms})
            submitted.raise_for_status()
            execution = submitted.json()["execution_id"]
            deadline = time.monotonic() + wait_seconds
            while time.monotonic() < deadline:
                result = httpx.get(
                    BASE + f"/executions/{execution}/wait",
                    headers=operator, params={"timeout_seconds": 1}, timeout=3,
                )
                result.raise_for_status()
                if result.json()["terminal"]:
                    return submitted, result.json()
            pytest.fail("Windows execution did not finish")

        _, set_result = execute("$global:trialValue = 41", "set-variable")
        assert set_result["status"] == "completed"
        _, read_result = execute("$global:trialValue + 1", "read-variable")
        assert read_result["output_preview"]["stdout"]["text"].strip() == "42"
        marker = root + "\\marker.txt"
        marker_script = f"Add-Content -LiteralPath '{marker}' -Value marker; (Get-Content -LiteralPath '{marker}').Count"
        first_submit, marker_result = execute(marker_script, "marker-once")
        retry = httpx.post(BASE + f"/sessions/{session}/executions", headers={
            **operator, "Idempotency-Key": "marker-once",
        }, json={"script": marker_script, "timeout_ms": 5000})
        assert retry.status_code == 202 and retry.json()["execution_id"] == first_submit.json()["execution_id"]
        assert marker_result["output_preview"]["stdout"]["text"].strip() == "1"
        child_script = "$p=Start-Process -FilePath $env:ComSpec -ArgumentList '/c ping -n 60 127.0.0.1 > nul' -PassThru; $p.Id; Start-Sleep -Seconds 20"
        _, timeout_result = execute(child_script, "timeout-child", timeout_ms=500, wait_seconds=30)
        assert timeout_result["status"] == "timed_out"
        assert timeout_result["invocation_outcome"] == "stopped"
        child_id = int(timeout_result["output_preview"]["stdout"]["text"].strip().splitlines()[0])
        closed = httpx.post(BASE + f"/sessions/{session}/close", headers=operator, timeout=30)
        assert closed.status_code == 200 and closed.json()["status"] == "closed"
        fresh = httpx.post(BASE + "/sessions", headers=operator, json={"device_id": device}, timeout=30)
        fresh.raise_for_status()
        session = fresh.json()["session_id"]
        _, child_cleanup = execute(f"$null -eq (Get-Process -Id {child_id} -ErrorAction SilentlyContinue)", "timeout-child-cleanup")
        assert child_cleanup["output_preview"]["stdout"]["text"].strip().lower() == "true"
        _, fresh_result = execute("$null -eq $global:trialValue", "fresh-variable")
        assert fresh_result["output_preview"]["stdout"]["text"].strip().lower() == "true"
        assert httpx.post(BASE + f"/sessions/{session}/close", headers=operator, timeout=30).status_code == 200

        time.sleep(17)
        row = enrolled_device()
        assert row["last_seen"] > first_seen
        offline_session = httpx.post(BASE + "/sessions", headers=operator, json={"device_id": device}, timeout=30)
        assert offline_session.status_code == 201
        session = offline_session.json()["session_id"]
        windows(f"""
$agentId=Get-Content '{root}\\pid.txt'
$process=Get-CimInstance Win32_Process -Filter "ProcessId=$agentId"
if ($process.CommandLine -notlike '*{key_name}*') {{ throw 'unexpected_process' }}
Stop-Process -Id $agentId
Write-Output 'RMM_DATA:stopped'
""")
        offline_submit = httpx.post(BASE + f"/sessions/{session}/executions", headers={
            **operator, "Idempotency-Key": "offline-terminal",
        }, json={"script": "'must-not-run'", "timeout_ms": 5000})
        offline_submit.raise_for_status()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            offline_result = httpx.get(
                BASE + f"/executions/{offline_submit.json()['execution_id']}/wait",
                headers=operator, params={"timeout_seconds": 1}, timeout=3,
            )
            offline_result.raise_for_status()
            if offline_result.json()["terminal"]:
                break
        assert offline_result.json()["status"] == "failed_to_start"
        assert offline_result.json()["outcome_reason"] == "device_offline_before_dispatch"
        time.sleep(46)
        assert enrolled_device()["reachability"] == "stale"
        start()
        row = enrolled_device()
        assert row["id"] == device and row["reachability"] == "online"

        revoked = httpx.post(BASE + f"/devices/{device}/revoke", headers=admin, timeout=35)
        revoked.raise_for_status()
        assert revoked.json()["authorization_status"] == "revoked"
        assert enrolled_device()["authorization_status"] == "revoked"
        assert httpx.post(BASE + "/sessions", headers=operator,
                          json={"device_id": device}).json() == {"detail": "device_revoked"}
        time.sleep(17)
        windows(f"""
$agentId=Get-Content '{root}\\pid.txt'
$process=Get-Process -Id $agentId -ErrorAction SilentlyContinue
if ($null -ne $process) {{ throw 'revoked_agent_still_running' }}
$codes=([regex]::Matches((Get-Content '{root}\\out.txt' -Raw),'PAIRING_CODE ')).Count
if ($codes -ne 1) {{ throw 'revoked_key_reentered_pairing' }}
Write-Output 'RMM_DATA:revoked'
""")
        print("Windows: paired → execution → restart identity → durable revocation denial")
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
