"""Opt-in real MSI smoke for the Windows service installer slice."""
import base64
import io
import json
import os
import subprocess
import uuid
import zipfile
from pathlib import Path

import pytest


def windows(script: str, timeout: int = 600) -> dict:
    result = subprocess.run([
        "az", "vm", "run-command", "invoke", "-g", "rmm-trial-win11", "-n", "rmm-win11",
        "--command-id", "RunPowerShellScript", "--scripts", "$ErrorActionPreference='Stop'; " + script,
        "--query", "value[].message", "-o", "json",
    ], capture_output=True, text=True, check=True, timeout=timeout)
    output = "\n".join(json.loads(result.stdout))
    if "RMM_DATA:" not in output:
        reason = next((marker for marker in (
            "installer_missing", "install_failed", "service_missing", "unexpected_service_identity",
            "status_missing", "unexpected_status", "restart_failed", "uninstall_failed",
            "service_remaining", "files_remaining", "status_remaining", "local_credential_remaining",
            "missing_endpoint_accepted",
        ) if marker in output), "unclassified_fixture_failure")
        pytest.fail("Windows installer smoke failed: " + reason + " (raw output suppressed)")
    return json.loads(output.split("RMM_DATA:", 1)[1].splitlines()[0])


def bundle_source() -> str:
    archive = io.BytesIO()
    include_roots = [Path("src/EndpointAgent"), Path("installer"), Path("scripts")]
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        for root in include_roots:
            for path in root.rglob("*"):
                if path.is_file():
                    bundle.write(path, path.as_posix())
    return base64.b64encode(archive.getvalue()).decode()


@pytest.mark.skipif(
    not os.environ.get("RMM_WINDOWS_INSTALLER_WSS"),
    reason="requires authorized Windows VM, tunnel, and reduced installer smoke opt-in",
)
def test_real_msi_service_restart_and_uninstall_cleanup():
    endpoint = os.environ["RMM_WINDOWS_INSTALLER_WSS"]
    assert endpoint.startswith("wss://") and endpoint.endswith("/agent") and "'" not in endpoint

    key_name = "rmm-msi-" + uuid.uuid4().hex
    root = "C:\\Windows\\Temp\\" + key_name
    payload = bundle_source()
    service = "SquashEndpointAgent"
    status_path = "C:\\ProgramData\\Prosper\\AiNativeRmm\\status.json"
    install_folder = "C:\\Program Files\\Prosper Endpoint Agent"

    try:
        built = windows(f"""
$root='{root}'
New-Item -ItemType Directory $root -Force | Out-Null
icacls $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
[IO.File]::WriteAllBytes((Join-Path $root 'source.zip'),[Convert]::FromBase64String('{payload}'))
Expand-Archive (Join-Path $root 'source.zip') (Join-Path $root 'source') -Force
$env:PATH='C:\\rmm-test-runtime;' + $env:PATH
Push-Location (Join-Path $root 'source')
try {{
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\package-windows-agent.ps1 | Set-Content (Join-Path $root 'package.out')
  if ($LASTEXITCODE) {{ throw 'install_failed' }}
}} finally {{ Pop-Location }}
$msi=Get-ChildItem (Join-Path $root 'source\\artifacts\\windows-agent') -Filter '*.msi' | Select-Object -First 1
if (-not $msi) {{ throw 'installer_missing' }}
Write-Output ('RMM_DATA:' + (@{{msi=$msi.FullName}} | ConvertTo-Json -Compress))
""")

        rejected = windows(f"""
$msi='{built["msi"]}'
$args=@('/i',$msi,'/qn','/l*v','{root}\\missing-endpoint.log','RMM_KEY_NAME={key_name}')
$process=Start-Process msiexec.exe -ArgumentList $args -Wait -PassThru
if ($process.ExitCode -eq 0) {{ throw 'missing_endpoint_accepted' }}
if (Get-CimInstance Win32_Service -Filter "Name='{service}'") {{ throw 'missing_endpoint_accepted' }}
Write-Output ('RMM_DATA:' + (@{{exit_code=$process.ExitCode}} | ConvertTo-Json -Compress))
""")
        assert rejected["exit_code"] != 0

        installed = windows(f"""
$msi='{built["msi"]}'
$args=@('/i',$msi,'/qn','/l*v','{root}\\install.log','RMM_ENDPOINT={endpoint}','RMM_KEY_NAME={key_name}')
$process=Start-Process msiexec.exe -ArgumentList $args -Wait -PassThru
if ($process.ExitCode -ne 0) {{ throw 'install_failed' }}
$svc=Get-CimInstance Win32_Service -Filter "Name='{service}'"
if (-not $svc) {{ throw 'service_missing' }}
if ($svc.StartMode -ne 'Auto' -or $svc.StartName -ne 'LocalSystem' -or $svc.State -ne 'Running') {{ throw 'unexpected_service_identity' }}
$deadline=(Get-Date).AddSeconds(40)
do {{
  Start-Sleep -Seconds 1
  $exists=Test-Path '{status_path}'
  if ($exists) {{
    $status=Get-Content '{status_path}' -Raw | ConvertFrom-Json
    if ($status.state -eq 'pending' -and $status.ready -eq $false -and $status.pairing_code -match '^[A-Z2-7]{{12}}$') {{ break }}
  }}
}} until ((Get-Date) -gt $deadline)
if (-not (Test-Path '{status_path}')) {{ throw 'status_missing' }}
$status=Get-Content '{status_path}' -Raw | ConvertFrom-Json
if ($status.state -ne 'pending' -or $status.ready -ne $false -or $status.pairing_code -notmatch '^[A-Z2-7]{{12}}$') {{ throw 'unexpected_status' }}
$key=[Security.Cryptography.CngKey]::Open('{key_name}')
$unique=$key.UniqueName
$key.Dispose()
Write-Output ('RMM_DATA:' + (@{{state=$status.state;ready=$status.ready;pairing_code_length=$status.pairing_code.Length;start_mode=$svc.StartMode;identity=$svc.StartName;key_unique_name=$unique}} | ConvertTo-Json -Compress))
""")
        assert installed["state"] == "pending"
        assert installed["ready"] is False
        assert installed["pairing_code_length"] == 12
        assert installed["start_mode"] == "Auto"
        assert installed["identity"] == "LocalSystem"

        restarted = windows(f"""
Restart-Service -Name '{service}' -Force
$deadline=(Get-Date).AddSeconds(30)
do {{
  Start-Sleep -Seconds 1
  $svc=Get-CimInstance Win32_Service -Filter "Name='{service}'"
}} until ($svc.State -eq 'Running' -or (Get-Date) -gt $deadline)
if ($svc.State -ne 'Running') {{ throw 'restart_failed' }}
$deadline=(Get-Date).AddSeconds(40)
do {{
  Start-Sleep -Seconds 1
  $status=Get-Content '{status_path}' -Raw | ConvertFrom-Json
}} until ($status.state -in @('pending','unavailable') -or (Get-Date) -gt $deadline)
if ($status.ready -eq $true -or $status.state -notin @('pending','unavailable')) {{ throw 'unexpected_status' }}
Write-Output ('RMM_DATA:' + (@{{state=$status.state;ready=$status.ready;service=$svc.State}} | ConvertTo-Json -Compress))
""")
        assert restarted["service"] == "Running"
        assert restarted["ready"] is False
        assert restarted["state"] in {"pending", "unavailable"}

        removed = windows(f"""
$msi='{built["msi"]}'
$args=@('/x',$msi,'/qn','/l*v','{root}\\uninstall.log')
$process=Start-Process msiexec.exe -ArgumentList $args -Wait -PassThru
if ($process.ExitCode -ne 0) {{ throw 'uninstall_failed' }}
if (Get-CimInstance Win32_Service -Filter "Name='{service}'") {{ throw 'service_remaining' }}
if (Test-Path '{install_folder}') {{ throw 'files_remaining' }}
if (Test-Path '{status_path}') {{ throw 'status_remaining' }}
if ([Security.Cryptography.CngKey]::Exists('{key_name}')) {{ throw 'local_credential_remaining' }}
Write-Output ('RMM_DATA:' + (@{{removed=$true}} | ConvertTo-Json -Compress))
""")
        assert removed["removed"] is True
    finally:
        windows(f"""
$svc=Get-CimInstance Win32_Service -Filter "Name='{service}'" -ErrorAction SilentlyContinue
if ($svc) {{
  Stop-Service -Name '{service}' -Force -ErrorAction SilentlyContinue
  sc.exe delete '{service}' | Out-Null
}}
if ([Security.Cryptography.CngKey]::Exists('{key_name}')) {{
  $key=[Security.Cryptography.CngKey]::Open('{key_name}')
  $key.Delete()
  $key.Dispose()
}}
Remove-Item '{status_path}' -Force -ErrorAction SilentlyContinue
Remove-Item '{root}' -Recurse -Force -ErrorAction SilentlyContinue
Write-Output ('RMM_DATA:' + (@{{cleaned=$true}} | ConvertTo-Json -Compress))
""")
