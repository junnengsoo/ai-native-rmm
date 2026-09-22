# Windows service installer

This slice packages the endpoint agent as a candidate WiX MSI and installs it as
an automatic-start Windows service. It is still trial infrastructure, not a
customer deployment profile.

## Service identity and local state

The MSI installs one service:

- Service name: `ProsperEndpointAgent`
- Start mode: automatic
- Test execution identity: `LocalSystem`
- Command line: `EndpointAgent.exe --service`

`LocalSystem` is the documented test identity for this slice. The installer does
not offer restricted, current-user, or customer-selectable execution profiles.
Scripts submitted through the public API run with the same effective privilege
as the service-owned worker.

The installer writes machine configuration under
`HKLM\SOFTWARE\Prosper\AiNativeRmm`:

- `Endpoint`: the trusted `wss://.../agent` control-plane URL.
- `KeyName`: the CNG key name used by the service. The default is
  `ProsperEndpointAgent`.

The service writes local status to
`C:\ProgramData\Prosper\AiNativeRmm\status.json`. While enrollment is pending,
that file contains `state: "pending"`, `ready: false`, and the one-time
`pairing_code` when the server first issues it. Once the key is approved and the
service proves possession again, it contains `state: "online"`, `ready: true`,
and the stable `device_id`. Pending enrollment is not a ready managed device.

## Build the MSI on Windows

From a Windows checkout with the .NET SDK available:

```powershell
.\scripts\package-windows-agent.ps1
```

The script publishes a self-contained `win-x64` agent payload and builds
`ProsperEndpointAgent.msi` under `artifacts\windows-agent`. Build output is
ignored by Git; do not commit generated MSI files, logs, credentials, or local
status files.

## Silent install and uninstall

Install with an elevated console:

```powershell
msiexec /i .\artifacts\windows-agent\ProsperEndpointAgent.msi /qn /l*v install.log RMM_ENDPOINT=wss://YOUR-TUNNEL.trycloudflare.com/agent
```

Optional:

```powershell
RMM_KEY_NAME=ProsperEndpointAgentTest
```

Expected installation outcome:

- exit code `0`
- service exists and is running as `LocalSystem`
- startup type is automatic
- `status.json` appears with either `pending` plus a pairing code, or `online`
  after approval

Uninstall with:

```powershell
msiexec /x .\artifacts\windows-agent\ProsperEndpointAgent.msi /qn /l*v uninstall.log
```

Expected uninstall outcome:

- exit code `0`
- the service is removed
- the service-owned status file and CNG key are removed
- installed files are removed
- the uninstall path does not call server deletion APIs; server-history
  validation belongs to the later lifecycle smoke

## Manual smoke

Use the existing authorized Windows VM through Azure Run Command or an elevated
console. Do not add a public IP or use RDP as a test shortcut.

1. Start local Compose, create an admin key, and start a Cloudflare tunnel as in
   [enrollment.md](enrollment.md). This smoke uses the tunnel only far enough to
   initiate pending enrollment and expose the local pairing code.
2. Build the MSI with `scripts\package-windows-agent.ps1`.
3. Silently install the MSI with `RMM_ENDPOINT` set to the tunnel WSS URL.
4. Inspect `C:\ProgramData\Prosper\AiNativeRmm\status.json`; expect
   `state: "pending"`, `ready: false`, and a 12-character pairing code.
5. Inspect the installed service; expect automatic start and `LocalSystem`.
6. Restart the service through Service Control Manager and confirm it returns to
   `Running` without an interactive user session.
7. Silently uninstall the MSI. Confirm the service is gone, installed files are
   gone, `status.json` is gone, and the configured CNG key no longer exists.

Full pairing, public API execution, reboot recovery, and durable server-history
verification are covered by the later lifecycle ticket, not this installer slice.

## Automated smoke

The opt-in `tests/control_plane/test_windows_installer.py` path uses the actual
MSI package on the authorized Windows VM when `RMM_WINDOWS_INSTALLER_WSS` is set.
It builds the real WiX package, silently installs it, verifies the documented
service identity and pending local status surface, restarts through Service
Control Manager, silently uninstalls, and checks service/file/status/key cleanup.
