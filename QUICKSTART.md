# Reviewer quick start

This is a disposable reviewer setup. A newly extracted ZIP begins with an empty
database and new credentials. `stop` preserves state; `reset` explicitly deletes
only the `ai-native-rmm-demo` Docker project state and creates a fresh demo.

## Prerequisites

- Docker Desktop, or Docker Engine with Compose, on the control-plane machine.
- An existing Windows machine with administrator access.
- The self-contained MSI produced by the Windows installer build.
- Outbound HTTPS/WSS connectivity from Windows to the selected control-plane URL.
- An OpenAI API key only when using the optional AI diagnostic console.

## 1. Start the control plane

On macOS or Linux:

```sh
./demo.sh start
```

On Windows:

```powershell
.\Demo.ps1 start
```

The default starts a temporary Cloudflare tunnel. To use an existing endpoint,
pass `--public-url https://rmm.example.com` on macOS/Linux or
`-PublicUrl https://rmm.example.com` on Windows. Use `--local-only`/`-LocalOnly`
only when the endpoint can reach the control plane locally.

The command starts PostgreSQL and the API, creates separate admin and operator
credentials, and writes the ignored local file `.demo/demo-connection.json`.
It prints the API and OpenAPI URLs. PostgreSQL is never published.

## 2. Transfer and install the Windows MSI

If you copy the extracted ZIP to Windows, open PowerShell as Administrator from
the ZIP's root directory and use the included wrapper with the `RMM_ENDPOINT`
printed by `demo start`:

```powershell
.\scripts\windows\Install-Agent.ps1 `
  -MsiPath 'C:\path\to\SquashEndpointAgent.msi' `
  -Endpoint 'wss://YOUR-TUNNEL.trycloudflare.com/agent'
```

The wrapper installs silently, waits for the automatic `SquashEndpointAgent`
service and local status file, then prints the pairing code. Its MSI log is
written to `%TEMP%\SquashEndpointAgent-install.log`.

If you transfer only the MSI, no script is required on Windows. Run the
underlying command directly from an elevated PowerShell console:

```powershell
msiexec.exe /i 'C:\path\to\SquashEndpointAgent.msi' /qn /norestart `
  /l*v "$env:TEMP\SquashEndpointAgent-install.log" `
  RMM_ENDPOINT='wss://YOUR-TUNNEL.trycloudflare.com/agent'
```

For an existing Azure Windows VM, a macOS helper can transfer exactly one MSI
without adding a public IP or SSH. The VM still needs outbound HTTPS egress,
normally through an Azure NAT Gateway or an existing managed egress path. That
egress is also required for the installed agent to reach the control-plane WSS
URL.

```sh
./scripts/mac/transfer-msi-to-azure.sh \
  --resource-group YOUR_RESOURCE_GROUP \
  --vm YOUR_VM_NAME \
  --local-directory /absolute/path/to/windows-endpoint
```

If the directory contains multiple MSI files, add `--msi FILE_NAME`. The helper
creates private temporary Azure Blob storage, invokes a hash-verifying download
through Azure Run Command, places the MSI under
`C:\ProgramData\AI-Native-RMM\staging`, and deletes the temporary Storage account.
After transfer, install it from macOS without RDP or a public IP:

```sh
./scripts/mac/install-msi-on-azure.sh \
  --resource-group YOUR_RESOURCE_GROUP \
  --vm YOUR_VM_NAME \
  --endpoint wss://YOUR-TUNNEL.trycloudflare.com/agent \
  --msi SquashEndpointAgent.msi
```

The Azure command runs the same Windows wrapper through Azure Run Command and
prints the pairing code. It embeds the wrapper from the macOS checkout, so you
do not need to copy any scripts to Windows. It expects only the MSI under the
staging directory created by the transfer command.

## 3. Approve the endpoint

After the installed Windows service displays its pairing code, return to the
control-plane machine:

```sh
./demo.sh approve
```

or:

```powershell
.\Demo.ps1 approve
```

The command prompts for the code without echoing it, approves the endpoint,
waits for online evidence, and adds `device_id` to
`.demo/demo-connection.json`.

## 4. Use a caller

Any caller adapter can read these three fields from `.demo/demo-connection.json`:

```json
{
  "api_url": "https://example.trycloudflare.com",
  "operator_api_key": "rmm_...",
  "device_id": "..."
}
```

The operator key is sent as `Authorization: Bearer …`. The authenticated OpenAPI
page is available at the printed `/docs` URL.

For the optional interactive AI driver:

```sh
./demo.sh ai
```

or:

```powershell
.\Demo.ps1 ai
```

If `OPENAI_API_KEY` is not already set, the launcher prompts without echoing and
does not save it. Each question opens and closes a fresh endpoint session. The
console prints timestamped model boundaries, tool arguments, bounded tool
results, timings, and usage while escaping terminal-control characters.

## Lifecycle

```text
demo status  Inspect without changing state
demo stop    Stop containers and tunnel; preserve data and credentials
demo start   Resume preserved data and credentials
demo reset   Delete only this demo's state and create new credentials
```
