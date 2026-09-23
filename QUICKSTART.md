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

The default path is to copy the directory containing the MSI to Windows using
your normal file-transfer method, then run that installer's documented silent
installation command with the URL printed by `demo start`. The MSI/service build
and its local pairing-status command are owned by issue #6.

For an existing Azure Windows VM, a macOS helper can transfer exactly one MSI
without adding a public IP or SSH:

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
It transfers but does not install until issue #6's final MSI properties and local
status command are available.

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
