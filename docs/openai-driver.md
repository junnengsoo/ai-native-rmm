# OpenAI diagnostic driver

The OpenAI driver is a prototype caller, not endpoint intelligence. It uses the
OpenAI Responses API from the caller process to choose among constrained
read-only diagnostic operations, then maps those operations locally to fixed
PowerShell templates submitted through the public control-plane session/execution
APIs. The model never receives a raw PowerShell execution tool. The endpoint
receives only the selected fixed diagnostic script and normal session metadata.
OpenAI keys, admin keys, operator keys, and control-plane HTTP access are never
exposed to the endpoint or included in model tool results.

The default model is `gpt-5-nano`, selected as the lowest-cost currently listed
OpenAI text model for this smoke path. The driver uses a small default budget:
five tool steps, three minutes wall-clock shared by preflight and diagnosis,
600 output tokens per model call, and 20-second execution timeouts capped to the
remaining wall-clock budget. Session closure uses one bounded close request with
a separate 35-second cleanup allowance. The server-side close grace is 30
seconds, so caller cleanup settings must be 31-60 seconds to leave transport
slack while keeping the non-idempotent close operation bounded. An unconfirmed
close is surfaced as command failure. These are
deliberately conservative prototype defaults, not the unapproved
15-command/15-minute budget.

## Local deterministic tests

The tests mock the OpenAI boundary and use fake or mocked control-plane calls:

```sh
.venv/bin/python -m pytest -q tests/control_plane/test_openai_driver.py
```

They cover adaptive tool sequencing, rejection of arbitrary or mutating tool
requests, bounded output pages without skipped middle output, per-investigation
execution/cursor restrictions, session closure on budget exhaustion, cleanup
failure reporting, local argument validation, separate progress reporting,
separate timing records, paginated device discovery, OpenAI request shape, token
usage collection, and the fact that control-plane calls authenticate with the
operator credential rather than the OpenAI key.

On 2026-09-21, all five fixed PowerShell templates were also executed directly
on the authorized Windows 11 Azure VM under Azure Run Command: network
configuration, default-gateway reachability, DNS resolution, target ping, and
TCP-port testing all parsed and completed successfully. The VM was deallocated
immediately afterward. This verifies the real Windows command surface, but it is
not a substitute for the end-to-end OpenAI, control-plane, tunnel, and endpoint
smoke below.

The same revision passed all 28 focused driver tests. A fresh Python 3.13
control-plane container backed by an isolated PostgreSQL 16 volume also passed
the broader non-Windows control-plane suite: 52 passed and one opt-in test was
skipped. The isolated Compose project and its disposable database volume were
removed after the run.

## Manual Windows/OpenAI smoke

Complete the local Compose, tunnel, Windows enrollment, and admin setup in
[enrollment.md](enrollment.md), keeping these variables in the shell that runs
the driver:

```sh
export RMM_API_URL=http://127.0.0.1:18080
export RMM_ADMIN_KEY=ADMIN_KEY_PLACEHOLDER
export OPENAI_API_KEY=OPENAI_KEY_PLACEHOLDER
```

The driver can create its own one-use operator caller with the admin key. If an
operator key already exists, set `RMM_OPERATOR_KEY=OPERATOR_KEY_PLACEHOLDER`
instead. When using only an operator key, also set `RMM_DEVICE_ID=DEVICE_UUID`.

Use a reversible test-only host-name fault. This does not affect the tunnel,
Azure Run Command, RDP, or any management path because it only changes the
Windows hosts entry for the synthetic file-server name:

```powershell
$marker = '# rmm-openai-driver-smoke'
$line = "203.0.113.10 rmm-test-fileserver $marker"
$hosts = "$env:WINDIR\System32\drivers\etc\hosts"
$existing = Get-Content -LiteralPath $hosts -ErrorAction Stop
if ($existing -notcontains $line) {
    Add-Content -LiteralPath $hosts -Value $line
}
```

Do not tell the model that the hosts entry is the hidden cause. Ask only the
plain-English problem:

```sh
.venv/bin/python -m control_plane.openai_driver \
  --model gpt-5-nano \
  --max-steps 5 \
  --max-seconds 180 \
  "Why can this Windows machine not reach \\\\rmm-test-fileserver\\diagnostics?"
```

Expected behavior:

- The driver opens an authorized debugging session, calls OpenAI from the caller,
  and adaptively submits dependent fixed-template diagnostics through
  `POST /sessions/{id}/executions`.
- Each execution is followed through bounded long-poll output events and final
  execution records. Both stdout and stderr are drained after terminal status
  before the driver moves on. If a preview is shortened, the model may request a
  bounded retained output page for an execution created by this investigation,
  using the next cursor tracked by the caller. Driver pages use the control
  plane's 8 KiB minimum and expose the full returned page before advancing the
  cursor.
- The final report names the likely cause and proposed human fixes, but does not
  apply remediation.
- The rendered output lists API round-trip time, endpoint execution duration,
  model latency before each tool step, total model latency, completion state,
  and token usage/cost when the API returns usage.
- While commands are running, bounded output progress is emitted separately from
  model context on stderr.
- The session is closed even when a budget ends the investigation; the single
  bounded close attempt is controlled by `--cleanup-seconds`.

Restore the controlled fault afterward:

```powershell
$marker = '# rmm-openai-driver-smoke'
$hosts = "$env:WINDIR\System32\drivers\etc\hosts"
(Get-Content -LiteralPath $hosts) |
  Where-Object { $_ -notlike "*$marker*" } |
  Set-Content -LiteralPath $hosts
```

The smoke should consume at most one bounded `gpt-5-nano` run. Retry only when
the first run fails before receiving a usable OpenAI response or before any
diagnostic command can be submitted.
