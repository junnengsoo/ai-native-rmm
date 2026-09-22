# OpenAI diagnostic driver

The OpenAI driver is a caller-side demo, not endpoint intelligence. It uses the
OpenAI Agents SDK with one `Agent`, three model-visible tools, and the SDK
`Runner` tool loop. The model-visible tools are:

- `submit_script(script, timeout_ms)` — submit model-authored PowerShell to the
  already-open driver-owned session.
- `wait_for_execution(execution_id, timeout_seconds)` — wait for terminal state,
  or return a bounded nonterminal status when the HTTP wait expires.
- `read_output(execution_id, stream, cursor)` — read one retained output page
  when a terminal preview is shortened.

Only one script can be active in the persistent PowerShell session at a time.
The control plane enforces that session boundary, and the model prompt tells the
agent to submit one script, repeatedly wait for its terminal result, then submit
the next script.

The endpoint never receives OpenAI keys, admin keys, operator keys, raw model
tool requests, or session-control authority from the model. Session open/close,
credentials, device/session binding, execution ownership, time/script budgets,
and cleanup remain driver-owned. The default model is `gpt-5-nano`.

The model is instructed to author only read-only diagnostic PowerShell and never
to remediate. That is a policy boundary, not an enforced PowerShell sandbox:
this prototype currently runs endpoint scripts as Windows `LocalSystem`.

## Deterministic tests

Run the driver tests without contacting OpenAI:

```sh
.venv/bin/python -m pytest -q tests/control_plane/test_openai_driver.py
```

The tests use a scripted local SDK `Model` with the real Agents SDK `Runner` and
function-tool path, while faking the public control-plane and endpoint evidence.
They cover dependent model-authored scripts, the exact three-tool SDK surface,
submit → repeated nonterminal/terminal wait → dependent next script → paged
output, unknown execution ID rejection, script budget enforcement, terminal-safe
rendering of untrusted text, lifecycle-hook model timing, session close in the
driver `finally` path, and operator authentication without OpenAI key leakage.

## Optional paid Windows/OpenAI smoke

This is a separate manual check after deterministic local tests pass. It makes
one small OpenAI call and requires a live local control plane plus an enrolled
Windows endpoint. Do not run it as part of the local rewrite validation.

Complete local enrollment in [enrollment.md](enrollment.md), then use an
operator key and explicit device ID from the caller shell:

```sh
export RMM_API_URL=http://127.0.0.1:18080
export RMM_OPERATOR_KEY=OPERATOR_KEY_PLACEHOLDER
export RMM_DEVICE_ID=DEVICE_UUID
export OPENAI_API_KEY=OPENAI_KEY_PLACEHOLDER
```

Create a reversible test-only file-server fault on the Windows test device:

```powershell
$marker = '# rmm-openai-driver-smoke'
$line = "203.0.113.10 rmm-test-fileserver $marker"
$hosts = "$env:WINDIR\System32\drivers\etc\hosts"
if ((Get-Content -LiteralPath $hosts) -notcontains $line) {
    Add-Content -LiteralPath $hosts -Value $line
}
```

Do not tell the model the hidden cause. Ask only the plain-English problem:

```sh
.venv/bin/python -m control_plane.openai_driver \
  --model gpt-5-nano \
  --max-steps 5 \
  --max-seconds 180 \
  "Why can this Windows machine not reach \\\\rmm-test-fileserver\\diagnostics?"
```

Expected behavior:

- The caller opens one debugging session and closes it in `finally`.
- The SDK runner manages model turns and function-tool execution.
- The model can author PowerShell, but the prompt policy allows only read-only
  diagnosis. This is not a sandbox; the endpoint currently runs as LocalSystem.
- Target host and port are caller-bound in the prompt; session/device binding
  and credentials are never exposed as model tools.
- The caller waits for terminal execution state through
  `GET /executions/{id}/wait`.
- If a preview is shortened, the tool retrieves bounded retained pages using
  continuation cursors.
- The final report proposes human fixes but performs no remediation.
- Rendered timings show per-tool API time, SDK lifecycle-hook model time, total
  time, and model usage when returned by the SDK.

Remove the test fault afterward:

```powershell
$marker = '# rmm-openai-driver-smoke'
$hosts = "$env:WINDIR\System32\drivers\etc\hosts"
(Get-Content -LiteralPath $hosts) |
  Where-Object { $_ -notlike "*$marker*" } |
  Set-Content -LiteralPath $hosts
```

## Prior failure notes

The previous live-smoke failures were not OpenAI model failures:

- The `422` occurred before any OpenAI call. The custom Azure harness extracted
  the pairing code incorrectly, so approval was attempted with an invalid body.
- One run pointed the tunnel at the Issue 4 stack instead of the Issue 15 control
  plane, so the public API did not match the branch under test.
- The slow loop repeatedly rebuilt and redeployed through Azure Run Command.
  That made each retry expensive and also risked competing with other VM work.

For this issue, keep SDK rewrite validation local and deterministic. Use the
manual smoke only once the normal enrollment/control-plane path is already up.
