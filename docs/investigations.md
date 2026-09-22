# Persistent investigations — slices 3–4

An admin creates independently revocable callers. An `operator` can open one
debugging session on an online device, submit one PowerShell execution at a time,
retrieve its structured result, and close the session. The endpoint keeps one
PowerShell worker alive within a session, so variables, functions, modules, and
the working directory persist between executions. Closing confirms worker and
owned-child cleanup; a replacement session starts fresh.

The [OpenAI diagnostic driver](openai-driver.md) is an example caller layered on
this API. It keeps model use on the caller side, enforces explicit step/time
budgets, and submits only authenticated public API operations to the control
plane.

For this trial, the endpoint agent and its PowerShell worker run as Windows
`LocalSystem`; there is no execution-profile choice or permission isolation yet.
Restricted and current-user workers, plus privileged approval/elevation flows,
are explicitly future work. The caller remains responsible for deciding which
scripts are appropriate to submit.

The control plane stores the exact script, SHA-256 hash, stable requesting
`caller_id`, idempotency key, lifecycle, and bounded structured evidence before
and after dispatch. The immediate `202` execution response is a handle, not a
claim that PowerShell finished. Retries with the same caller and idempotency key
return the original execution; changing any bound input returns `409`.

## API

- `POST /callers` — admin only; returns a new credential once.
- `POST /sessions` — operator only; returns only after the endpoint worker is ready.
- `GET /sessions/{id}` — operator, workspace scoped.
- `POST /sessions/{id}/executions` — operator; requires `Idempotency-Key`; `timeout_ms` is accepted for client compatibility but is not an endpoint execution deadline.
- `GET /executions/{id}/wait?timeout_seconds=20` — operator, workspace scoped;
  immediate status lookup when `timeout_seconds=0`, or a terminal-state wait
  for command-line callers. It wakes only when the execution reaches a terminal
  status or the HTTP wait expires; stdout/stderr output does not wake it.
- `GET /executions/{id}/output/{stdout|stderr}` — operator, workspace scoped;
  returns retained output pages of at most 64 KiB.
- `GET /executions/{id}/output/{stdout|stderr}/search` — operator, workspace
  scoped; literal text only, no regex, with bounded context, match count,
  `after_byte` continuation, snapshot/high-water metadata, and UTF-8 byte ranges
  that can be expanded later.
- `GET /executions/{id}/output/{stdout|stderr}/tail` — operator, workspace
  scoped; returns the last requested retained lines, capped at 200 lines and
  64 KiB of text.
- `GET /executions/{id}/output/{stdout|stderr}/range` — operator, workspace
  scoped; expands a caller-provided UTF-8 byte range, normally one returned by
  search or tail, with a 64 KiB response text ceiling.
- `POST /executions/{id}/cancel` — operator, workspace scoped; requests cancellation of queued/running work.
- `POST /sessions/{id}/close` — operator; returns after endpoint cleanup confirmation.

Session status `lost` means a previously live PowerShell worker was retired
during reconnect reconciliation; its variables, functions, modules, and working
directory must be treated as gone.

Execution statuses are `queued`, `running`, `completed`, `failed_to_start`,
`timed_out`, `cancelled`, and `outcome_unknown`. `failed_to_start` is used for
known non-execution, including submission while the endpoint is offline.
`timed_out` and `cancelled` are used only when the endpoint confirms that the
worker and owned children stopped. Unknown outcomes retain null values for
evidence that was not observed and report a reason plus the last confirmed
lifecycle state. Completed results distinguish normalized invocation codes from
explicit script exits.
Output is retained incrementally as inert per-stream data, never parsed as
lifecycle even when it resembles protocol JSON. Endpoint terminal records carry
lifecycle metadata only; stdout/stderr text comes from ordered endpoint ledger
`output_chunk` records. Terminal wait responses derive and return preview text
only under `output_preview`; they do not duplicate preview text as top-level
`stdout` or `stderr`. Paging endpoints expose more retained context without
rerunning the script. Cursors are per execution stream,
monotonically ordered by retained UTF-8 text events, and never split a Unicode
character.

Reconnect reconciliation is ledger based. The endpoint writes accepted work,
output, output-loss markers, worker-stop evidence, and terminal records to a
local append-only ledger before sending them. The control plane ingests ordered
`ledger_batch` messages transactionally and replies with `ledger_ack` only after
the contiguous records are committed. A socket disconnect makes reachability
stale, but it does not cancel a surviving invocation, retire the PowerShell
worker, or finalize the execution as unknown. On reconnect, the endpoint resends
records above its acknowledged checkpoint; duplicate records with identical
content are ignored and conflicting duplicates or binding/hash mismatches are
rejected.

A terminal record received after reconnect is the ordinary result for that
execution as long as the execution was not already finalized as genuinely
unknown. Normal completion leaves the debugging session active and reusable. If
the endpoint service or machine restarts with no surviving worker and no terminal
record, the endpoint writes `worker_stopped`; any accepted running execution
becomes `outcome_unknown`, and the old session becomes `lost`. Reconciliation
never replays the prior script.
Preview shortening is reported separately from capture loss. Capture loss means
execution ended before all emitted output could be forwarded, such as cancellation,
session cleanup, endpoint restart, or worker loss; a shortened preview only means more retained output is available
behind the paging endpoints.

Retained-output investigation is a control-plane storage read. Search is
case-insensitive by default; callers can request case-sensitive matching. Match
and range positions are stable UTF-8 byte offsets within one execution stream at
the returned snapshot high-water cursor. Search scans bounded retained work and
returns `partial` plus `partial_reason` if event or byte scan limits prevent a
complete answer; an empty `matches` list only means no match was found in the
disclosed scanned region. These reads never submit endpoint work, never inspect
arbitrary host files, and expose no storage path, SQL, shell, or regex surface.

Terminal-wait callers provide `timeout_seconds` from 0 through 60. A terminal
response includes the normal bounded execution view plus `terminal: true` and
`wait_timed_out: false`. A wait timeout returns only the execution ID, current
`queued`/`running` status, `terminal: false`, and `wait_timed_out: true`; it
does not cancel or otherwise affect the execution.

The endpoint does not enforce a separate per-execution timeout. Compatible
clients may still send `timeout_ms` from 100 ms through the 60-minute safety
ceiling, but cancellation, explicit session closure, revocation cleanup, and
session/service lifetime own worker termination. Confirmed cleanup terminates the
worker's Windows Job Object, including owned child processes, and close waits up
to 30 seconds for confirmation before reporting uncertainty.

## Manual smoke test

Complete the local Compose, tunnel, Windows enrollment, and admin setup in
[enrollment.md](enrollment.md). Keep the agent, tunnel, and Compose stack running.
Use the interactive OpenAPI page at `http://127.0.0.1:18080/docs`, or send the
same requests with an HTTP client:

1. As the admin, `POST /callers` with `{"name":"manual-operator","role":"operator"}`.
   Save the returned `api_key`; it is shown once. Using this operator key against
   `GET /devices` must return `403`.
2. With `Authorization: Bearer OPERATOR_KEY`, `POST /sessions` using the enrolled
   `device_id`. Expect `201`, `status: active`, and a `session_id`; a second live
   session for that device must return `409`.
3. `POST /sessions/SESSION_ID/executions` with header
   `Idempotency-Key: progressive-output` and body containing a script that prints
   progressively, for example
   `1..5 | ForEach-Object { "tick $_"; Start-Sleep -Milliseconds 300 }`.
   Expect `202` and an `execution_id`.
4. Call
   `GET /executions/EXECUTION_ID/wait?timeout_seconds=1` while output is still
   being produced. Intermediate stdout/stderr must not wake it. It should return
   only when the execution becomes terminal or with `wait_timed_out: true`.
5. Call `GET /executions/EXECUTION_ID/wait?timeout_seconds=20` until it returns
   `terminal: true`; confirm `output_preview.stdout.shortened` distinguishes
   hidden retained content from `capture.loss_detected`.
6. Page through the retained output with
   `GET /executions/EXECUTION_ID/output/stdout?after=CURSOR&limit_bytes=65536`
   until `more_available` is false.
7. Submit a script that writes a long retained stdout log and stderr tail, for
   example:

   ```powershell
   1..250 | ForEach-Object { "line $_" }
   "ERROR café at final line"
   [Console]::Error.WriteLine("warn one")
   [Console]::Error.WriteLine("fatal two")
   ```

   Wait for its `execution_id`, stop the endpoint agent, then call:

   ```sh
   curl -H "Authorization: Bearer OPERATOR_KEY" \
     "http://127.0.0.1:18080/executions/EXECUTION_ID/output/stdout/search?query=error%20caf%C3%A9&context_lines=2&limit_matches=5"
   curl -H "Authorization: Bearer OPERATOR_KEY" \
     "http://127.0.0.1:18080/executions/EXECUTION_ID/output/stderr/tail?lines=2"
   curl -H "Authorization: Bearer OPERATOR_KEY" \
     "http://127.0.0.1:18080/executions/EXECUTION_ID/output/stdout/range?start_byte=START&end_byte=END"
   ```

   Use the `start_byte` and `end_byte` from the search match for the range
   request. All three reads must work while the endpoint is offline. Submit a
   new execution to the same session while offline; the old session should no
   longer be active, proving retained-output reads did not create or dispatch
   endpoint work. Also verify a search for absent text returns `matches: []`,
   unauthorized workspace reads return `404`, an empty query returns `422`, and
   an inverted range returns `422`.
8. Submit `$global:trialValue = 41`, then `$global:trialValue + 1` under a new
   idempotency key. The terminal wait response must show
   `output_preview.stdout.text` containing `42`, exit code `0`, and a duration.
   That preview is derived from retained output frames, not duplicated endpoint
   terminal metadata.
9. Submit a harmless marker-file append, then repeat the identical request with
   the same idempotency key. Both responses must contain the same execution ID,
   and the file must contain only one marker. Reuse that key with different script
   text; expect `409`.
10. `POST /sessions/SESSION_ID/close`; expect `status: closed`. Create another
   session and evaluate `$null -eq $global:trialValue`; expect `True`, proving a
   fresh PowerShell environment. Close it.
11. For active close cleanup, create a fresh session and submit a long script
   that starts an owned child process before sleeping. Close the session while
   the execution is running; expect the execution to return `cancelled`,
   `invocation_outcome: stopped`, the session to become `closed`, and the owned
   child process to be gone after opening a fresh session.
12. Repeat with caller cancellation: submit a long-running execution, call
   `POST /executions/EXECUTION_ID/cancel`, and poll until it returns `cancelled`,
   `invocation_outcome: stopped`, and null exit-code fields.
13. For offline behavior, create a session while the device is online, stop the
   endpoint agent, then submit an execution to that old session. The request may
   create a truthful `failed_to_start` execution if no endpoint connection can
   accept it; it must not invent output, an exit code, or a replacement dispatch.
14. For active reconnect reconciliation, create a session and submit a script
   that writes durable marker 1, waits, then writes durable marker 2. Interrupt
   connectivity after marker 1 and reconnect while the invocation is still
   active. The execution should remain `running`, new sessions/executions should
   be blocked, and marker 2 should be written exactly once. When the invocation
   becomes terminal, `GET /executions/{id}/wait` should show the ordinary
   terminal status and output preview, and the same session should accept a
   second command after reconciliation completes.
15. Drop a `ledger_ack`, reconnect, and confirm retransmission does not duplicate
   retained output or lifecycle transitions.
16. Exercise a small test-only endpoint ledger capacity and confirm execution
   completes with `output_complete: false` and an output-loss reason while
   preserving terminal evidence.

On 2026-09-23, the Compose-backed control-plane suite ran against PostgreSQL and
the independent endpoint simulators: `66 passed, 3 skipped`. The output tests
covered terminal waits that ignore intermediate output, preview bounds, 64 KiB
pages, Unicode, empty streams, output imitating control messages, wait timeouts
that leave execution running, and workspace-scoped denial. The opt-in
`tests/control_plane/test_windows.py` automates the persistent investigation path
against the authorized Azure Windows VM. It additionally stops the endpoint,
observes an offline terminal execution record, waits for staleness, restarts it,
and verifies the stable device identity.

## Boundaries

The trial uses one control-plane process because live WebSocket routing is
in-memory. Durable endpoint ledger records, committed cursor acknowledgements,
normal execution results, output-loss markers, and genuinely unknown outcomes
remain in PostgreSQL. The ledger is intentionally scoped to one generation, one
active debugging session, and one active execution at a time; it is not a general
event-sourcing system. The prototype does not include multiple concurrent
executions, high-availability control-plane routing, offline command queueing,
automatic rerun of unknown work, indefinite endpoint retention after
acknowledgement, full caller revocation, installer/service lifecycle, or
configurable execution profiles. Nothing in this slice claims that arbitrary
scripts are sandboxed from the managed Windows host.
