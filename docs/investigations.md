# Persistent investigations — slices 3–4

An admin creates independently revocable callers. An `operator` can open one
debugging session on an online device, submit one PowerShell execution at a time,
retrieve its structured result, and close the session. The endpoint keeps one
PowerShell worker alive within a session, so variables, functions, modules, and
the working directory persist between executions. Closing confirms worker and
owned-child cleanup; a replacement session starts fresh.

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
- `POST /sessions/{id}/executions` — operator; requires `Idempotency-Key` and an explicit `timeout_ms`.
- `GET /executions/{id}` — operator, workspace scoped; includes up to 8 KiB
  of preview per output stream.
- `GET /executions/{id}/output/{stdout|stderr}` — operator, workspace scoped;
  returns retained output pages of at most 64 KiB.
- `GET /executions/{id}/output/{stdout|stderr}/events` — operator, workspace
  scoped; finite HTTP long-poll for retained output after a cursor.
- `POST /executions/{id}/cancel` — operator, workspace scoped; requests cancellation of queued/running work.
- `POST /sessions/{id}/close` — operator; returns after endpoint cleanup confirmation.

Execution statuses are `queued`, `running`, `completed`, `failed_to_start`,
`timed_out`, `cancelled`, and `outcome_unknown`. `failed_to_start` is used for
known non-execution, including submission while the endpoint is offline.
`timed_out` and `cancelled` are used only when the endpoint confirms that the
worker and owned children stopped. Unknown outcomes retain null values for
evidence that was not observed and report a reason plus the last confirmed
lifecycle state. Completed results distinguish normalized invocation codes from
explicit script exits.
Output is retained incrementally as inert per-stream data, never parsed as
lifecycle even when it resembles protocol JSON. Endpoint terminal `result`
messages carry lifecycle metadata only; stdout/stderr text comes from ordered
endpoint `output` frames. `GET /executions/{id}` derives and returns only the
preview from retained events; paging and long-poll endpoints expose more
retained context without rerunning the script. Cursors are per execution stream,
monotonically ordered by retained UTF-8 text events, and never split a Unicode
character.
Preview shortening is reported separately from capture loss. Capture loss means
execution ended before all emitted output could be forwarded, such as timeout or
worker loss; a shortened preview only means more retained output is available
behind the paging endpoints.

Long-poll callers provide `after` and a finite `wait_ms`. A response returns on
the first of new retained output after the cursor, terminal execution transition,
or timeout. It includes the current execution status, a terminal boolean,
`next_cursor`, stream high-water cursor, `more_available`, explicit gap/loss
metadata, and `timed_out`/`no_change` flags so a caller can decide whether to
inspect evidence, poll again, page more output, or submit the next command.

The caller must select `timeout_ms` for every execution; there is no default.
Values are accepted from 100 ms through the 60-minute safety ceiling. The
endpoint enforces the selected timeout locally even if the caller disconnects.
Timeout, cancellation, and explicit session closure terminate the worker's
Windows Job Object, including owned child processes, and wait up to ten seconds
for confirmation before reporting uncertainty.

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
4. Repeatedly call
   `GET /executions/EXECUTION_ID/output/stdout/events?after=CURSOR&wait_ms=2000`,
   starting from cursor `0`. Each response either returns new retained events,
   terminal completion metadata, or an explicit timeout/no-change result. Resume
   from the returned `next_cursor`; interrupting the client and resuming from the
   last cursor must not rerun the script or lose ordering.
5. After completion, call `GET /executions/EXECUTION_ID` and confirm API
   `stdout` is the control-plane-derived preview while
   `output_preview.stdout.shortened` distinguishes hidden retained content from
   `capture.loss_detected`.
6. Page through the retained output with
   `GET /executions/EXECUTION_ID/output/stdout?after=CURSOR&limit_bytes=65536`
   until `more_available` is false.
7. Submit `$global:trialValue = 41`, then `$global:trialValue + 1` under a new
   idempotency key. `GET /executions/{id}` must show API `stdout` preview
   containing `42`, exit code `0`, and a duration; that preview is derived from
   retained output frames, not duplicated endpoint terminal metadata.
8. Submit a harmless marker-file append, then repeat the identical request with
   the same idempotency key. Both responses must contain the same execution ID,
   and the file must contain only one marker. Reuse that key with different script
   text; expect `409`.
9. `POST /sessions/SESSION_ID/close`; expect `status: closed`. Create another
   session and evaluate `$null -eq $global:trialValue`; expect `True`, proving a
   fresh PowerShell environment. Close it.
10. For timeout cleanup, create a fresh session and submit a long script with
   `timeout_ms: 500` that starts an owned child process before sleeping. Poll the
   execution until it returns `timed_out`, `invocation_outcome: stopped`, null
   exit-code fields, and any partial output observed before the timeout. Close
   that session, open a fresh session, and verify the child process ID is gone.
11. Repeat with caller cancellation: submit a long-running execution, call
   `POST /executions/EXECUTION_ID/cancel`, and poll until it returns `cancelled`,
   `invocation_outcome: stopped`, and null exit-code fields.
12. For offline behavior, create a session while the device is online, stop the
   endpoint agent, then submit an execution. The execution record should become
   `failed_to_start` with `outcome_reason: device_offline_before_dispatch` and
   `last_confirmed_status: queued`; no script output or invented exit code should
   be present.

On 2026-09-21, the local public HTTP suite ran against a live PostgreSQL-backed
control plane with an independent endpoint simulator: `20 passed, 3 skipped`.
The output test covered progressive long-poll resume, preview bounds, 64 KiB
pages, Unicode, empty streams, output imitating control messages, disconnected
slow consumers, and workspace-scoped denial. The opt-in
`tests/control_plane/test_windows.py` automates the persistent investigation path
against the authorized Azure Windows VM. It additionally stops the endpoint,
observes an offline terminal execution record, waits for staleness, restarts it,
and verifies the stable device identity.

## Boundaries

The trial uses one control-plane process because live WebSocket routing is
in-memory; durable claims and results remain in PostgreSQL. A restart marks
previously running work `outcome_unknown` and live sessions `failed` rather than
relaunching uncertain work. The prototype does not include configurable session
idle/absolute lifetime, start-deadline clock coordination, offline command
queueing, or restart reconciliation. Multi-process connection routing, full
output search, caller revocation, installer/service lifecycle, and configurable
execution profiles belong to later tickets. Nothing in this slice claims that
arbitrary scripts are sandboxed from the managed Windows host.
