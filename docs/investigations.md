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
- `POST /sessions/{id}/executions` — operator; requires `Idempotency-Key`.
- `GET /executions/{id}` — operator, workspace scoped.
- `POST /sessions/{id}/close` — operator; returns after endpoint cleanup confirmation.

Execution statuses are `queued`, `running`, `completed`, `expired`, `timed_out`,
and `outcome_unknown`. `expired` is used only for known non-execution before the
endpoint reports `running`. `timed_out` is used only when the endpoint confirms
that the worker and owned children stopped. Unknown outcomes retain null values
for evidence that was not observed and report a reason plus the last confirmed
lifecycle state. Completed results distinguish normalized invocation codes from
explicit script exits.
Output is currently retained and returned up to the endpoint's bounded
32,768-character capture per stream; complete paging/live output is a later slice.

Default execution runtime is five minutes. Callers may request `timeout_ms` up
to 60 minutes, but the control plane rejects executions whose requested deadline
would exceed the debugging session's absolute lifetime. Session idle timeout
defaults to 30 minutes and may be requested up to two hours at session creation;
running work is not idle. Every session has an eight-hour absolute lifetime.
The control plane uses a 60-second start deadline and waits up to ten seconds for
cleanup confirmation where applicable.

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
   `Idempotency-Key: set-value` and body
   `{"script":"$global:trialValue = 41","timeout_ms":5000}`. Expect `202` and an
   `execution_id`; poll `GET /executions/EXECUTION_ID` until `completed`.
4. Submit `$global:trialValue + 1` under a new idempotency key. The structured
   result must have `stdout` containing `42`, exit code `0`, and a duration.
5. Submit a harmless marker-file append, then repeat the identical request with
   the same idempotency key. Both responses must contain the same execution ID,
   and the file must contain only one marker. Reuse that key with different script
   text; expect `409`.
6. `POST /sessions/SESSION_ID/close`; expect `status: closed`. Create another
   session and evaluate `$null -eq $global:trialValue`; expect `True`, proving a
   fresh PowerShell environment. Close it.
7. For deadline cleanup, create a fresh session and submit a long script with
   `timeout_ms: 500` that starts an owned child process before sleeping. Poll the
   execution until it returns `timed_out`, `invocation_outcome: stopped`, null
   exit-code fields, and any partial output observed before the timeout. Close
   that session, open a fresh session, and verify the child process ID is gone.
8. For offline behavior, create a session while the device is online, stop the
   endpoint agent, then submit an execution. The execution record should become
   `outcome_unknown` with `outcome_reason: device_offline_before_dispatch` and
   `last_confirmed_status: queued`; no script output or invented exit code should
   be present.

The opt-in `tests/control_plane/test_windows.py` automates this path against the
authorized Azure Windows VM. It additionally stops the endpoint, observes an
offline terminal execution record, waits for staleness, restarts it, and verifies
the stable device identity.

## Boundaries

The trial uses one control-plane process because live WebSocket routing is
in-memory; durable claims and results remain in PostgreSQL. A restart marks
previously running work `outcome_unknown` and live sessions `failed` rather than
relaunching uncertain work. Endpoint disconnect marks live executions unknown but
does not free an active session for overlapping replacement; callers must close
and obtain confirmed cleanup before reuse. Multi-process connection routing,
full output paging, live streaming, caller revocation, installer/service
lifecycle, and configurable execution profiles belong to later tickets. Nothing
in this slice claims that arbitrary scripts are sandboxed from the managed
Windows host.
