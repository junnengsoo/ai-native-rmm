# Control-plane HTTP API reference

This document specifies the caller-facing API implemented at `main` commit
`0c6de5e`. It is the integration contract for administrative tools, operator
callers, and the AI driver. The interactive schema at `/docs` and machine-readable
OpenAPI document at `/openapi.json` are useful for exploration; this reference
additionally defines response bodies, lifecycle meaning, retry behavior, and
implementation limits.

The endpoint-agent WebSocket at `/agent` is not a caller API. Its possession
proof, enrollment, heartbeat, and dispatch protocol are documented separately
in [Pairing and reachability](enrollment.md) and [Persistent investigations](investigations.md).

## Conventions

### Base URL and content type

Examples use `https://rmm.example.com` as the control-plane base URL. JSON request
and response bodies use `application/json`. Timestamps are UTC RFC 3339 strings.
Identifiers are UUID strings.

Every HTTP `POST` must include a decimal `Content-Length`, even when its body is
empty. Chunked request bodies are not accepted. Request bodies may not exceed
1 MiB; the smaller field limits documented below still apply.

### Authentication and roles

All HTTP operations require a caller credential:

```http
Authorization: Bearer rmm_...
```

Credentials are scoped to one workspace and have one of two roles:

| Role | Allowed operations |
| --- | --- |
| `admin` | List/name/revoke/recover devices, approve pairings, create callers |
| `operator` | Create/read/close debugging sessions, submit/wait/read/cancel executions |

Roles are exact: an admin credential cannot call operator endpoints, and an
operator credential cannot call admin endpoints. Resources are workspace scoped.
A resource in another workspace is returned as not found rather than exposed.

The initial admin credential is created locally, not over HTTP:

```sh
python -m control_plane.setup "Workspace name"
```

The command prints the credential once. `POST /callers` likewise returns each new
credential once; there is no credential-readback endpoint.

### Errors

Errors have one stable, machine-readable code:

```json
{"detail":"unauthorized"}
```

Common responses are:

| Status | `detail` | Meaning |
| --- | --- | --- |
| `401` | `unauthorized` | Bearer credential is absent, malformed, unknown, or revoked. |
| `403` | `forbidden` | The authenticated caller has the wrong role. |
| `411` | `content_length_required` | A POST omitted `Content-Length`, or a request used transfer encoding. |
| `413` | `request_too_large` | `Content-Length` is invalid or exceeds 1 MiB. |
| `422` | `invalid_request` | A path, query, header, or JSON body failed schema validation. |
| `429` | `rate_limited` | A fixed one-minute request allowance was exceeded. See `Retry-After`. |
| `503` | `temporarily_unavailable` | An unexpected control-plane or database failure was sanitized. |

Endpoint-specific error codes are listed with each operation. Error responses do
not echo rejected request values.

The current trial deployment permits 600 HTTP authentication attempts per minute
globally, 10 pairing approvals per minute per workspace, and 10 recovery
approvals per minute per workspace. A `429` response includes `Retry-After: 60`.
These are availability bounds, not production tenant quotas.

## Endpoint summary

| Method | Path | Role | Success |
| --- | --- | --- | --- |
| `GET` | `/devices` | admin | `200` device page |
| `PATCH` | `/devices/{device_id}` | admin | `200` renamed device |
| `POST` | `/devices/{device_id}/revoke` | admin | `200` revoked device |
| `POST` | `/devices/{device_id}/recover` | admin | `200` recovery awaiting activation|
| `POST` | `/callers` | admin | `201` caller and one-time API key |
| `POST` | `/pairings/approve` | admin | `200` approved device |
| `POST` | `/sessions` | operator | `201` ready debugging session |
| `GET` | `/sessions/{session_id}` | operator | `200` session |
| `POST` | `/sessions/{session_id}/executions` | operator | `202` execution handle |
| `GET` | `/executions/{execution_id}/wait` | operator | `200` status or terminal result |
| `GET` | `/executions/{execution_id}/output/{stream}` | operator | `200` output page |
| `GET` | `/executions/{execution_id}/output/{stream}/search` | operator | `200` literal matches |
| `GET` | `/executions/{execution_id}/output/{stream}/tail` | operator | `200` bounded retained tail |
| `GET` | `/executions/{execution_id}/output/{stream}/range` | operator | `200` retained byte range |
| `POST` | `/executions/{execution_id}/cancel` | operator | `202` cancellation snapshot |
| `POST` | `/sessions/{session_id}/close` | operator | `200` closed session |

## Admin operations

### List devices

```http
GET /devices?limit=100&after={device_id}
```

Query parameters:

| Name | Required | Contract |
| --- | --- | --- |
| `limit` | no | Integer from 1 through 100; default `100`. |
| `after` | no | UUID cursor from a previous `next_cursor`. Results are ordered by device UUID. |

Response:

```json
{
  "devices": [
    {
      "id": "8f34df53-9dc2-43ff-8507-b07da2c24470",
      "device_name": "Reception PC",
      "approved_at": "2026-09-21T20:10:00Z",
      "last_seen": "2026-09-21T20:11:00Z",
      "reachability": "online",
      "authorization_status": "active",
      "revoked_at": null,
      "revoked_by": null
    }
  ],
  "next_cursor": null
}
```

`device_name` is administrator-managed display metadata and is unique without
regard to case within its workspace. `authorization_status` is `active` or
`revoked`; revocation metadata is null until an admin revokes the device.

`last_seen` is null until an approved endpoint credential completes a fresh
possession proof. `reachability` is independent of authorization and is one of:

| Value | Meaning |
| --- | --- |
| `awaiting_activation` | Pairing or recovery was approved, but the new endpoint credential has not activated yet. |
| `activation_expired` | The first post-approval proof did not arrive before its deadline. |
| `online` | Authenticated contact was observed less than 45 seconds ago. |
| `stale` | The device activated previously, but authenticated contact is at least 45 seconds old. |

Reachability is recent evidence, not a guarantee that the next request will
succeed and not an assertion that the machine is powered off. A revoked device
can briefly remain `online` from its last recorded contact; authorization status
is authoritative for access.

### Create caller

```http
POST /callers
Content-Type: application/json

{"name":"diagnostic-agent","role":"operator"}
```

`name` is 1–100 characters and must be unique within the workspace. `role` is
`admin` or `operator`. Additional JSON properties are rejected.

Response (`201`):

```json
{
  "caller_id": "5239ca9a-0c6f-4c70-a50d-0dab75c7f9f0",
  "role": "operator",
  "api_key": "rmm_..."
}
```

Store `api_key` immediately; it cannot be retrieved again.

Endpoint-specific errors:

| Status | `detail` | Meaning |
| --- | --- | --- |
| `409` | `caller_name_conflict` | The workspace already has a caller with that name. |

### Approve pairing

```http
POST /pairings/approve
Content-Type: application/json

{"code":"ABCDEF234567","device_name":"Reception PC"}
```

`code` is exactly 12 uppercase base32 characters (`A`–`Z`, `2`–`7`) displayed
by the endpoint during pending enrollment. `device_name` is 1–100 characters;
leading and trailing whitespace is removed, and a whitespace-only value is
invalid. The normalized name must be unique without regard to case within the
workspace. Additional properties are rejected.

Response (`200`):

```json
{
  "device_id": "8f34df53-9dc2-43ff-8507-b07da2c24470",
  "state": "approved"
}
```

Approval consumes the code atomically. The endpoint must reconnect and prove
possession of its private key before it becomes online.

Endpoint-specific errors:

| Status | `detail` | Meaning |
| --- | --- | --- |
| `409` | `invalid_or_consumed_code` | The code is unknown, expired, or already consumed. |
| `409` | `device_name_conflict` | The workspace already has that device name. |

### Rename device

```http
PATCH /devices/{device_id}
Content-Type: application/json

{"device_name":"Reception PC Main"}
```

The name has the same normalization, length, and workspace-uniqueness rules as
pairing approval. Renaming does not change device identity, credentials, history,
authorization, or reachability.

Response (`200`):

```json
{
  "device_id": "8f34df53-9dc2-43ff-8507-b07da2c24470",
  "device_name": "Reception PC Main"
}
```

Endpoint-specific errors are `404 device_not_found` and
`409 device_name_conflict`.

### Revoke device

```http
POST /devices/{device_id}/revoke
Content-Length: 0
```

Revocation durably removes execution authority before the control plane attempts
best-effort remote cleanup. It does not delete device, session, execution, or
output history and does not uninstall the endpoint.

Response (`200`):

```json
{
  "device_id": "8f34df53-9dc2-43ff-8507-b07da2c24470",
  "authorization_status": "revoked",
  "revoked_at": "2026-09-22T20:10:00Z",
  "revoked_by": "fb79134a-e761-4033-854e-2edc796ff460",
  "cleanup": "confirmed"
}
```

`cleanup` is `confirmed`, `unconfirmed`, `not_required`, or `already_revoked`.
The operation is idempotent: repeated requests preserve the original revocation
metadata and return `already_revoked`. If cleanup cannot be confirmed, affected
work becomes `outcome_unknown` with reason
`device_revoked_cleanup_unconfirmed`. A revoked device cannot open sessions,
authenticate its old key, undergo recovery, or be unrevoked in this API version.

Endpoint-specific error: `404 device_not_found`.

### Approve technician recovery

```http
POST /devices/{device_id}/recover
Content-Type: application/json

{"code":"ABCDEF234567"}
```

Recovery binds the fresh endpoint key behind a pending-enrollment code to the
selected existing logical device. It preserves the device UUID, name, and
history. The previous credential remains active until the replacement reconnects
and proves possession; activation then replaces the old credential atomically.
The code has the same 12-character uppercase base32 schema as pairing approval;
additional JSON properties are rejected.

Response (`200`):

```json
{
  "device_id": "8f34df53-9dc2-43ff-8507-b07da2c24470",
  "device_name": "Reception PC Main",
  "state": "awaiting_activation"
}
```

Repeating the same approval as the same admin while it is still pending returns
the same successful response. A device with unresolved live work must be cleaned
up before recovery.

Endpoint-specific errors:

| Status | `detail` | Meaning |
| --- | --- | --- |
| `404` | `device_not_found` | The selected device is absent or outside the workspace. |
| `409` | `device_revoked` | Revoked devices cannot be recovered. |
| `409` | `device_busy` | The device has an unresolved live session. |
| `409` | `recovery_pending` | A different replacement credential is already awaiting activation. |
| `409` | `invalid_or_consumed_code` | The code is unknown, expired, consumed, or otherwise unusable. |

## Operator operations

### Create debugging session

```http
POST /sessions
Content-Type: application/json

{"device_id":"8f34df53-9dc2-43ff-8507-b07da2c24470"}
```

The response is delayed until the endpoint confirms that its persistent
PowerShell worker is ready. Only one live session may exist per device.
Additional JSON properties are rejected.

Response (`201`):

```json
{
  "session_id": "bc189277-77fa-42bf-b080-cf22fd742c61",
  "device_id": "8f34df53-9dc2-43ff-8507-b07da2c24470",
  "caller_id": "5239ca9a-0c6f-4c70-a50d-0dab75c7f9f0",
  "status": "active",
  "created_at": "2026-09-21T20:12:00Z",
  "ready_at": "2026-09-21T20:12:01Z",
  "closed_at": null
}
```

Endpoint-specific errors:

| Status | `detail` | Meaning |
| --- | --- | --- |
| `404` | `device_not_found` | The device is absent or outside the caller's workspace. |
| `409` | `device_revoked` | The device's execution authority was revoked. |
| `409` | `device_offline` | No authenticated endpoint channel is currently connected. |
| `409` | `device_busy` | The device already has a live or cleanup-uncertain session. |
| `503` | `session_start_failed` | The endpoint did not confirm readiness within 20 seconds. |

### Get debugging session

```http
GET /sessions/{session_id}
```

Response (`200`) uses the session shape above. `status` is one of `starting`,
`active`, `closing`, `closed`, `failed`, or `cleanup_unknown`; timestamps that
have not occurred are null.

Endpoint-specific error: `404 session_not_found`.

### Submit execution

```http
POST /sessions/{session_id}/executions
Idempotency-Key: diagnose-dns-001
Content-Type: application/json

{
  "script": "Resolve-DnsName rmm-test-fileserver",
  "timeout_ms": 5000
}
```

Request contract:

| Field/header | Contract |
| --- | --- |
| `Idempotency-Key` | Required, 1–200 characters. Its contents are opaque to the server. |
| `script` | Required, 1–32,768 characters. It is hashed exactly as UTF-8 and is not rewritten. |
| `timeout_ms` | Required integer from 100 through 3,600,000 (60 minutes). There is no default. |

Additional JSON properties are rejected. Only one execution may be queued or
running in a session at once.

Response (`202`):

```json
{
  "execution_id": "6768b006-4436-4465-ab8a-13253fd4f2ab",
  "status": "queued",
  "script_sha256": "9dad5e902bde4522f326aeade2f36dd44ec7fd6c276cda474c2fa30900c31c72"
}
```

`202` means the request was durably accepted; it does not mean that PowerShell
started or completed. If the endpoint disconnects before dispatch, the accepted
record becomes `failed_to_start` rather than being replayed later.

Idempotency is scoped to the authenticated caller. Repeating the same key with
the same session ID, exact script, and timeout returns the original execution,
including its current status. Reusing the key with any different bound input is
a conflict. A valid duplicate is returned even if the session is now busy or no
longer active.

Endpoint-specific errors:

| Status | `detail` | Meaning |
| --- | --- | --- |
| `404` | `active_session_not_found` | The session is absent, outside the workspace, or not active. |
| `409` | `session_busy` | Another execution is queued or running in the session. |
| `409` | `idempotency_conflict` | The caller reused a key with different bound inputs. |
| `422` | `idempotency_key_required` | The header is absent or outside its length bound. |

### Wait for execution

```http
GET /executions/{execution_id}/wait?timeout_seconds=20
```

`timeout_seconds` is a number from 0 through 60 and defaults to `20`. A value of
zero is an immediate status lookup. Output events do not wake this request; it
returns when the execution becomes terminal or the HTTP wait expires.

A nonterminal response contains only:

```json
{
  "execution_id": "6768b006-4436-4465-ab8a-13253fd4f2ab",
  "status": "running",
  "terminal": false,
  "wait_timed_out": true
}
```

The timeout does not cancel or otherwise change the execution. Continue calling
the endpoint with the same execution ID.

A terminal response contains the full execution view:

```json
{
  "execution_id": "6768b006-4436-4465-ab8a-13253fd4f2ab",
  "session_id": "bc189277-77fa-42bf-b080-cf22fd742c61",
  "caller_id": "5239ca9a-0c6f-4c70-a50d-0dab75c7f9f0",
  "status": "completed",
  "script_sha256": "9dad5e902bde4522f326aeade2f36dd44ec7fd6c276cda474c2fa30900c31c72",
  "invocation_outcome": "completed_normally",
  "outcome_reason": null,
  "last_confirmed_status": null,
  "exit_code": 0,
  "exit_code_source": "normalized_invocation",
  "had_errors": false,
  "duration_ms": 108.4,
  "capture_truncated": false,
  "capture": {"loss_detected": false, "reason": null},
  "output_preview": {
    "stdout": {"text": "Server: 10.0.0.2\n", "shortened": false, "capture_lost": false},
    "stderr": {"text": "", "shortened": false, "capture_lost": false}
  },
  "last_native_exit_code": null,
  "created_at": "2026-09-21T20:13:00Z",
  "started_at": "2026-09-21T20:13:00Z",
  "finished_at": "2026-09-21T20:13:01Z",
  "terminal": true,
  "wait_timed_out": false
}
```

Each stream preview contains at most 8 KiB of retained UTF-8 output.
`shortened: true` means more retained output is available from the paging
endpoint. `capture.loss_detected: true` means output was actually lost; its
current reason is `retention_limit`. These are different conditions.

Fields without observed evidence are null. In particular, do not interpret a
null exit code as zero.

Endpoint-specific error: `404 execution_not_found`.

### Read execution output

```http
GET /executions/{execution_id}/output/stdout?after=0&limit_bytes=65536
```

`stream` is `stdout` or `stderr`. `after` is a decimal event cursor and defaults
to `0`. `limit_bytes` is 8,192–65,536 and defaults to 65,536.

Response (`200`):

```json
{
  "text": "Server: 10.0.0.2\n",
  "next_cursor": "2",
  "has_more": false,
  "more_available": false,
  "capture_lost": false,
  "gap": {"detected": false, "reason": null},
  "unicode": {
    "encoding": "utf-8",
    "ordering": "per-stream insertion order",
    "unit": "cursored event text"
  }
}
```

To page, pass `next_cursor` as the next `after` value until `more_available` is
false. Cursors are independent for stdout and stderr. A page never splits a
Unicode character. `has_more` and `more_available` are equivalent in this API
version.

Endpoint-specific errors:

| Status | `detail` | Meaning |
| --- | --- | --- |
| `404` | `stream_not_found` | `stream` is not `stdout` or `stderr`. |
| `404` | `execution_not_found` | The execution is absent or outside the workspace. |
| `422` | `invalid_cursor` | `after` is not a non-negative decimal integer. |

### Search retained output

```http
GET /executions/{execution_id}/output/stdout/search?query=error&context_lines=2
```

This is a read over centrally retained output. It does not contact the endpoint,
rerun a script, accept regular expressions, or inspect arbitrary device files.
It works while the endpoint is disconnected.

Query parameters:

| Name | Required | Contract |
| --- | --- | --- |
| `query` | yes | Literal text, 1–1,024 characters. |
| `case_sensitive` | no | Boolean; default `false`. |
| `context_lines` | no | Lines before and after each match, 0–5; default `0`. |
| `limit_matches` | no | Matches to return, 1–50; default `20`. |
| `after_byte` | no | Non-negative UTF-8 byte offset for continuation; default `0`. |

Response (`200`, abbreviated to one match):

```json
{
  "snapshot": {
    "high_water_cursor": "42",
    "scanned_events": 42,
    "scanned_bytes": 8192
  },
  "query": "error",
  "case_sensitive": false,
  "context_lines": 2,
  "searched_from_byte": 0,
  "matches": [
    {
      "range": {"start_byte": 1030, "end_byte": 1035},
      "line_range": {"start_line": 18, "end_line": 18},
      "text": "ERROR",
      "context": {"before": "line 16\nline 17\n", "after": "line 19\nline 20\n"},
      "shortened": false
    }
  ],
  "match_count": 1,
  "limit_reached": false,
  "next_after_byte": null,
  "partial": false,
  "partial_reason": null,
  "content_truncated": false,
  "content_limit_bytes": 65536,
  "stream": "stdout",
  "capture_lost": false,
  "gap": {"detected": false, "reason": null},
  "unicode": {
    "encoding": "utf-8",
    "ordering": "per-stream insertion order",
    "unit": "utf-8 byte offsets"
  }
}
```

When `limit_reached` is true, repeat the request with `after_byte` set to
`next_after_byte`. `range` values can be passed to the range endpoint. Search is
bounded to 4,096 events and 1 MiB of scanned UTF-8 text per request. If either
bound prevents a complete scan, `partial` is true and `partial_reason` is
`event_scan_limit` or `byte_scan_limit`; an empty match list then applies only to
the disclosed scanned region. Match text and context are jointly capped at
65,536 bytes and disclose truncation separately.

### Tail retained output

```http
GET /executions/{execution_id}/output/stderr/tail?lines=50
```

`lines` is 1–200 and defaults to `50`. The response uses the same snapshot,
capture, gap, and Unicode metadata as search:

```json
{
  "snapshot": {"high_water_cursor": "9", "scanned_events": 9, "scanned_bytes": 2048},
  "lines": 50,
  "text": "warn one\nfatal two\n",
  "range": {"start_byte": 2019, "end_byte": 2048},
  "line_range": {"start_line": 87, "end_line": 88},
  "partial": false,
  "partial_reason": null,
  "content_truncated": false,
  "content_limit_bytes": 65536,
  "stream": "stderr",
  "capture_lost": false,
  "gap": {"detected": false, "reason": null},
  "unicode": {
    "encoding": "utf-8",
    "ordering": "per-stream insertion order",
    "unit": "utf-8 byte offsets"
  }
}
```

If the selected tail exceeds 65,536 bytes, the response retains its final UTF-8
suffix, advances `range.start_byte`, and sets `content_truncated: true`. If
`partial` is true, scan limits prevented the operation from reaching all retained
events, so the text is only the tail of the disclosed scanned region.

### Read retained output range

```http
GET /executions/{execution_id}/output/stdout/range?start_byte=1030&end_byte=1035
```

Both offsets are required non-negative integers, and `end_byte` must be greater
than `start_byte`. Use offsets returned by search, tail, or an earlier range.

Response (`200`):

```json
{
  "snapshot": {"high_water_cursor": "42", "scanned_events": 42, "scanned_bytes": 8192},
  "text": "ERROR",
  "range": {"start_byte": 1030, "end_byte": 1035},
  "requested_range": {"start_byte": 1030, "end_byte": 1035},
  "line_range": {"start_line": 18, "end_line": 18},
  "partial": false,
  "partial_reason": null,
  "content_truncated": false,
  "content_limit_bytes": 65536,
  "stream": "stdout",
  "capture_lost": false,
  "gap": {"detected": false, "reason": null},
  "unicode": {
    "encoding": "utf-8",
    "ordering": "per-stream insertion order",
    "unit": "utf-8 byte offsets"
  }
}
```

If an offset falls inside a multi-byte character, `range` reports the actual
whole-character boundaries returned. Response text is capped at 65,536 bytes.
When `partial` is true, the requested range may extend beyond the disclosed
scanned region and must not be treated as a complete read.

All three retained-output investigation endpoints return `404 stream_not_found`
for an invalid stream and `404 execution_not_found` for an absent or
cross-workspace execution. Schema-bound query failures return
`422 invalid_request`; an end offset not greater than its start returns
`422 invalid_range`.

### Cancel execution

```http
POST /executions/{execution_id}/cancel
Content-Length: 0
```

Response (`202`) is the full execution view described under the wait operation,
without `terminal` or `wait_timed_out`.

For queued work, cancellation is immediate and terminal with
`outcome_reason: caller_cancelled_before_start` and
`last_confirmed_status: queued`. For running work, the response only confirms
that the cancellation request was sent; wait for a terminal result. The endpoint
reports `cancelled` only after it confirms the worker and owned children stopped.
If confirmation is lost, the final status is `outcome_unknown`, not `cancelled`.
Calling cancel on an already-terminal execution is idempotent and returns its
current view.

Endpoint-specific error: `404 execution_not_found`.

### Close debugging session

```http
POST /sessions/{session_id}/close
Content-Length: 0
```

The response waits up to 30 seconds for endpoint confirmation that the worker and
owned children were cleaned up.

Response (`200`) uses the session shape with `status: closed` and a populated
`closed_at`.

Endpoint-specific errors:

| Status | `detail` | Meaning |
| --- | --- | --- |
| `409` | `session_not_active` | The session is absent, outside the workspace, or not active. |
| `503` | `session_close_unconfirmed` | Cleanup could not be confirmed; the session becomes `cleanup_unknown`. |

A cleanup-unknown session continues to reserve the device. Do not assume a new
session is safe merely because the close request returned.

## Execution result semantics

Execution `status` values are:

| Status | Terminal | Meaning |
| --- | --- | --- |
| `queued` | no | Durably accepted but endpoint start is not confirmed. |
| `running` | no | Endpoint confirmed that the invocation started. |
| `completed` | yes | Endpoint returned definitive invocation evidence. This does not mean the IT problem was resolved. |
| `failed_to_start` | yes | Non-execution is known, such as endpoint loss before dispatch. |
| `timed_out` | yes | The selected deadline elapsed and stopping was confirmed. |
| `cancelled` | yes | Cancellation/non-start was confirmed. |
| `outcome_unknown` | yes | Dispatch, completion, cancellation, disconnect, or restart evidence was lost. The execution is never replayed automatically. |

For `completed`, `invocation_outcome` is:

| Value | Exit-code behavior |
| --- | --- |
| `completed_normally` | `exit_code` is normalized invocation result `0`. |
| `terminating_error` | `exit_code` is normalized invocation result `1`. |
| `explicit_exit` | `exit_code` is the script-supplied exit code. |

Completed exit codes use `exit_code_source` of `normalized_invocation` or
`explicit_script_exit`. Confirmed `timed_out` and running `cancelled` results use
`invocation_outcome: stopped` and null exit-code fields. Unknown and failed-start
results retain null evidence plus `outcome_reason` and `last_confirmed_status`.

Current `outcome_reason` values include:

- `device_offline_before_dispatch`
- `caller_cancelled_before_start`
- `dispatch_confirmation_lost`
- `cancel_confirmation_lost`
- `endpoint_reported_unknown`
- `endpoint_disconnected`
- `control_plane_restart`
- `device_revoked_cleanup_unconfirmed`

Callers should tolerate new reason strings and new optional response fields.

## Minimal operator workflow

```sh
export RMM_API_URL=https://rmm.example.com
export RMM_OPERATOR_KEY=rmm_replace_me
export RMM_DEVICE_ID=8f34df53-9dc2-43ff-8507-b07da2c24470

session_json="$(curl --fail-with-body \
  -H "Authorization: Bearer $RMM_OPERATOR_KEY" \
  -H 'Content-Type: application/json' \
  -d "{\"device_id\":\"$RMM_DEVICE_ID\"}" \
  "$RMM_API_URL/sessions")"
```

Read `session_id` from that response, submit an execution with a unique
`Idempotency-Key`, then call its wait endpoint until `terminal` is true. Page
either output stream when its preview is shortened. Always close the session in
a `finally`/defer-style cleanup path.

## Current compatibility boundaries

- The API is unversioned. Pin integrations to a known deployment revision and
  treat incompatible path or field changes as requiring coordination.
- Only one control-plane process is supported because live endpoint routing is
  in memory, although execution records are durable in PostgreSQL.
- There is no offline command queue, caller-credential revocation endpoint,
  device unrevocation, session lifetime configuration, or restart reconciliation
  in this revision.
- The control plane retains exact submitted scripts and output as protected
  execution evidence. Script output is untrusted data and must be rendered inertly.
- The current endpoint worker runs as Windows `LocalSystem`. The API does not
  provide a sandbox or enforce read-only PowerShell.
