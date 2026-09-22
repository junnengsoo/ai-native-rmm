# Pairing and reachability — slice 2

This slice enrolls a Windows key and reports contact through a local Python
control plane backed by PostgreSQL. It does not install a service, dispatch
scripts, recover/revoke devices, or implement the later session/execution API.
The older `--agent` entry point remains an isolated, manually provisioned mTLS
execution harness; never deploy it to customer endpoints as an enrollment bypass.

The caller roles are **admin** and **operator**. This slice creates only the
initial workspace admin credential and implements its pairing/device-list access.
Operator credentials and sessions/executions/output permissions arrive with the
execution API; operators will not receive admin pairing or management authority.
There is no separate technician or viewer role.

## Local setup and manual smoke

Prerequisites: Docker Desktop running on the Mac; Python 3.13; .NET 8 on Windows;
`cloudflared` installed from Cloudflare's official distribution. The Mac must stay
awake and connected. Use only the authorized trial Windows machine. Database
state persists in a Compose volume; normal `docker compose down` preserves it.
Do not use `down -v` unless intentionally discarding the isolated trial database.
Do not run concurrent manual/automated trials against the same Compose project.
For an independent validation run, set a distinct `COMPOSE_PROJECT_NAME` and
`RMM_HTTP_PORT` (default 18080), and point `RMM_API_URL` and the tunnel at that
port. Each Compose project has its own database volume and saved password.

Before starting Compose, configure its database password:

- **First run, no existing trial volume:** generate a strong URL-safe password in
  your password manager and save it there. Create a local `.env` in this worktree
  containing `RMM_POSTGRES_PASSWORD=YOUR_SAVED_URL_SAFE_PASSWORD`. Replace the
  placeholder, restrict the file with `chmod 600 .env`, and keep it out of Git
  (`.env` is ignored). Do not copy another worktree's credentials.
- **Existing trial volume:** use its original saved password in `.env`. Do not
  generate a new password on every startup. A different environment value does
  not rotate an initialized PostgreSQL password. If the original is unavailable,
  stop and decide on recovery or intentional disposal of that trial's data;
  do not automatically delete its volume.

From the repository worktree on the Mac, after saving `.env`:

```sh
python3.13 -m venv .venv
.venv/bin/pip install -r requirements.txt
unset RMM_POSTGRES_PASSWORD # avoid a stale exported value overriding .env
docker compose up -d --build --wait --wait-timeout 60
```

Continue only if that command succeeds and both services are healthy. On failure,
`docker compose ps -a` shows service state; the control plane's sanitized
`database_initialization_failed` can indicate a mismatched persisted password.
Restore the original password and rerun startup. Do not run setup against an
unhealthy service. After successful readiness, create a workspace **once**:

```sh
RMM_ADMIN_KEY="$(docker compose exec -T control-plane python -m control_plane.setup Trial)" && export RMM_ADMIN_KEY
export RMM_API_URL=http://127.0.0.1:18080
.venv/bin/python -m control_plane.client list
cloudflared tunnel --url http://127.0.0.1:18080
```

Setup creates a workspace and its admin key locally, outputs the
key once, and persists only its SHA-256 verification hash. The command substitution
above delivers it directly to the shell; save it in your secret store if needed.
There is no public signup or credential-readback operation. Repeating local setup
creates a separate workspace, not a recovery of the original credential.

The first list must contain no devices. Cloudflared prints a temporary
`https://…trycloudflare.com` URL; retain the matching hostname for this run.
The tunnel exposes only the HTTP/WSS control plane. PostgreSQL has no published
port. API schema: `http://127.0.0.1:18080/docs`.

In a trusted Windows console under the account that will retain the endpoint key:

```powershell
dotnet build src/EndpointAgent -c Release
dotnet src/EndpointAgent/bin/Release/net8.0/EndpointAgent.dll --enroll wss://YOUR-TUNNEL.trycloudflare.com/agent rmm-trial-device
```

1. Observe `PAIRING_CODE` on Windows. The endpoint generates a nonexportable CNG
   P-256 signing key in the launching account's Windows key store. This console
   output is deliberate one-time delivery; do not collect it as an operational
   log. While pending, the device list remains empty.
2. On the Mac run `.venv/bin/python -m control_plane.client approve` and enter the
   code from that trusted Windows view. Expect `approved` plus a stable device
   UUID. The approval HTTP request carries the code in its JSON body.
3. Run `.venv/bin/python -m control_plane.client list`. Within about 15 seconds,
   Windows prints `online` and the list reports `online` with the same UUID.
   Repeat after 15–20 seconds; `last_seen` advances. `approved` means admin
   approval exists but the endpoint has not yet completed a fresh key proof.
4. Stop the Windows agent with Ctrl+C. After 46 seconds, list again: reachability
   is `stale`. Staleness describes missing recent evidence, not device power state.
   Restart with the same account/key name; expect the same UUID and `online`.
5. Try approving the same code again: expect HTTP 409. Remove/change the
   admin environment key and list: expect HTTP 401. A copied code alone
   cannot approve or authenticate a device. A different local key requires new
   admin approval and cannot claim the original UUID.
6. Stop the tunnel when finished and run `docker compose down`. Unset the
   admin environment variable. Keep the endpoint key only if continuing the
   trial; uninstall and recovery approved by an admin belong to later tickets.

An approved key must first activate before the original ten-minute code deadline;
otherwise it reports `approval_expired` and cannot authenticate. There is no key
replacement/recovery operation yet. If the one-time code display is lost, allow
the pending request to expire; reconnect then receives a fresh code. Do not
silently enroll a replacement key as the same logical device.

## Wire and trust contract

`/agent` accepts an outbound WebSocket. The Windows entry point requires `wss`
and normal platform certificate-chain, hostname and expiry validation. A fresh
256-bit nonce starts each connection. The endpoint sends exactly `public_key`
(base64 DER SubjectPublicKeyInfo, P-256) and `signature` (base64 DER ECDSA/SHA-256)
over UTF-8 `rmm-reachability-v1\n` followed by the nonce. The proof is accepted only
on that connection. Canonical public-key encoding is required. No client-provided
device ID or forwarded certificate header establishes identity.

An unknown proven key receives `pending`, a one-time 12-character base32 code,
and `expires_in_seconds: 600`. Reconnecting with that key before expiry returns
`pending` without disclosing the code again. The database binds the code hash
immutably to that public key. Admin `POST /pairings/approve` atomically
consumes a live code and assigns a UUID in the admin's workspace. Pending
keys never appear in device lists and this mode has no execution path.

After approval, a new connection and nonce proof activates the key. `online`
returns the UUID, `heartbeat_seconds: 15`, and `stale_seconds: 45`. The agent
sends only `{"type":"heartbeat"}`; the server acknowledges it. Unknown messages,
including dispatch, are rejected. Reconnect proves the persisted key again;
there are no reusable bearer tokens on Windows. `GET /devices` scopes every row
to the authenticated workspace; `limit` is 1–100 and `after` accepts the prior
`next_cursor` UUID. Reachability is `approved`, `online`, `stale`, or
`approval_expired`. Times come from PostgreSQL, not endpoint claims. A small typed
Python policy classifies each page against one database-supplied `observed_at`:
contact strictly newer than 45 seconds is online; contact exactly 45 seconds old
is stale. Without contact, the activation deadline is expired at equality.
Previously activated devices remain stale/online regardless of that deadline.
Workspace filtering, ordering and pagination remain in PostgreSQL.

The new reachability protocol uses application-level possession proof because a
TLS-terminating development tunnel need not forward client certificates. The
existing pinned-mTLS harness protocol remains unchanged. Cloudflare is a trusted
TLS termination boundary and can see proxied data; this is not end-to-end TLS
to Python. The cloudflared-to-origin hop is loopback HTTP, while cloudflared's
outbound tunnel is encrypted. Bind the origin only to loopback and keep proxy
logs metadata-only. Do not add a forwarded-header authentication fallback.

[Quick Tunnels](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/trycloudflare/)
are temporary development routing without uptime guarantees. Their URL changes
on restart; restart the Windows agent with the new trusted URL and the same key.
They support WebSockets but **do not support SSE**, so this smoke routing does
not establish the later streaming/deployment slice's compatibility.

## Bounds and secret handling

- At most 1,000 unexpired pending keys globally, each lasting ten minutes. Expired
  transient pairing rows are removed on a subsequent initiation; device history
  is not deleted. Pending creation and key activation serialize in PostgreSQL.
- At most 120 agent connection attempts/minute globally, including invalid proof
  attempts; at most 600 admin HTTP requests/minute globally; at most ten
  approval attempts/minute per authenticated workspace. Fixed-window counters
  persist across restarts in `rate_limits` (`scope`, `window_started_at`,
  `attempt_count`), enforced by `enforce_rate_limit()`. HTTP 429 includes
  `Retry-After: 60`; a rejected WS
  handshake returns 403. Global bounds intentionally trade availability under
  attack for bounded resource use in this trial, and are not production DDoS
  protection. No rate identity is taken from spoofable forwarding headers.
- Proof deadline ten seconds; WS text at most 2,048 bytes; heartbeat read deadline
  45 seconds; heartbeats faster than one/second rejected. HTTP bodies require
  Content-Length at most 2,048 bytes and no chunked encoding. Run the documented
  server command with its transport size/concurrency limits.
  This HTTP ceiling fits only #4's tiny approval API: #5 must introduce a larger
  global ceiling and an endpoint-specific script limit before accepting scripts.
  Request-body-limit middleware and sanitized unexpected-error handling are
  separate responsibilities; unexpected HTTP failures return only a generic 503.
  Database connection/statements are bounded to five seconds and lock waits to
  two seconds; failure returns a sanitized unavailable response.
- Admin keys contain 256 random bits. Only their verification hashes and
  pairing-code hashes are persisted. Endpoint private keys stay in Windows CNG;
  possession proofs, codes and authorization headers are not routine logs.
  API validation and database failure responses do not echo request values.
- The CNG key belongs to the launching Windows account. Same-account/SYSTEM code
  may use the key; nonexportability is not a sandbox against privileged scripts.
  Installer/service identity and recovery are deliberately not implemented here.

## Automated verification

With a dedicated local PostgreSQL database and `RMM_DATABASE_URL` configured:

```sh
.venv/bin/uvicorn control_plane.app:app --host 127.0.0.1 --port 18080 --no-access-log --log-level warning --ws-max-size 2048 --limit-concurrency 256
# Another terminal, same RMM_DATABASE_URL:
RMM_EXPIRY_TEST=1 RMM_RATE_TEST=1 .venv/bin/python -m pytest -q tests/control_plane/test_logging.py tests/control_plane/test_pairing.py tests/control_plane/test_reachability.py
# The rate test exhausts the global allowance: wait 60 seconds before
# starting another agent on that test control plane.
```

For the actual authorized Azure Windows VM → tunnel → Mac smoke, first follow
the Compose setup above in the same shell, retaining `RMM_ADMIN_KEY` and
`RMM_API_URL`. Azure CLI must be authenticated to the authorized trial subscription,
and the existing trial VM must be running. No local `RMM_DATABASE_URL` or published
PostgreSQL port is required: this smoke uses only HTTP and the admin key already
created inside Compose. Replace the tunnel hostname with the current trusted URL:

```sh
RMM_WINDOWS_WSS=wss://YOUR-TUNNEL.trycloudflare.com/agent .venv/bin/python -m pytest -q -s tests/control_plane/test_windows.py
bash scripts/azure-smoke.sh
```

The smoke creates one retained device record in that workspace and selects its
UUID, so existing trial devices do not affect its assertions. It removes the test
key afterward; the retained record becomes stale, not a reusable enrollment.
The renamed rate-limit schema assumes a fresh disposable database for this
unmerged slice. Schema migration tooling remains #5 work.

The expiry gate waits the real ten minutes. The Windows integration uses Azure
only to deploy/start/stop an isolated test agent and observe its local code; API
approval stays on the Mac. A temporary SYSTEM scheduled task detaches the agent
from Run Command and is removed afterward. Code-output files and test keys are
removed; source/build files may remain under the unique Windows Temp directory.
The test asserts heartbeat, stale state, and stable UUID after restart. The
independent peer additionally verifies the actual Windows signature,
nonexportability, timing, and refusal of execution messages; all prior worker
contract tests remain in place.

Not covered by manual smoke: replayed nonce proofs, concurrent competing
approvals, cross-workspace reads, request/attempt limits and real code expiry
are automated gates; maximum pending-pool bound and hash-only persistence are
also reviewed in code. Installer/service lifecycle, arbitrary execution,
recovery/revocation, SSE and production deployment remain later tickets.

## Recorded results

On 2026-09-21 the actual Windows 11 trial VM used its generated CNG key to connect
outbound through a free Cloudflare Quick Tunnel to FastAPI on the Mac, backed by
local PostgreSQL. The Mac approved the code observed from the Windows process;
the API reported the device online, its heartbeat advanced, stopping the process
produced stale reachability, and restarting with the same key retained its UUID.
The automated smoke completed successfully in about 4 minutes 22 seconds,
including Azure orchestration and the real stale wait. This proves cross-machine
outbound connectivity; it is not a latency, uptime or later SSE claim.

The public API tests, including a real ten-minute expiry wait, also passed.
The expiry gate rejected both an expired code and an approved key that had not
proved possession again before its activation deadline. No cloud control plane
or new VM was provisioned. The local Compose image built successfully; workspace
authentication also survived a normal restart of both Compose services.
The independent Windows harness passed all original worker scenarios plus fresh
key proofs, nonexportability, 15-second heartbeats, same-key reconnect after a
server Close frame, and refusal of execution messages in enrollment mode.
