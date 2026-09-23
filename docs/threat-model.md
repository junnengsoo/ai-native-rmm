# Threat model

This prototype lets authenticated callers run raw PowerShell on enrolled Windows
devices. Its security goal is not to make arbitrary PowerShell safe. It is to
ensure that only authorized work reaches the intended device, that results belong
to the correct execution, and that failures do not silently repeat side effects.

## Trust boundaries

- **Caller → control plane:** AI drivers and operators authenticate for every
  operation. Caller input, including PowerShell, is untrusted.
- **Technician → enrollment API:** a pending endpoint has no execution authority
  until an authenticated administrator verifies its pairing code through a
  trusted view of the intended machine.
- **Control plane → PostgreSQL:** the database contains device authority, exact
  scripts, output, and audit history. Database credentials stay in the control
  plane.
- **Control plane ↔ endpoint:** the endpoint initiates an outbound WSS connection.
  The peers use individual certificates and pinned fingerprints; no inbound
  endpoint port is required.
- **Endpoint service → PowerShell worker:** scripts run in a separate persistent
  worker owned by the Windows service, currently as `LocalSystem`.
- **Endpoint → control plane/caller:** stdout, stderr, timestamps, and other
  endpoint values are untrusted data. Text resembling protocol messages remains
  output and cannot directly trigger control-plane actions.
- **Endpoint → local ledger:** accepted work, output, and terminal evidence are
  written before network delivery and acknowledged only after PostgreSQL commit.

## Defences implemented

- Callers have separate revocable credentials and role checks. Devices
  authenticate individually; pending enrollments cannot execute work.
- Pairing is short-lived, administrator-approved, and bound to the endpoint key.
  The endpoint later proves possession of the matching private key.
- Dispatch and ingestion validate device, debugging-session, execution, and
  script-hash bindings.
- The endpoint recomputes the submitted script's SHA-256 hash, detecting content
  mismatch or accidental transport corruption.
- Unique execution IDs, durable acceptance records, and idempotent ingestion
  prevent retries or reconnects from running an accepted execution twice.
- The endpoint ledger retains unacknowledged lifecycle and output evidence across
  transient network loss. The active invocation can continue while disconnected.
- Session closure, cancellation, and expiry terminate the worker and its Job
  Object-owned children. A definitive stopped state is reported only after
  cleanup is confirmed; otherwise the outcome is unknown.
- Authentication headers, private keys, database URLs, and full configuration
  objects are excluded from logs and sanitized errors. The worker receives an
  allowlisted environment rather than the agent's complete environment.
- Caller responses contain bounded output previews and pages. If endpoint ledger
  capacity is exhausted, PowerShell continues, output loss is recorded, and
  capacity remains reserved for lifecycle and terminal evidence.

## Known limitation: command provenance

The current hash proves only that the endpoint received the script paired with
that hash. SHA-256 is not authentication: an attacker capable of injecting an
otherwise accepted dispatch could replace both the script and its hash. TLS,
pinned certificates, endpoint authentication, and control-plane authorization
reduce this risk, but dispatches are not independently signed.

A production version should sign a canonical dispatch envelope with an
asymmetric control-plane key. The signature should bind the protocol version,
device ID, session ID, execution ID, script hash, execution profile, and expiry.
The endpoint would pin the public verification key and reject unsigned or invalid
dispatches. Execution-ID deduplication would still prevent replay. This
defence-in-depth feature was deferred to keep the two-day prototype focused on
enrollment, execution, output, and reconnect reconciliation.

## Deferred risks

- **Script guardrails and privilege profiles:** raw PowerShell runs as
  `LocalSystem`. Allowlists, risk classification, human approval, and
  lower-privilege profiles are future work; the authenticated caller currently
  owns the decision to run a script.
- **Rollback and isolation:** arbitrary Windows changes cannot be reliably
  reversed. The agent records evidence but provides no transaction or sandbox.
- **Code signing:** the trial MSI is unsigned. Production installers and binaries
  should be signed through a protected release pipeline.
- **Scale and availability:** the prototype supports one control-plane process,
  one active session, and one active execution per endpoint. Multi-instance
  routing and concurrency are deferred.
- **Production bootstrap and rotation:** the prototype uses technician approval.
  An MSP could later use an existing RMM's authenticated device identity.
  Automated credential rotation and hardware attestation are not implemented.
- **Ledger hardening:** pruning acknowledged data during a long-lived session and
  embedding the ledger generation ID in every record remain future improvements.
- **Sensitive diagnostic output:** platform credentials are protected, but an
  arbitrary script can print host secrets. Production needs appropriate output
  access, encryption, retention, and redaction policies.

These limitations are explicit so the prototype does not claim guarantees it
does not provide. Its demonstrated guarantees are authenticated enrollment,
correlated non-duplicating execution, structured evidence, and reconciliation
after transient network loss.
