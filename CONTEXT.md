# Endpoint execution

An execution service through which authorized callers investigate and change managed Windows devices. The caller decides whether an IT problem is resolved; execution records describe what happened to submitted scripts.

## Language

**Device**:
A managed Windows machine with a stable logical identity and retained execution history, independent of a particular agent installation.
_Avoid_: Session, agent installation as synonyms for device

**Endpoint agent**:
The deterministic software on a device that accepts authorized work and reports execution evidence.
_Avoid_: AI agent

**Caller**:
An authenticated application or operator requesting operations within its granted permissions.
_Avoid_: Client when it could mean the Windows device

**AI driver**:
The demonstration caller that uses an LLM to choose diagnostic commands and interpret their results.

**Control plane**:
The authority for device enrollment, caller permissions, debugging sessions, and execution records.
_Avoid_: Controller plane

**Debugging session**:
One investigation on one device, with a persistent PowerShell environment and fixed execution privileges shared by its successive executions.
_Avoid_: Connection as a synonym for session

**Execution**:
One accepted script submission with its own identity, lifecycle, captured output, and result, belonging to a debugging session.
_Avoid_: Session as a synonym for execution

**Pairing**:
The technician-authorized binding of a pending endpoint key to a device identity after verification through a trusted view of that machine.

**Pending enrollment**:
An unapproved request to bind an endpoint public key to a device; it is not yet a trusted managed device and has no execution authority.

**Awaiting activation**:
An approved device whose endpoint key has not yet completed its first post-approval possession proof. Approval is already implied by the device's existence.
_Avoid_: Approved as an ongoing device state

**Device reachability**:
The freshness of authenticated contact from a device, reported as online when recent or stale when recent evidence is absent. It is independent of the device's authorization status and does not assert whether the machine itself is powered on or connected.
_Avoid_: Offline

**Device authorization status**:
An administrator-controlled device state that records whether its execution authority is active or revoked, independent of reachability.

**Technician recovery**:
An authorized replacement of a device's agent credential after reinstall, preserving the existing device identity and history.

**Execution profile**:
The Windows privilege configuration under which a debugging session's commands run.
_Avoid_: Safe mode or read-only mode unless those guarantees are enforced

**Invocation outcome**:
The observed manner in which a submitted PowerShell invocation ended, distinct from whether the underlying IT problem was resolved.

**Endpoint ledger**:
The endpoint agent's durable append-only record of accepted session/execution lifecycle, retained output chunks, output-loss markers, and terminal evidence. The control plane acknowledges only the contiguous records committed to PostgreSQL.

**Output preview**:
The limited portion of retained execution output returned initially to a caller.

**Capture truncation**:
Loss of emitted output because it exceeds the retention boundary, distinct from merely hiding retained content behind a preview.

**Output completeness**:
Whether the endpoint believes retained output evidence is complete. `output_complete: false` means output was explicitly lost, such as endpoint ledger capacity exhaustion, even if the invocation's terminal result was preserved.
