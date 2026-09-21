# AI-Native RMM — Project Brief

> Working notes derived from the [original Squash assignment](https://squash.ai/interview-projects/ai-native-rmm). This is a structured paraphrase for project use; consult the original page if wording matters.

## Project summary

Build a standalone execution channel for Windows endpoints consisting of:

1. A Windows endpoint agent and unattended installer.
2. A control plane.
3. An API intended to be used by an AI agent.

Squash resolves IT support tickets for managed service providers (MSPs). Many tickets require investigating or fixing a laptop, desktop, or server. Existing remote monitoring and management (RMM) products are optimized for human technicians using graphical interfaces and pre-uploaded scripts. This project explores an RMM execution layer designed around an AI operator instead.

## Product context

Existing RMM systems create several limitations for AI-driven troubleshooting:

- Scripts often have to be added to a library by a human before execution.
- Some systems do not return a unique execution identifier, making runs and outputs hard to correlate.
- Results are presented for human consumption rather than reliable machine parsing.
- Even simple, sequential diagnostics can take minutes because APIs rely on slow dispatch-and-poll cycles.

The proposed system should enable fast, safe, attributable execution of dynamically supplied PowerShell.

## Product boundary

Design for one API consumer: an AI agent diagnosing and resolving endpoint problems.

The following are explicitly outside scope:

- Chat interface
- Approval workflow
- Technician dashboard
- Patch management
- Antivirus
- Remote desktop

The calling application is responsible for approvals, presenting audit information, and AI reasoning. This project owns the execution layer beneath it. Code may run on an enrolled endpoint only through an authenticated control-plane request, and the executed content must match the submitted content.

This is a focused prototype, not a complete commercial RMM.

## Required system

### 1. Windows endpoint agent and installer

Provide one unattended installer suitable for deployment using an MSP's existing tooling.

The installation flow must:

- Enroll the device.
- Require no interactive setup.
- Install an agent that runs without a signed-in user.
- Start automatically and continue working across reboots.
- Uninstall cleanly.

Assume every endpoint is behind NAT and cannot receive an inbound connection from the control plane. The device therefore initiates the connection. Low-latency delivery over that outbound connection is a central design decision and should be explained.

The endpoint agent should remain simple and deterministic. It receives jobs, executes them, and returns results; it should not contain AI decision-making.

### 2. Control plane and API

Exact routes and schemas are open-ended, but the API must clearly expose the following capabilities.

#### Enrollment

- A device can enroll itself once and is recognized thereafter.
- Possession of installer enrollment material must not provide permanent access.
- The same enrollment material must not allow an attacker to enroll an arbitrary device of their own.
- Each device receives a stable identity that survives reinstalling the agent.

#### Device listing and presence

- List enrolled devices.
- Report whether each device is currently reachable.

#### Script execution

- Accept raw PowerShell source, rather than a reference to a pre-registered script.
- Return a handle for the specific execution immediately instead of blocking for completion.
- Reliably associate results with the originating request.
- Ensure retries or duplicate dispatches cannot execute a script more than once.

#### Execution status and results

- Expose the current state and terminal outcome of every job.
- Represent the case where a device was never reachable.
- Represent script timeout separately and reliably.
- Return structured results containing at least:
  - Exit code
  - Standard output
  - Standard error
  - Execution duration
- Bound captured output.
- Indicate explicitly when output was truncated.
- Guarantee that every job eventually reaches a terminal state, even if an endpoint hangs or disappears.

#### Authentication and audit

- Authenticate API callers.
- Authenticate endpoint agents individually.
- Make devices revocable.
- Retain every execution record.
- Store the exact script submitted as part of the audit record.

### 3. Speed

Sequential, dependent commands on an online endpoint should each complete a full request/result round trip in roughly two seconds or less. This enables interactive diagnosis where each next command is selected using the previous result.

A long polling interval will not satisfy this requirement. The implementation may use fast individual executions or introduce a session abstraction, but the choice should be explained.

## Security expectations

- No unauthenticated path—caller-side or agent-side—may cause code execution.
- Every device must have an individual identity and support revocation.
- Enrollment credentials must not become standing credentials.
- The executed script must be verifiably identical to the script dispatched.
- Treat all endpoint data, including script output, as untrusted input.
- Endpoint output must never be interpreted as instructions that trigger control-plane actions.
- Do not expose secrets in logs, persisted output, or error messages.
- Do not allow a hung endpoint to leave a control-plane job permanently unfinished.

Include a concise threat model covering:

- Trust boundaries
- Threats addressed
- Deferred threats
- Reasons and tradeoffs behind deferrals

## Required demonstration

Record a video showing all of the following.

### Installation and enrollment

Install the agent on a Windows machine or virtual machine, then show the endpoint as online in the control plane.

### End-to-end script execution

Submit a script through the API and show the returned structured result.

### Failure handling

Demonstrate:

- A script that exceeds its timeout.
- Dispatch to an offline device.

### Multi-step diagnosis

Show a sequence where later commands depend on earlier results. One suggested scenario is tracing a network-connectivity problem by examining the network adapter, testing the gateway, testing a target, and narrowing down the failure.

Display the elapsed time for every step.

### Minimal AI driver

Build a small agent loop using any LLM API. It should accept a plain-English endpoint problem, use the RMM API to investigate, interpret results, and report its findings. A terminal interface and transcript are sufficient.

Example prompts include:

- “This machine feels slow.”
- “Why can't this machine reach the file server?”

## Optional extra credit

If core requirements are complete, implement and demonstrate one or two of these additions.

### Device inventory

Maintain API-accessible endpoint information without requiring an on-demand script, including OS version/build, hardware, installed software, and last boot time.

### File transfer

Support bounded, audited upload to and download from an endpoint, such as distributing an installer or retrieving a log archive.

### Reboot handling

Request a restart through the API and follow the endpoint through disconnection and reconnection. Include detection of an already-pending reboot.

### Event log access

Query Windows event logs using time and severity filters and return structured entries.

## Environment and expenses

- Use a Windows 10 or Windows 11 spare machine or VM.
- Microsoft evaluation VM images are acceptable for local use.
- Squash offers a prepaid virtual card for cloud Windows VM and LLM API expenses if required.

## Deliverables

Send the following to `karthik@squash.ai`:

1. **Source archive** — a ZIP of the complete project; retain `.git` if Git was used.
2. **Demo video** — the walkthrough described above.
3. **Setup instructions** — sufficient for a reviewer to go from the ZIP to an enrolled device in less than 30 minutes.
4. **Design notes** — one to two pages covering the connection model, job lifecycle, device identity, and likely next steps.
5. **Threat model** — one to two pages covering the required security analysis.
6. **Build-process note** — AI tools used, how the work was divided, and approximate time spent.

Questions are encouraged when requirements are ambiguous.

## Evaluation order

The submission will be evaluated in this order:

1. **Working system** — installation, enrollment, script execution, and correct structured results.
2. **Security** — whether an MSP could reasonably trust the design around customer endpoints.
3. **Speed** — genuinely fast multi-step diagnosis.
4. **Reliability** — correct offline, timeout, retry, idempotency, and output-limit behavior.
5. **API design** — understandable boundaries and documentation that permit integration without redesign.
6. **Code quality** — clarity, maintainability, and extensibility.

## Submission contact

Karthik — `karthik@squash.ai`
