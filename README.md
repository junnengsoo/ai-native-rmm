# AI-Native RMM

Two-day work-trial project: a Windows endpoint agent and control plane designed for an AI operator.

## Project documents

- [Software spec and implementation tickets](https://github.com/junnengsoo/ai-native-rmm/issues/1) — authoritative agreed scope, dependencies, and open assumptions
- [Delivery and operations checklist](https://github.com/junnengsoo/ai-native-rmm/issues/2) — submission and trial cleanup obligations
- [Domain glossary](CONTEXT.md) — shared terminology
- [Windows test environment](docs/windows-test-environment.md) — existing VM access and operating constraints
- [Original assignment](https://squash.ai/interview-projects/ai-native-rmm)

## Status

Slices 1–2 provide the Windows execution harness plus PostgreSQL-backed technician
pairing and device reachability. Start with [local pairing and smoke test](docs/enrollment.md)
or the [independent Windows harness](docs/agent-harness.md). Enrollment mode is
reachability-only; the installer and public session/execution API are later slices.

The default control-plane setup is local Python/PostgreSQL with Docker Compose and a development HTTPS/WSS tunnel. Cloud control-plane hosting is optional. Current implementation status is tracked in GitHub, not duplicate local planning notes.
