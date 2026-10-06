# ADR 0012 (proposed): Broker protocol v2 — still minimal, now verifiable

- Status: **Proposed**
- Date: 2026-10-06

## Decision
The root broker stays a typed-operations executor with no diagnosis or orchestration logic. Changes:
- `hello` handshake: version, protocol, supported operation kinds, 2FA configured, tier policy.
- Grants bound to `(operation_id, params_sha256)`; broker verifies approver proof for T2/T3 (TOTP now, optionally WebAuthn later).
- Concurrent connections; long operations are start/poll with per-operation client timeouts so approvals are never blocked.
- Operation ledger `{operation_id, kind, params_sha256, state, times, result_digest}` enabling ADR 0005 reconciliation.
- Hash-chained privileged audit including principal, approver/method and redacted params (e.g. node capabilities granted).
- Config apply by hash: Admin stages a candidate, broker checks the approved SHA-256, runs the per-target validator, installs atomically, keeps a rollback copy.
- Reads of Core go through a scoped read credential, not the root CLI.

## Interim hardening (0.3.x)
Authenticate the MCP endpoint with a connector token the sandbox user cannot read; restrict sandbox loopback; require TOTP/local-root for `privanet.nodes` and `system.packages` grants until bound approvals ship.
