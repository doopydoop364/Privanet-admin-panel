# ADR 0009 (proposed): Operations with proposal-on-first-call and parameter-bound approvals

- Status: **Proposed**
- Date: 2026-10-06

## Context
Scope leases bind (request, scope, expiry) but not the operation: a 60-minute `privanet.nodes` lease covers `approve_node` with any capability list. The model must thread `authorization_request_id` and `confirmation_request_id` through a retry dance, and the card cannot show what will run.

## Decision
A mutating tool called without `operation_id` validates input, runs preflight and creates a **proposal** `{operation_id, kind, target, params, params_sha256, tier, reversible, impact, expires_at}`; the result carries the approval card, rendered from the structured proposal (model prose shown as "Assistant's stated reason"). Approval creates a grant bound to `(operation_id, params_sha256)`, one use, short expiry. Default execution is **Approve & run** server-side; retrying the typed tool with `operation_id` remains supported.

States: `PROPOSED, APPROVED, EXECUTING, SUCCEEDED, FAILED, UNKNOWN, EXPIRED, DENIED, CANCELLED` (+ `VERIFIED`). `UNKNOWN` is reconciled against authoritative state (ADR 0005).

Timed leases survive only as an optional T1 *operator window*; never for T2/T3.

## Consequences
- Removes `request_admin_access`, `request_action_confirmation`, `request_sudo_command` from the model surface (deprecated aliases for one minor release).
- Approval state becomes readable (`get_operation`), fixing the pending/denied/expired blind spot.
