# ADR 0008 (proposed): Principals, approver authority and risk tiers

- Status: **Proposed**
- Date: 2026-10-06

## Context
Audit records a random per-session token as `session`. `visibility:["app"]` is the only thing separating requesting from approving, and the server does not enforce it (verified: a local HTTP client self-approved scoped leases; design doc Appendix A).

## Decision
1. Every request carries a **principal**: `assistant` (MCP connector, identified by configured connector id), `operator` (panel login), `local-root` (unix socket peer credential), `system` (runbook engine inside an approved plan).
2. An MCP transport/session identifier is **never** an operator identity and never part of an authorization decision. It is kept only as informational `client_session`.
3. `assistant` and `system` principals can never approve. Approval requires `operator` or `local-root`.
4. Risk tiers: T0 observe; T1 routine/reversible (card click allowed, optional operator window); T2 impactful (exact-params approval, one use, step-up proof verified **by the broker**, never timed); T3 root-equivalent (exact command/package, TOTP, one use, short window). Existing scope names remain the broker vocabulary.
5. `visibility:["app"]` is UI metadata only and is never a trust root.

## Consequences
- The broker must verify approver proof itself; a compromised bridge can relay but not forge T2/T3 approvals.
- T1 keeps a weaker, host-attested path by design; it is limited to low-impact reversible operations.
- Single operator (`owner`) now; `operator_id` is in the schema for multi-operator later (roadmap Q14).
