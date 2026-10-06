# Proposal for PrivaNet Core: management operations and scoped admin credentials

- Status: **Draft for the Core repo** (not applied there). Written from the Chat Admin side; Core owns the final design.
- Reviewed against PrivaNet-Core `dd13928` (0.4.0-alpha.4). Protocol stays `1`; every change is additive and optional, per Core's compatibility rules.

## Verified starting point
- Admin routes today: applications, enrollment-tokens, invites, nodes (list/show/revoke/rename), requests, storage, storage key rotate. No drain, maintenance, slots, restart, update or diagnostics operation.
- One `PRIVANET_ADMIN_SECRET`; no scoped or read-only admin credential.
- Node views carry `daemonVersion`, `protocolVersion`, `capabilities`, `jobSlots`, `currentJobs`, optional `resources`, `lifecycle`, `services`. `/v1/capabilities` is application-scoped.

## Proposed additions
1. **Scoped admin credentials**: read, node-ops, enrollment, storage. Admin uses read for observation (no root needed).
2. **`GET /v1/admin/capabilities`**: coordinator version, protocol, admin feature flags, management-operation registry and versions.
3. **Management-operation registry** (closed, versioned, schema-validated, lockstep-tested, like `JOB_TYPES`/`SERVICES`). v1 kinds: `node.drain`, `node.resume`, `node.maintenance.enter|exit`, `node.slots.set`, `node.diagnostics.collect` (bounded, redacted), `node.restart.request`, `node.update.request`. No kind accepts a command, path, URL or script.
4. **Operation envelope and state machine**: `{id, kind, params, idempotency_key, expires_at}` enqueued by admin API, delivered in the heartbeat response, acked `ACCEPTED|REJECTED(reason)|COMPLETED|FAILED`, states queryable by id, `EXPIRED` when undelivered. Coordinator-signed with nonce/expiry (reuse of the existing ticket-signing key and verification route is plausible; Core must confirm).
5. **Owner sovereignty**: a node runs a kind only if its owner enabled it locally; kinds can be granted or withheld at enrollment/approval via the existing capability ceiling. Operator-owned nodes get full management; community nodes none or drain-only.
6. **Heartbeat advertisement** (additive): management kinds supported and enabled.
7. **`on-behalf-of` audit field** so Core's log can name the Admin principal and approver.

## First vertical slice
`node.drain` / `node.resume` and `node.slots.set`, with mixed-version tests in the style of `compat-previous-release.test.ts` (older node/coordinator must ignore or report unsupported, never fail).

## Non-goals
Remote shell, file transfer, arbitrary update URLs, application-specific policy in Core (ADR 005).
