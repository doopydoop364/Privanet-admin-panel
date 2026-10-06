# Proposed amendments to accepted ADRs 0001–0006

Not applied. Apply as short "Amended" sections when agreed.

- **0001** Add: Admin links to, but does not extend, Core's `privanet-admin ui`; Admin reads Core via a scoped read-only credential without root; Admin plans, Core executes node operations.
- **0002** Add invariants: MCP session/transport id is never operator identity; assistant principals never approve; `visibility:["app"]` is advisory; T2+ approvals carry broker-verified step-up proof bound to `(operation_id, params_sha256)`; the automatic `privanet.updates` policy is limited to updates meeting ADR 0011's definition of verified. Replace "partially trusted" wording with what the bridge can and cannot assert.
- **0003** Status → "Accepted direction; blocked on Core proposal" (Core has no management operations today). Add: management-operation registry, owner-enabled execution, coordinator-signed envelope, operation state machine, offline semantics, `UNSUPPORTED_BY_TARGET`, operator-owned vs community nodes.
- **0004** Add: privileged ledger/audit are broker-owned; schema versioning; Admin DB ownership/mode; supersession of the bridge-owned `audit.sqlite3`; loss behaviour per table.
- **0005** Add: broker operation ledger as a precondition; idempotency keys; long-operation start/poll; self-update runbook with persisted resume point; `UNKNOWN` reconciliation.
- **0006** Add three negotiation layers (broker `hello`, Core admin discovery, app `compat.json`), tool-list staleness and alias policy; note that Core discovery does not exist yet.
