# ADR 0003: Remote node administration is typed and coordinator-mediated

- Status: Accepted for 0.4 planning
- Date: 2026-10-06

## Context

External PrivaNodes should not require inbound ports, a VPN, or direct SSH connectivity for normal administration. Nodes already maintain an authenticated relationship with the Coordinator.

## Decision

Remote-node administration will use **typed, versioned, capability-scoped operations mediated by the Coordinator**.

Initial operations may include inspection, drain/resume, job-slot policy, maintenance mode, bounded diagnostics, daemon restart requests, and verified update requests.

The protocol must not introduce a general arbitrary remote shell.

The first implementation may use queued/polled management operations over the node's existing outbound relationship. A persistent control stream may be introduced later if latency requirements justify it.

## Consequences

- remote administration works through NAT without opening worker-node inbound ports;
- Core owns protocol schemas, authentication, replay protection, compatibility, and authoritative operation state;
- Admin owns the higher-level plan that decides when those operations should be used;
- unsupported operations must be reported as unsupported rather than simulated through hidden SSH/shell fallbacks.
