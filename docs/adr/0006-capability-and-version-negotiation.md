# ADR 0006: Admin discovers supported operations and versions; it does not assume a homogeneous fleet

- Status: Accepted for 0.4 planning
- Date: 2026-10-06

## Context

Real deployments will temporarily contain mixed Coordinator, node, Search, Proxy, Drive, and Admin versions. 0.4 remote administration must not assume that every target supports every newly added operation.

## Decision

Core/node management operations will be versioned and discoverable.

Admin should determine support from advertised capabilities/protocol information before offering or executing a mutation. Unsupported operations return a structured unsupported/compatibility result.

Update orchestration must use an explicit compatibility model rather than simple lexical version comparison.

New management protocol fields and operations should be additive when practical. Breaking changes require an explicit protocol/version transition and migration path.

## Consequences

- mixed-version fleets become an expected condition, not an exceptional one;
- the persistent Admin UI and MCP tools can explain why an operation is unavailable;
- staged/canary updates can be implemented without requiring lock-step upgrades of every node.
