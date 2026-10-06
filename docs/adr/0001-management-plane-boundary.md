# ADR 0001: PrivaNet Admin is the management plane, not the Core control plane

- Status: Accepted for 0.4 planning
- Date: 2026-10-06

## Context

PrivaNet Core already owns the network control plane: node identity, enrollment, authentication, capabilities, heartbeats, scheduler state, jobs, leases, resource policy enforcement, and coordinator-to-node protocol behavior.

Chat Admin needs to grow beyond a collection of local MCP tools without duplicating or replacing those responsibilities.

## Decision

PrivaNet Admin will be a separate **management/operator plane** layered above PrivaNet Core.

Core owns authoritative network facts and mechanisms. Admin owns operator policy, approvals, diagnosis, orchestration, runbook state, update planning, backup orchestration, and cross-application correlation.

ChatGPT/MCP is a client of the Admin service, not the authority that defines PrivaNet state.

The local root broker remains a separate minimal privileged process. It executes narrowly validated privileged operations; it does not contain diagnosis or orchestration logic.

## Consequences

- Core remains usable without Chat Admin.
- Admin can eventually support clients other than ChatGPT, such as a web UI or CLI.
- Admin must query Core for live authoritative node/job state instead of maintaining a competing copy.
- Cross-application reasoning belongs in Admin adapters, not in Core.
- PrivaSearch, PrivaProxy, and PrivaDrive remain separate applications; Core must not learn application-specific policy such as crawler frontier semantics.
