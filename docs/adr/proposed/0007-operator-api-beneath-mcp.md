# ADR 0007 (proposed): A versioned Operator API sits beneath MCP

- Status: **Proposed** (see docs/design/0.4-operator-plane.md §3.1)
- Date: 2026-10-06

## Context
Today every capability is an MCP tool backed by one `AdminBackend` (agent/core.py). A panel or CLI would have to re-implement logic or call MCP. Roadmap questions 1 and 13 ask whether Admin should be MCP-only.

## Decision
Admin exposes a versioned **Operator API** (`/v1`, additive-only within a version, OpenAPI-described) implemented by one in-process service layer. MCP tools, a web panel and a CLI are thin adapters over it. Transports: in-process (MCP), unix socket (CLI, `SO_PEERCRED`), loopback HTTP (panel). The existing `:8787/mcp` endpoint and tunnel configuration are unchanged.

The Operator API is not a proxy of Core's admin API. Admin owns policy, approvals, history and orchestration (ADR 0001); Core remains the source of live network facts.

## Consequences
- No MCP-only business logic; `core.py` is split by domain behind the service layer.
- Reads use a scoped Core read credential and do not need the root broker (requires the Core proposal).
- Client compatibility is governed by the API version header and ADR 0013.

## Rejected
- MCP-only Admin: no persistent UI, no strong approver channel.
- Extending Core's `privanet-admin ui`: couples release trains, violates ADR 0001.
