# ADR 0004: Admin has its own SQLite state, but Core remains authoritative for live network state

- Status: Accepted for 0.4 planning
- Date: 2026-10-06

## Context

A management plane needs durable information that does not belong in the Core scheduler database: approval policy, correlated audit history, runbook progress, configuration history, update attempts, backup catalog metadata, and eventually operator identities.

Duplicating authoritative node/job state would create consistency problems.

## Decision

PrivaNet Admin will use its own durable database, initially SQLite.

Admin-owned state may include:

- authorization policy and approval records;
- runbook instances and checkpoints;
- audit correlation metadata;
- configuration history and rollback metadata;
- update/deployment history;
- backup catalog metadata;
- diagnostic history;
- future operator identity/role data.

Admin will not treat its database as authoritative for whether a node currently exists, is online, or is running a job. Those facts come from Core and the relevant application APIs.

## Recovery property

If the Admin database is lost, PrivaNet Core must continue operating. Loss of Admin state may lose history/policy/runbook progress, but must not corrupt the live network control plane.
