# ADR 0005: Mutating workflows are checkpointed, idempotent where possible, and verified after each risky step

- Status: Accepted for 0.4 planning
- Date: 2026-10-06

## Context

0.4 will introduce multi-step workflows such as draining and updating a node. Nodes, services, the Coordinator, or the Admin process may disappear mid-operation. Blind retry can duplicate destructive work; assuming success can leave the deployment in an unknown state.

## Decision

Admin runbooks will be explicit state machines with durable checkpoints.

Each mutating step should define:

- a stable operation/runbook ID;
- preconditions;
- whether the step is idempotent;
- timeout and retry policy;
- observable success criteria;
- post-step verification;
- rollback/compensation behavior where actually possible;
- an explicit UNKNOWN/NEEDS_OPERATOR state when safety cannot be established automatically.

A timeout is not success. A lost connection after sending a command must be reconciled against authoritative state before retrying.

Rollback must never be promised for operations that are not genuinely reversible.

## Initial vertical-slice expectations

For drain/resume and job-slot changes, Admin should be able to resume a runbook after its own restart and determine whether the requested state was already reached before issuing another mutation.
