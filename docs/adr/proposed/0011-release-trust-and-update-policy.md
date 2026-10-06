# ADR 0011 (proposed): Release trust and update policy

- Status: **Proposed**
- Date: 2026-10-06

## Context
The automatic `privanet.updates` policy covers `update_chat_admin` and `apply_available_updates`. For Chat Admin, "verified" is a SHA-256 from the same origin as the archive; `update.sh` compares only `CURRENT == LATEST` (no downgrade guard), runs the unpacked `deploy.sh` as root, which runs unpinned `pip install`. Core's `privanet-update` already enforces same-series, no-downgrade, lock, backup and rollback.

## Decision
The automatic policy applies only when **all** hold: signature by a host-pinned key independent of the download origin; strictly newer numeric version; same major.minor series and no `requires_approval`/migration flag; dependencies vendored or hash-locked; rate-bounded and single-flight; preflight, snapshot, post-verify and rollback. Anything else is a normal T2 proposal showing release notes. Arbitrary packages and root commands keep T3 authorization.

Policy knob: `updates.policy = auto-patch | approve-all | manual`; Chat Admin self-update may be set stricter.

`get_updates` returns a plan; `apply_updates(plan_id)` applies exactly that plan or returns `PLAN_STALE`. Self-update is a runbook with a persisted resume point and automatic rollback.

## Interim
Until signing exists, `update_chat_admin` requires approval and `update.sh`/`deploy.sh` gain the monotonic/series guard and pinned dependencies. (Narrows 0.3.3 behaviour; needs owner decision.)
