# PrivaNet Chat Admin Roadmap

> **Status: planning / subject to change**
>
> This roadmap is intentionally not a fixed implementation contract. The goal is to record the current direction for the rest of the **Chat Admin 0.3.x** line and the proposed **Chat Admin 0.4.0** architecture while the project is still being brainstormed.
>
> **Versioning note:** Chat Admin has its own release train. **Chat Admin v0.4.0 is separate from PrivaNet Core v0.4.0.**

## Product direction

The working split is:

- **0.3.x:** finish the security, authorization, diagnostics, deployment, and operator-UX foundation.
- **0.4.0:** turn Chat Admin from a collection of local administration tools into a capability-aware operator control plane for the wider Priva ecosystem.

A core design principle remains:

> ChatGPT may be given useful shell and administration capabilities, but it must not automatically receive unrestricted root or unrestricted remote-node control.

---

# 0.3.x — Finish the local administration foundation

Current published baseline: **0.3.2**

0.3.x should remain focused on making the existing local-server administration model dependable, understandable, and safe. Major new distributed-control protocol work should generally be deferred to 0.4.0.

## 0.3.3 — Approval UX

Primary goal: make privilege requests feel deliberate and difficult to overlook.

Planned work:

- strengthen fullscreen preference metadata where supported by the ChatGPT host
- explicitly request fullscreen after the MCP App connects when the host advertises support
- provide an **Open fullscreen** user action as a fallback
- improve mobile layout
- clearer states for:
  - pending approval
  - approved
  - denied
  - expired
  - consumed
  - invalid request
- make one-shot versus timed approval visually obvious
- clearly display requested scope, reason, target, duration, and risk level
- preserve a safe inline fallback if the host refuses fullscreen

Constraint:

- ChatGPT ultimately controls how MCP App views are rendered. The app may request fullscreen, but it cannot assume the host will grant it.

## 0.3.4 — Operator diagnostics

Primary goal: answer common operational questions without requiring shell exploration.

Planned tools/features:

- `get_privanet_summary`
- `diagnose_node`
- node heartbeat and version-drift warnings
- resource-pressure summary
- job-slot / current-job context
- service health correlation
- cleaner updater current-state versus historical-log separation
- richer PrivaSearch summary:
  - crawler state
  - queue/frontier state
  - failures
  - duplicates
  - throughput
  - domain concentration
  - recrawl health
- actionable warnings rather than raw telemetry dumps

Desired diagnosis output shape:

- likely cause
- supporting evidence
- impact
- safe next action
- privilege required

## 0.3.5 — Safe administration polish

Primary goal: cover common administration tasks with structured tools before falling back to shell/sudo.

Planned work:

- `get_node`
- `rename_node`
- revoked-node filtering and clearer node-state presentation
- structured configuration inspection
- service dependency diagnostics
- improved bounded command-output handling
- optional output artifact/download behavior for large diagnostic results
- better error codes and operator-facing explanations
- clearer distinction between:
  - read-only tools
  - normal unprivileged shell
  - scoped privileged operations
  - 2FA sudo

Important limitation:

- remote node operations must not be invented where PrivaNet Core does not yet expose a real protocol/API.

## 0.3.6 — Security hardening

Primary goal: aggressively test and tighten the privilege boundary introduced in 0.3.x.

Planned work:

- approval replay tests
- expired-capability tests
- wrong-scope tests
- wrong-target tests
- one-shot consumption tests
- TOTP replay protection tests
- TOTP brute-force/rate-limit tests
- root broker socket permission tests
- malformed broker message fuzzing
- shell timeout/process-group termination tests
- output-size/resource-limit tests
- environment sanitization tests
- secret-redaction tests
- installer permission/ownership tests
- verify the bridge cannot modify broker code/config
- verify the shell user cannot modify root-executed Priva binaries/configs
- audit integrity improvements for privileged operations

The general sudo model should remain:

- exact command is recorded before approval
- explicit user approval
- TOTP required
- one-shot execution
- short expiry
- no interactive stdin
- sanitized/empty environment
- fully audited
- no reusable root shell

## 0.3.7 / 0.3 release candidate — Deployment and migration polish

Primary goal: prove 0.3.x is safe to install and upgrade in realistic deployments.

Planned validation:

- clean install on a fresh machine
- upgrade from 0.2.x
- upgrade from early 0.3.x releases
- rollback testing
- broker/bridge restart behavior
- authorization invalidation after restart where appropriate
- recovery from broken config
- recovery from failed update
- service ordering/startup tests
- plugin/tool-schema refresh documentation
- installer idempotency
- documentation cleanup
- end-to-end operator acceptance test

## Definition of done for 0.3

0.3.x should be considered complete when:

- approvals work even when ChatGPT changes MCP session IDs between tool calls
- normal shell remains unprivileged
- TOTP sudo is reliable, exact-command-bound, short-lived, and one-shot
- no root/TOTP/API secret material is exposed to ChatGPT
- update and rollback are dependable
- common diagnostics are available as structured tools
- most normal operations do not require manual shell commands
- mobile approval UX is as strong as the host permits
- clean-install and upgrade-install paths both pass end-to-end tests

---

# 0.4.0 — PrivaNet operator control plane

## High-level goal

0.4.0 should evolve Chat Admin from a local admin bridge into a capability-aware operator layer for the entire Priva deployment.

A useful headline:

> **0.3: safe local server administration from ChatGPT**
>
> **0.4: safe administration of the wider PrivaNet deployment from ChatGPT**

0.4.0 will likely require coordinated work in both **Chat Admin** and **PrivaNet Core**.

## 1. Real remote-node administration

PrivaNet Core should gain a real authenticated coordinator-to-node administration protocol instead of relying on SSH or pretending unsupported operations exist.

Potential node capabilities:

- `node.inspect`
- `node.configure`
- `node.maintenance`
- `node.update`

Potential operations:

- inspect detailed resource state
- set/clear job-slot override
- change resource policy
- enter/leave maintenance mode
- drain active jobs
- request node daemon restart
- request node update
- rename node
- disable/re-enable scheduling
- collect a bounded diagnostic bundle

Design rule:

- no arbitrary remote shell by default
- every remote operation should be typed, capability-scoped, authenticated, bounded, and auditable

## 2. Deployment-wide summary

A single operator call should summarize the stack:

- coordinator
- nodes
- node versions
- node resource pressure
- current jobs / slots
- PrivaSearch
- PrivaProxy
- PrivaDrive when present
- update state
- storage
- backups
- active warnings

Warnings should be actionable and prioritized rather than merely informational.

## 3. Diagnosis engine

Proposed tools:

- `diagnose_privannet`
- `diagnose_node`
- `diagnose_search`
- `diagnose_service`

The engine should correlate:

- systemd state
- recent bounded logs
- coordinator state
- node heartbeats
- protocol compatibility
- daemon versions
- job/slot state
- CPU/RAM/disk pressure
- updater state
- crawler/search state
- recent admin actions

Output should identify:

- likely cause
- evidence
- impact
- recommended safe fix
- approval/privilege requirement

## 4. Structured configuration management

Normal Priva configuration changes should not require sudo + shell text editing.

Proposed flow:

- `get_config`
- `propose_config_change`
- render a structured diff
- explicit approval
- `apply_config_change`
- automatic validation
- automatic rollback copy
- `rollback_config_change`

Potential managed targets:

- Core coordinator
- local/remote node policy
- PrivaSearch
- PrivaProxy
- PrivaDrive
- Chat Admin itself

This should not become an arbitrary `/etc` editor.

## 5. Safe runbooks

Common multi-step workflows should become explicit, resumable runbooks.

Examples:

- `update_priva_stack`
- `repair_unhealthy_service`
- `drain_and_update_node`
- `backup_and_upgrade`
- `diagnose_search_crawler`
- `rotate_privanet_credentials`

Runbooks should expose progress such as:

1. preflight
2. backup
3. drain
4. apply
5. restart
6. verify
7. rollback if verification fails

Privilege boundaries must still be enforced at each necessary checkpoint.

## 6. More expressive authorization policy

Potential scope tiers:

### Read-only

- `system.inspect`
- `node.inspect`
- `search.inspect`

### Operator

- `privanet.services`
- `node.configure`
- `privanet.updates`
- `privanet.config`

### High-risk

- `node.revoke`
- `credential.rotate`
- `backup.restore`

### Root

- `system.sudo`
- exact-command + TOTP only

Potential policy features:

- view active approvals
- revoke approvals
- show remaining lifetime
- one-shot / N-use / timed leases
- maximum-duration policy
- per-scope requirement for TOTP
- require TOTP for selected high-risk operations even when they are not raw sudo

Example configurable policy:

- service restart -> normal approval
- node revoke -> TOTP
- credential rotation -> TOTP
- backup restore -> TOTP
- arbitrary sudo -> exact-command + TOTP

## 7. Audit timeline

The audit experience should become an operator timeline rather than only raw entries.

Correlate:

- ChatGPT request
- approval request
- user decision
- broker authorization
- exact operation
- result
- verification
- rollback if any

Privileged audit records should remain protected from modification by the unprivileged bridge account.

## 8. Persistent PrivaNet Admin app view

Chat should remain the primary interface, but 0.4.0 can add a persistent visual operator surface for information that benefits from a dashboard.

Possible areas:

- overall health
- node list
- search/crawler status
- updates
- active approvals
- audit timeline
- backup state
- runbook progress

The UI should complement natural-language administration rather than replace it.

## 9. First-class update orchestration

0.4.0 should understand the full Priva ecosystem and compatibility relationships.

Potential managed applications:

- PrivaNet Core coordinator
- nodes
- PrivaSearch
- PrivaProxy
- PrivaDrive
- Chat Admin

Planned behavior:

- dependency-aware ordering
- compatibility matrix
- pre-update backup
- node draining
- canary/staged node rollout
- post-update health verification
- automatic rollback on failed verification
- release-note summary before approval

Long-term operator command:

> Update PrivaNet everywhere.

The implementation should still expose and verify every significant stage rather than hiding a risky monolithic operation.

## 10. Backup and recovery

Proposed operations:

- `create_backup`
- `list_backups`
- `verify_backup`
- `restore_backup`

Potential backup scope:

- Core state
- enrollment/node records
- service configs
- PrivaSearch SQLite
- PrivaProxy state
- PrivaDrive metadata/config where appropriate
- Chat Admin configuration

Restore should be treated as high risk and likely require TOTP.

---

# Proposed 0.4 implementation phases

## Phase 1 — Control-plane protocol

Primarily PrivaNet Core work:

- remote-node admin message types
- authenticated capability model
- maintenance/drain/update operations
- compatibility/version negotiation
- protocol tests
- replay protections
- bounded result transport

## Phase 2 — Chat Admin backend

- broker support for new capabilities
- remote-node tools
- structured config manager
- diagnosis engine
- policy scopes
- richer authorization metadata

## Phase 3 — Operator workflows

- deployment summary
- runbooks
- update orchestration
- backup/recovery
- rollback workflows

## Phase 4 — App UI

- persistent Admin view
- approvals UI
- nodes view
- audit timeline
- update/runbook progress
- stronger fullscreen approval behavior where host support permits

## Phase 5 — Hardening and real-deployment validation

- malicious/misbehaving node tests
- privilege-boundary fuzzing
- mixed-version deployments
- interrupted updates
- unreachable nodes
- corrupted state
- rollback failures
- backup restore verification
- three consecutive complete audit passes with no new actionable findings before calling the release stable

---

# Explicit non-goals / guardrails

Unless revisited deliberately during planning:

- no automatic unrestricted root shell
- no permanent reusable sudo token
- no root password exposed to ChatGPT
- no TOTP enrollment secret exposed to ChatGPT
- no arbitrary remote shell on worker nodes by default
- no pretending unsupported Core APIs exist
- no writable access for the unprivileged Chat Admin account to root-executed application binaries
- no silent destructive actions
- no treating an MCP UI button as the sole security boundary without broker-side validation
- no dependency on VPN/WireGuard for normal external-node administration

---

# Open questions for brainstorming

These are intentionally unresolved and should be discussed before 0.4 implementation begins.

1. Should Chat Admin remain mostly an MCP interface, or become a broader standalone operator service that MCP connects to?
2. How much logic belongs in Chat Admin versus PrivaNet Core?
3. Should remote-node administration use coordinator-mediated RPC only, or also support node-initiated management channels?
4. What should happen when the coordinator is offline but an operator needs to inspect a node?
5. Which non-sudo actions deserve mandatory TOTP?
6. Should approvals be tied to a device/user identity if the host eventually provides a trustworthy identity signal?
7. How should configuration history be represented and rolled back?
8. Should backups be local-only first, or integrate PrivaDrive later?
9. How much autonomous diagnosis/remediation should be allowed before explicit approval?
10. Should runbooks be hard-coded, declarative YAML/JSON, or plugin-extensible?
11. How should mixed Core/Node/Search/Proxy versions be modeled and validated?
12. What should the persistent Admin UI show that chat does not already communicate well?
13. Should 0.4 expose a public/local API for other operator clients besides ChatGPT?
14. How should multiple operators be handled if PrivaNet eventually stops being single-operator?
15. What is the right trust model for community nodes that may be malicious or compromised?

---

# Planning rule

Before implementing major 0.4.0 work:

1. brainstorm architecture and product direction
2. write down decisions and rejected alternatives
3. identify required PrivaNet Core protocol changes
4. define security invariants
5. define migration and compatibility behavior
6. only then convert roadmap items into implementation tasks

The roadmap should be updated as those decisions become clearer.
