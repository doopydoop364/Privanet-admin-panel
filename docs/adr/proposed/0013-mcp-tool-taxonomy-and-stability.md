# ADR 0013 (proposed): MCP tool taxonomy and stability contract

- Status: **Proposed**
- Date: 2026-10-06

## Decision
- Observe tools: `get_*`/`list_*`, side-effect free, `readOnlyHint`. Mutations: imperative verb+noun, typed, with `destructiveHint`/`idempotentHint`; proposal-on-first-call (ADR 0009). Tools that touch the network are `openWorldHint`.
- One noun per resource (`node`), one `operation_id`, one result envelope `{ok, code, data, warnings, freshness, sections, operation, unsupported}`; aggregates return per-section status instead of failing wholesale.
- Catalogue and tiers: design doc §5 (35 model-visible tools, 38 with backups; 3 app-only helpers).
- Names are stable; parameters are added additively; renamed tools remain aliases with a deprecation note for at least one minor release; a contract test pins names, visibility and annotations.
- Discovery: `get_capabilities` reports versions and per-target supported operations; unsupported operations return `UNSUPPORTED_BY_TARGET`, never an SSH/shell fallback.
