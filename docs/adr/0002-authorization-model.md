# ADR 0002: Partially trusted Admin with scoped capabilities for privileged actions

- Status: Accepted for 0.4 planning
- Date: 2026-10-06

## Context

Chat Admin 0.3 already separates an unprivileged bridge from a root broker and supports request-bound authorization plus one-shot TOTP-protected root commands.

A future Admin service will become more capable, so treating the whole Admin process as permanently omnipotent would unnecessarily enlarge the blast radius of a compromise.

## Decision

0.4 will use a **partially trusted** model:

- read-only and low-risk inspection may be performed by the Admin service with its normal authenticated service identity;
- ordinary mutations require explicit scoped authorization according to policy;
- high-risk operations use narrow, target-bound, short-lived capabilities that are independently checked by the receiving authority or broker;
- raw root execution remains exact-command-bound, one-shot, short-lived, and TOTP-protected;
- destructive actions may require a second confirmation and/or TOTP even when a broader operator scope is already active.

The project may move additional operations toward capability-everything later, but 0.4 does not require every harmless mutation to carry a signed single-use capability from day one.

## Security invariants

- no permanent reusable root token exposed to ChatGPT;
- no TOTP seed exposed to ChatGPT;
- approval is not inferred from a model/tool request alone;
- action, target, scope, expiry, and use count are broker/server validated;
- high-risk capabilities cannot be broadened by the Admin client after approval.
