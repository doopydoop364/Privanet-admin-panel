# ADR 0010 (proposed): Hybrid Admin surface; panel is the strong approver channel

- Status: **Proposed**
- Date: 2026-10-06

## Decision
Chat remains primary. MCP cards handle contextual moments (approval, node, run progress); a standalone PWA panel served by the Operator API on loopback provides persistence, an approvals inbox, history and update/run views, and is the strong approver channel (passkey or password+TOTP login; step-up bound to the proposal). Cards and panel share components; every card links "Open in panel". Panel delivery is staged read-only first.

Security baseline is ported from Core's local-ui guard: per-run sign-in token exchanged for HttpOnly SameSite=Strict cookie, Host allowlist, Origin + CSRF on writes, nonce CSP, strict body limits, no CORS. Remote reachability is the operator's choice of tunnel; the panel never requires VPN/WireGuard as a product dependency.

## Relationship to Core
Admin does not extend `privanet-admin ui`. It may link to it or surface node data through the Operator API.

## Rejected
Cards-only (no trustworthy approver channel, no persistence); extending Core's dashboard (ADR 0001).
