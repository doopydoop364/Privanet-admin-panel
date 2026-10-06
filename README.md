# PrivaNet Chat Admin v0.3.3

PrivaNet Chat Admin is a private MCP server for administering a PrivaNet deployment from ChatGPT. v0.3.3 keeps the v0.3.2 capability and TOTP security model while improving approval-card display negotiation, mobile state visibility, and retry behavior when ChatGPT keeps a confirmation inline.

## v0.3.3 changes

- **Explicit fullscreen retry:** approval cards still request fullscreen automatically, but now also expose an **Open fullscreen** control when the host keeps the card inline.
- **Host-result feedback:** the card reports whether fullscreen was accepted or whether ChatGPT chose to keep the view inline.
- **Clear approval states:** Pending, Approved, Denied, Expired, and Error states are visible and terminal states are not accidentally re-enabled by later host-global refreshes.
- **Better expiry handling:** expired requests disable mutation controls and explain that ChatGPT must create a new request.
- **Mobile approval polish:** state and fullscreen controls adapt to narrow screens while preserving the inline fallback.
- **Development packaging fix:** setuptools now explicitly packages only the `agent` package, allowing normal editable/test installs from the source repository.

## v0.3.2 changes

- **Request-ID capability authorization:** normal admin approval is bound to an opaque `req_...` capability handle instead of a transient MCP session identifier. The handle can survive ChatGPT using a different transport/session ID on the next tool call.
- **Fullscreen-capable approval UI:** the MCP App advertises inline + fullscreen modes, prefers fullscreen, and asks the host for fullscreen once when supported. Display mode is ultimately controlled by the ChatGPT host, so clients may still render the card inline.
- **Exact destructive confirmations:** node revocation and package installation use a separate `confirm_req_...` one-use capability tied to the exact action and target.
- **Per-command root approval:** `request_sudo_command` can request one exact non-interactive root command. The approval card displays the exact command and requires a 6-digit TOTP code before the broker will approve it.
- **No open-ended root lease:** a successful TOTP approves only that already-stored command, for one execution, with a short execution window. Changing the command requires a new request and another 2FA approval.
- **TOTP replay/rate protection:** the broker rejects already-used TOTP counters and temporarily blocks verification after repeated failures.
- **Root-only enrollment:** `privanet-chat-admin-2fa setup` creates the TOTP seed locally in the root-owned broker state directory. The seed/QR is never returned through MCP and should never be pasted into ChatGPT.
- **No server-initiated elicitation:** approvals use normal client-initiated MCP App calls rather than `context.elicit`, so they do not require a server-to-client transport back-channel.
- **App-only grant/deny helpers:** card buttons call helpers hidden from the model; model-visible request tools cannot grant authorization themselves.
- **One-shot lease preservation:** a one-action normal admin lease is not consumed merely because a destructive operation discovers that a second confirmation is required.
- **Denial/replay protection:** denied or already-used authorization, confirmation, and sudo request IDs cannot be reused.

## Security architecture

```text
ChatGPT / MCP client
        |
        v
privanet-chat-admin.service
user: privanet-chat
        |
        +------------------------------+
        |                              |
        v                              v
privanet-chat-shell.service      privanet-chat-admin-broker.service
user: privanet-shell             user: root
unprivileged commands            validates capabilities + 2FA
        |                              |
        | cannot access                +-- typed PrivaNet maintenance
        | broker socket                |
        v                              +-- one exact TOTP-approved
host diagnostics                     root command, one use
```

The MCP frontend may reach the shell and broker sockets. The `privanet-shell` account is **not** a member of the broker-access group, so `run_command` cannot directly mint approvals or invoke the privileged broker. Executable releases, broker state, systemd configuration, and privileged credentials remain root-owned.

`run_command` always stays unprivileged. The general root path is a separate step-up workflow and never turns the command sandbox into root.

## Normal administrative authorization

A normal privileged request works like this:

1. A privileged tool checks for a valid `authorization_request_id` for the required scope.
2. If missing, it returns `AUTHORIZATION_REQUIRED` and does nothing.
3. ChatGPT calls `request_admin_access` with that exact scope and reason.
4. The MCP App shows the approval card. The host is asked for fullscreen when supported, but may choose inline rendering.
5. The user chooses **this action only / 15 min / 30 min / 1 hour** and explicitly approves or denies.
6. Approval creates a scoped lease tied to that `req_...` request ID, not to the current MCP transport session.
7. ChatGPT retries the original action with `authorization_request_id=<req_...>`.
8. The root broker independently checks the capability before doing anything privileged.

Scopes:

| Scope | Allows |
| --- | --- |
| `privanet.services` | Restart allowlisted Priva services |
| `privanet.nodes` | Approve, deny, rename, or revoke nodes |
| `privanet.node_local` | Change the local node's saved slot setting |
| `privanet.updates` | Apply verified Priva application updates |
| `system.packages` | Install a validated package from configured APT repositories |
| `system.sudo` | Reserved for the separate per-command TOTP root workflow |

`revoke_admin_access` can revoke one request-bound lease or all active normal admin leases.

### Sensitive-action confirmation

Node revocation and package installation require a second confirmation even when their broader scope is already approved:

1. The broker verifies the normal `authorization_request_id` without consuming a one-shot lease.
2. If the exact action/target has not been confirmed, the tool returns `DESTRUCTIVE_CONFIRMATION_REQUIRED` without making a change.
3. ChatGPT calls `request_action_confirmation` with the exact action, target, reason, and existing authorization request ID.
4. The user approves a one-use `confirm_req_...` capability tied to that exact action and target.
5. ChatGPT retries with both `authorization_request_id` and `confirmation_request_id`.
6. The broker consumes the confirmation and, if applicable, the one-shot normal lease only when the actual action executes.

## General root command + 2FA

General root execution is intentionally separate from the normal scope leases.

### Enroll 2FA locally

After installing v0.3.3, run this **on the server as root**:

```bash
privanet-chat-admin-2fa setup
```

It creates a random TOTP seed at:

```text
/var/lib/privanet-chat-admin-broker/totp.secret
```

The directory is root-only and the secret file is mode `0600`. The command prints an `otpauth://` URI and enrollment secret locally; if `qrencode` is installed it also prints a terminal QR code. Add it to your authenticator app there.

Do **not** paste the secret, QR contents, or enrollment URI into ChatGPT. They are equivalent to the second factor.

Useful local commands:

```bash
privanet-chat-admin-2fa status
privanet-chat-admin-2fa verify 123456
privanet-chat-admin-2fa rotate
privanet-chat-admin-2fa disable --yes
```

### Root-command flow

1. ChatGPT calls `request_sudo_command` with the **exact** command, a reason, and an execution timeout.
2. The broker stores that exact command first and returns an opaque `sudo_req_...` request ID plus a SHA-256 digest.
3. The approval card displays the exact command and asks the user for a 6-digit TOTP code.
4. The app-only grant helper sends the code directly to the broker for verification. The follow-up message does not include the code.
5. A valid code approves that one `sudo_req_...` for a short execution window and one use.
6. ChatGPT calls `run_sudo_command(sudo_request_id=...)`; it does **not** resend the command.
7. The broker executes only the command it stored before approval. Supplying different command text cannot change what runs.
8. Reusing the sudo request or the same accepted TOTP counter is rejected.

Root commands are non-interactive, time-bounded, output-bounded, audited, and executed with a clean environment rather than inheriting MCP/API secrets.

**Important security limit:** TOTP is a step-up barrier *before* root execution, not a sandbox around an already-approved root command. A root command can inherently make broad system changes. Read the exact command shown on the card before approving it.

## Local fallback authorization

If the MCP App UI is unavailable, a root operator can use the local fallback helper with the opaque request IDs shown by Chat Admin. It no longer relies on a stable MCP session ID.

Normal admin request:

```bash
privanet-chat-admin-authorize \
  --request req_... \
  --duration 30m
```

Destructive confirmation:

```bash
privanet-chat-admin-authorize \
  --confirm-request confirm_req_...
```

Root-command 2FA approval:

```bash
privanet-chat-admin-authorize \
  --sudo-request sudo_req_... \
  --totp 123456
```

These are fallback mechanisms only. Normal ChatGPT usage should use the approval card.

## Command sandbox

`run_command` executes non-interactive commands as `privanet-shell`, never root. It has no password, no sudo, no broker-socket access, a sanitized environment, bounded execution/output, its own writable work directory, `ProtectSystem=strict`, and `ProtectHome=true`.

Typical diagnostic uses include:

```bash
uptime
free -h
ss -lntp
ps aux
du -sh /var/lib/privasearch
curl http://127.0.0.1:4020/health
```

## Privileged broker

For ordinary PrivaNet administration, the root broker still accepts fixed structured operations rather than arbitrary root text. These cover allowlisted service restarts, node approve/deny/rename/revoke, local slot changes, verified Priva updates, and validated Debian package installation.

The only general root-text path is `request_sudo_command` → TOTP approval → `run_sudo_command`, with exact-command binding and one-use approval as described above. It is not exposed as `sudo ALL`, an SSH shell, or a reusable root session.

## Node and diagnostic tools

v0.3 includes:

- `get_privanet_summary`
- `get_command_environment`
- `run_command`
- `get_nodes(include_revoked=...)`
- `get_node`
- `diagnose_node`
- `get_node_version_drift`
- `rename_node`
- `get_privasearch_summary`
- `get_update_history`
- cleaner fresh `get_update_status`
- combined frontend/broker audit reporting

Remote nodes can be inspected and diagnosed. The current Core coordinator still does not expose a safe central operation for changing another node's local slot/resource policy, so v0.3.3 does not fake that capability with SSH.

## Install / upgrade

From an extracted release:

```bash
cd privanet-chat-admin
sudo ./deploy.sh
```

The deploy script automatically creates/migrates the locked system identities and groups:

```text
privanet-chat             MCP frontend, no login
privanet-shell            command sandbox, no login
privanet-chat-broker      broker-client group
privanet-chat-shell       shell-client group
```

Services:

```text
privanet-chat-admin.service
privanet-chat-admin-broker.service
privanet-chat-shell.service
privanet-chat-admin-update-check.service
```

The MCP endpoint remains `http://127.0.0.1:8787/mcp`; the existing OpenAI Secure MCP Tunnel can continue pointing to it.

Upgrading from v0.3.1 intentionally does **not** preserve old session-bound temporary authorization leases. Create fresh approvals after the upgrade. Existing configuration/state is backed up and migrated as usual.

After upgrading, configure root-command 2FA only if you want the general root-command feature:

```bash
sudo privanet-chat-admin-2fa setup
```

## Easy updates

```bash
privanet-chat-admin-update --check
privanet-chat-admin-update
```

The updater reads `https://doopydoop364.github.io/privanet-chat-admin-latest.json`, verifies the release origin and SHA-256, extracts it, and runs `deploy.sh` with rollback support.

## Model-visible MCP tools

### Overall / diagnostics

- `get_privanet_summary`
- `get_services`
- `get_service_status`
- `get_recent_logs`
- `get_system_health`
- `get_command_environment`
- `run_command`
- `get_audit_log`

### Authorization / confirmation

- `get_authorization_status`
- `request_admin_access`
- `request_action_confirmation`
- `revoke_admin_access`

Grant/deny helpers used by approval cards are app-only.

### Root step-up

- `get_sudo_2fa_status`
- `request_sudo_command`
- `run_sudo_command`

The TOTP grant/deny helpers are app-only.

### Nodes

- `get_nodes`
- `get_node`
- `diagnose_node`
- `get_node_version_drift`
- `get_pending_nodes`
- `approve_node`
- `deny_node`
- `rename_node`
- `revoke_node`
- `get_local_node_slots`
- `set_local_node_slots`
- `clear_local_node_slots`

### PrivaSearch

- `get_privasearch_health`
- `get_privasearch_status`
- `get_privasearch_summary`

### Updates / host maintenance

- `get_update_status`
- `get_update_history`
- `get_update_schedule`
- `apply_available_updates`
- `install_system_package`

## Validation

The release test suite covers request-ID authorization across changing MCP sessions, one-use/timed leases, destructive target binding, TOTP setup requirements, exact-command sudo binding, TOTP replay rejection, fullscreen-capable app metadata, migration/deployment protections, updater behavior, and the existing PrivaNet diagnostic/admin adapters.

## Repository roadmap

Development planning for the remainder of 0.3.x and the 0.4.0 operator-plane architecture lives in [ROADMAP.md](./ROADMAP.md).

The 0.4 architecture decisions are recorded under [docs/adr](./docs/adr/).
