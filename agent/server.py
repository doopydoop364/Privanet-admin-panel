from __future__ import annotations

import json
import os
import secrets
import weakref
from typing import Any, Literal

from mcp.server import MCPServer
from mcp.server.apps import Apps
from mcp.server.mcpserver.context import Context
from mcp.server.mcpserver.resources import TextResource

from .core import AdminBackend, BrokerError, SCOPES, VERSION

CONFIG_PATH = os.environ.get("PRIVANET_CHAT_ADMIN_CONFIG", "/etc/privanet-chat-admin/config.json")
with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
    config = json.load(fh)
backend = AdminBackend(config)

_SESSION_KEYS: weakref.WeakKeyDictionary[Any, str] = weakref.WeakKeyDictionary()


def _session_key(context: Context[Any, Any]) -> str:
    session = context.request_context.session
    try:
        key = _SESSION_KEYS.get(session)
        if key is None:
            key = "mcp_" + secrets.token_hex(16)
            _SESSION_KEYS[session] = key
        return key
    except TypeError:
        return "mcp_" + format(id(session), "x")


def _ensure_scope(
    context: Context[Any, Any],
    scope: str,
    reason: str,
    authorization_request_id: str | None,
) -> tuple[bool, dict[str, Any]]:
    if authorization_request_id:
        try:
            status = backend.check_authorization(authorization_request_id, scope, _session_key(context))
        except BrokerError as exc:
            status = {"ok": False, "code": exc.code, "error": str(exc)}
        if status.get("ok"):
            return True, {"authorization": "approved", "scope": scope, "requestId": authorization_request_id}
    return False, {
        "ok": False,
        "code": "AUTHORIZATION_REQUIRED",
        "scope": scope,
        "reason": reason,
        "allows": SCOPES[scope],
        "nextTool": "request_admin_access",
        "message": "Open the PrivaNet approval card with request_admin_access, then retry this action with authorization_request_id set to the returned requestId after the user approves it.",
    }


APP_URI = "ui://privanet-admin/approval-v3.html"
APP_HTML = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PrivaNet Admin Approval</title>
<style>
:root{font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color-scheme:light dark}
*{box-sizing:border-box}body{margin:0;padding:14px;background:transparent;color:inherit}.card{border:1px solid color-mix(in srgb,currentColor 18%,transparent);border-radius:18px;padding:18px;max-width:720px;margin:0 auto;background:color-mix(in srgb,Canvas 97%,transparent);box-shadow:0 6px 24px rgba(0,0,0,.08)}
.head{display:flex;gap:10px;align-items:center;margin-bottom:12px}.badge{font-size:12px;font-weight:750;padding:4px 8px;border-radius:999px;background:color-mix(in srgb,#6b5cff 18%,transparent)}h2{font-size:19px;margin:0;flex:1}.state-pill{font-size:12px;font-weight:750;padding:4px 8px;border-radius:999px;background:color-mix(in srgb,currentColor 9%,transparent)}.state-pill.approved{background:color-mix(in srgb,#18a558 18%,transparent)}.state-pill.denied,.state-pill.expired,.state-pill.error{background:color-mix(in srgb,#d33 14%,transparent)}.muted{opacity:.72;font-size:13px;line-height:1.5}.scope{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;padding:9px 11px;border-radius:11px;background:color-mix(in srgb,currentColor 7%,transparent);overflow-wrap:anywhere}.reason{margin:13px 0;line-height:1.5}.command{white-space:pre-wrap;overflow-wrap:anywhere;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;padding:10px 12px;border-radius:10px;background:color-mix(in srgb,currentColor 8%,transparent);margin:12px 0}.choices{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin:12px 0}.choices label{border:1px solid color-mix(in srgb,currentColor 16%,transparent);border-radius:10px;padding:10px;font-size:13px;cursor:pointer}.field{margin:14px 0}.field label{display:block;font-size:13px;font-weight:650;margin-bottom:6px}.field input{width:100%;font:inherit;font-size:18px;letter-spacing:.16em;padding:10px 12px;border-radius:10px;border:1px solid color-mix(in srgb,currentColor 20%,transparent);background:Canvas;color:CanvasText}.display-actions{display:flex;gap:10px;align-items:center;margin-top:12px}.display-note{font-size:12px;opacity:.72;line-height:1.4;flex:1}.actions{display:flex;gap:8px;justify-content:flex-end;margin-top:14px}button{border:0;border-radius:11px;padding:10px 14px;font-weight:700;cursor:pointer}button.primary{background:#6b5cff;color:white}button.secondary{background:color-mix(in srgb,currentColor 10%,transparent);color:inherit}button:disabled{opacity:.5;cursor:not-allowed}.status{margin-top:10px;font-size:13px;min-height:18px}.danger{border-color:color-mix(in srgb,#d33 55%,transparent)}.warning{margin-top:12px;padding:10px 12px;border-radius:10px;background:color-mix(in srgb,#d33 10%,transparent);font-size:13px;line-height:1.45}.timer{font-size:12px;opacity:.65;margin-top:8px}
@media(max-width:700px){body{padding:12px}.card{max-width:none;min-height:calc(100vh - 24px)}.head{align-items:flex-start;flex-wrap:wrap}.state-pill{margin-left:auto}.choices{grid-template-columns:1fr}.display-actions{align-items:stretch;flex-direction:column}.actions{flex-direction:column-reverse}button{width:100%;padding:13px}.scope{font-size:14px}}
</style>
</head>
<body>
<div class="card" id="card">
  <div class="head"><span class="badge">PrivaNet Admin</span><h2 id="title">Permission request</h2><span class="state-pill" id="state">Pending</span></div>
  <div class="scope" id="scope">Loading request…</div>
  <div class="reason" id="reason"></div>
  <div class="muted" id="details"></div>
  <pre class="command" id="command" hidden></pre>
  <div class="warning" id="warning" hidden></div>
  <div class="choices" id="choices"></div>
  <div class="field" id="totpField" hidden><label for="totp">Authenticator code</label><input id="totp" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" placeholder="000000"><div class="muted">Enter the current 6-digit code from the authenticator you enrolled locally on the server.</div></div>
  <div class="display-actions" id="displayActions"><button class="secondary" id="fullscreen">Open fullscreen</button><div class="display-note" id="displayNote"></div></div>
  <div class="actions"><button class="secondary" id="deny">Deny</button><button class="primary" id="approve">Approve</button></div>
  <div class="status" id="status"></div>
  <div class="timer" id="timer"></div>
</div>
<script>
(() => {
  const $ = id => document.getElementById(id);
  let payload = null, fullscreenAutoRequested = false, timerHandle = null, terminalState = null;
  const extract = value => {
    if (!value) return null;
    if (value.structuredContent && typeof value.structuredContent === 'object') return value.structuredContent;
    if (typeof value === 'object' && (value.kind || value.requestId)) return value;
    const content = value.content || value?.mcp_tool_result?.content;
    if (Array.isArray(content)) {
      const text = content.find(x => x && x.type === 'text' && typeof x.text === 'string')?.text;
      if (text) { try { return JSON.parse(text); } catch {} }
    }
    return null;
  };
  const current = () => extract(window.openai?.toolOutput) || extract(window.openai?.toolResponseMetadata?.mcp_tool_result);
  const setBusy = busy => { $('approve').disabled = busy; $('deny').disabled = busy; };
  const setState = (state, message='') => {
    const pill=$('state'); pill.textContent=state[0].toUpperCase()+state.slice(1); pill.className=`state-pill ${state}`;
    if (message) $('status').textContent=message;
    terminalState=['approved','denied','expired'].includes(state)?state:null;
  };
  const failureMessage = result => {
    const msg=result?.error || result?.message || 'Approval was not completed.';
    const code=result?.code || result?.error?.code;
    if (code==='AUTHORIZATION_REQUEST_INVALID' || /expired or invalid/i.test(String(msg))) return 'This approval request expired or was already used. Ask ChatGPT to create a new request.';
    return String(msg);
  };
  const call = async (name, args) => {
    if (!window.openai?.callTool) throw new Error('This ChatGPT client does not expose widget tool calls.');
    return extract(await window.openai.callTool(name, args));
  };
  const followUp = async text => {
    if (window.openai?.sendFollowUpMessage) await window.openai.sendFollowUpMessage({prompt:text,scrollToBottom:true});
  };
  const requestFullscreen = async (manual=false) => {
    const button=$('fullscreen');
    if (!window.openai?.requestDisplayMode) {
      button.hidden=true;
      $('displayNote').textContent='This ChatGPT client does not expose fullscreen switching for this approval.';
      return null;
    }
    if (!manual && fullscreenAutoRequested) return null;
    if (!manual) fullscreenAutoRequested=true;
    button.hidden=false; button.disabled=true;
    if (manual) $('displayNote').textContent='Requesting fullscreen…';
    try {
      const result=await window.openai.requestDisplayMode({mode:'fullscreen'});
      const mode=(typeof result==='string'?result:result?.mode) || window.openai?.displayMode || null;
      if (mode==='fullscreen') {
        button.hidden=true;
        $('displayNote').textContent='Fullscreen approval view active.';
      } else {
        button.hidden=false;
        $('displayNote').textContent=manual
          ? 'ChatGPT kept this approval inline. You can still review and approve it safely here.'
          : 'ChatGPT opened this approval inline. Use Open fullscreen to try again.';
      }
      return mode;
    } catch (e) {
      button.hidden=false;
      $('displayNote').textContent=manual
        ? `Fullscreen request was not accepted: ${e?.message || e}`
        : 'ChatGPT kept this approval inline. Use Open fullscreen to try again.';
      return null;
    } finally {
      if (!terminalState) button.disabled=false;
    }
  };
  const startTimer = () => {
    if (timerHandle) clearInterval(timerHandle);
    const tick=()=>{
      if (!payload?.expiresAt) { $('timer').textContent=''; return; }
      const left=Math.max(0, Number(payload.expiresAt)*1000-Date.now());
      const sec=Math.ceil(left/1000);
      $('timer').textContent=sec>0?`Request expires in ${Math.floor(sec/60)}:${String(sec%60).padStart(2,'0')}`:'Request expired. Ask ChatGPT to create a new approval request.';
      if (sec<=0 && !terminalState) { setBusy(true); $('fullscreen').disabled=true; setState('expired','This request expired before approval. Ask ChatGPT to create a new one.'); }
    }; tick(); timerHandle=setInterval(tick,1000);
  };
  const render = () => {
    const next = current(); if (next) payload = next;
    if (!payload) { $('status').textContent='Waiting for request data…'; setBusy(true); return; }
    if (!terminalState) setBusy(false); requestFullscreen(false); startTimer();
    const destructive = payload.kind === 'confirmation';
    const sudo = payload.kind === 'sudo';
    const sensitiveApproval = payload.kind === 'authorization' && ['privanet.nodes','privanet.updates','system.packages'].includes(payload.scope);
    if (!terminalState) setState('pending', sudo?'2FA approval required.':destructive?'Sensitive-action confirmation required.':'Administrative approval required.');
    $('title').textContent = sudo ? 'Root command approval' : destructive ? 'Confirm sensitive action' : 'Administrative access request';
    $('card').classList.toggle('danger', destructive || sudo);
    $('scope').textContent = sudo ? 'system.sudo' : destructive ? `${payload.action} · ${payload.target}` : payload.scope;
    $('reason').textContent = payload.reason || '';
    $('details').textContent = sudo
      ? 'This approval applies to the exact command shown below, once. The command will run non-interactively as root only after the 2FA code is verified.'
      : destructive
        ? 'This confirmation is valid for this exact action and target once.'
        : sensitiveApproval
          ? `${payload.allows || ''} This high-impact legacy scope also requires a fresh TOTP code verified by the root broker.`
          : `${payload.allows || ''} The command sandbox remains the unprivileged privanet-shell account; this does not enable root command execution.`;
    $('command').hidden=!sudo; $('command').textContent=sudo?(payload.command||''):'';
    $('warning').hidden=!sudo; $('warning').textContent=sudo?'Root commands can modify or delete system data, credentials, services, and software. Command output is returned to ChatGPT. Approve only if the exact command is expected and does not expose secrets you do not want in chat.':'';
    $('totpField').hidden=!(sudo || sensitiveApproval);
    const box=$('choices'); box.innerHTML='';
    if (!destructive && !sudo) {
      [['once','This action only'],['15m','15 minutes'],['30m','30 minutes'],['60m','1 hour']].forEach(([v,label],i)=>{
        const el=document.createElement('label');
        el.innerHTML=`<input type="radio" name="duration" value="${v}" ${i===0?'checked':''}> ${label}`; box.appendChild(el);
      });
    }
  };
  $('approve').addEventListener('click', async () => {
    if (!payload || terminalState) return; setBusy(true); $('fullscreen').disabled=true; setState('pending','Approving…');
    try {
      let result;
      if (payload.kind === 'confirmation') {
        result = await call('grant_action_confirmation',{request_id:payload.requestId});
      } else if (payload.kind === 'sudo') {
        const code=$('totp').value.trim();
        if (!/^[0-9]{6}$/.test(code)) throw new Error('Enter a 6-digit authenticator code.');
        result = await call('grant_sudo_command',{request_id:payload.requestId,totp_code:code});
        $('totp').value='';
      } else {
        const duration=document.querySelector('input[name="duration"]:checked')?.value || 'once';
        const args={request_id:payload.requestId,duration};
        if (['privanet.nodes','privanet.updates','system.packages'].includes(payload.scope)) {
          const code=$('totp').value.trim();
          if (!/^[0-9]{6}$/.test(code)) throw new Error('Enter a 6-digit authenticator code for this high-impact approval.');
          args.totp_code=code; $('totp').value='';
        }
        result = await call('grant_admin_access',args);
      }
      if (!result?.ok) { const err=new Error(failureMessage(result)); err.code=result?.code || result?.error?.code; throw err; }
      setState('approved','Approved. ChatGPT can retry the requested action.');
      $('approve').disabled=true; $('deny').disabled=true; $('fullscreen').disabled=true;
      if (payload.kind === 'sudo') {
        await followUp(`PrivaNet root command approval was granted for sudo_request_id=${payload.requestId}. Run run_sudo_command with that exact sudo_request_id and verify the result.`);
      } else if (payload.kind === 'confirmation') {
        await followUp(`PrivaNet sensitive-action confirmation was granted for confirmation_request_id=${payload.requestId}. Retry the exact operation with that confirmation_request_id and the existing authorization_request_id.`);
      } else {
        await followUp(`PrivaNet administrative access was approved for authorization_request_id=${payload.requestId}. Retry the operation that requested ${payload.scope} with that authorization_request_id and verify its result.`);
      }
    } catch (e) {
      const msg=e?.message || String(e);
      if (/expired|already used|no longer valid/i.test(msg)) { setBusy(true); $('fullscreen').disabled=true; setState('expired',msg); }
      else { setState('error',`Approval failed: ${msg}`); setBusy(false); $('fullscreen').disabled=false; }
    }
  });
  $('deny').addEventListener('click', async () => {
    if (!payload || terminalState) return; setBusy(true); $('fullscreen').disabled=true; setState('pending','Denying…');
    try {
      const name=payload.kind==='confirmation'?'deny_action_confirmation':payload.kind==='sudo'?'deny_sudo_command':'deny_admin_access';
      const result=await call(name,{request_id:payload.requestId});
      if (!result?.ok) { const err=new Error(failureMessage(result)); err.code=result?.code || result?.error?.code; throw err; }
      setState('denied','Denied. No privileged action was performed.');
      $('approve').disabled=true; $('deny').disabled=true; $('fullscreen').disabled=true;
    } catch (e) {
      const msg=e?.message || String(e);
      if (/expired|already used|no longer valid/i.test(msg)) { setBusy(true); $('fullscreen').disabled=true; setState('expired',msg); }
      else { setState('error',`Could not record denial: ${msg}`); setBusy(false); $('fullscreen').disabled=false; }
    }
  });
  $('fullscreen').addEventListener('click', async () => { await requestFullscreen(true); });
  window.addEventListener('openai:set_globals', render, {passive:true});
  render(); setTimeout(render,100);
})();
</script>
</body>
</html>
'''

apps = Apps()


@apps.tool(
    resource_uri=APP_URI,
    visibility=["model", "app"],
    meta={"openai/outputTemplate": APP_URI, "openai/widgetAccessible": True},
    description="Show an inline PrivaNet approval card for a scoped temporary administrative lease. This tool does not grant access by itself.",
)
def request_admin_access(
    scope: Literal["privanet.services", "privanet.nodes", "privanet.node_local", "privanet.updates", "system.packages"],
    reason: str,
    context: Context[Any, Any],
) -> dict[str, Any]:
    session_key = _session_key(context)
    prepared = backend.prepare_authorization(scope, reason, session_key)
    return {
        "ok": True,
        "kind": "authorization",
        "state": "PENDING_USER_APPROVAL",
        "requestId": prepared["requestId"],
        "scope": scope,
        "reason": reason,
        "allows": SCOPES[scope],
        "expiresAt": prepared.get("expiresAt"),
        "followUp": "PrivaNet administrative access was approved. Retry the operation with this authorization_request_id and verify its result.",
    }


@apps.tool(
    resource_uri=APP_URI,
    visibility=["app"],
    meta={"openai/outputTemplate": APP_URI, "openai/widgetAccessible": True},
    description="App-only helper that grants a previously prepared PrivaNet authorization request after the user presses Approve.",
)
def grant_admin_access(request_id: str, duration: Literal["once", "15m", "30m", "60m"], context: Context[Any, Any], totp_code: str | None = None) -> dict[str, Any]:
    try:
        return backend.grant_authorization(request_id, duration, _session_key(context), totp_code)
    except BrokerError as exc:
        return {"ok": False, "code": exc.code, "error": str(exc)}


@apps.tool(
    resource_uri=APP_URI,
    visibility=["app"],
    meta={"openai/outputTemplate": APP_URI, "openai/widgetAccessible": True},
    description="App-only helper that denies and consumes a pending PrivaNet authorization request.",
)
def deny_admin_access(request_id: str, context: Context[Any, Any]) -> dict[str, Any]:
    try:
        return backend.deny_authorization(request_id, _session_key(context))
    except BrokerError as exc:
        return {"ok": False, "code": exc.code, "error": str(exc)}


@apps.tool(
    resource_uri=APP_URI,
    visibility=["model", "app"],
    meta={"openai/outputTemplate": APP_URI, "openai/widgetAccessible": True},
    description="Show an inline one-action confirmation card for a sensitive PrivaNet operation after its normal admin scope is already authorized.",
)
def request_action_confirmation(
    action: Literal["admin.node.revoke", "package.install"],
    target: str,
    reason: str,
    authorization_request_id: str,
    context: Context[Any, Any],
) -> dict[str, Any]:
    try:
        prepared = backend.prepare_confirmation(action, target, reason, authorization_request_id, _session_key(context))
    except BrokerError as exc:
        return {"ok": False, "code": exc.code, "error": str(exc), "action": action, "target": target}
    return {
        "ok": True,
        "kind": "confirmation",
        "state": "PENDING_USER_CONFIRMATION",
        "requestId": prepared["requestId"],
        "action": action,
        "target": prepared["target"],
        "reason": reason,
        "expiresAt": prepared.get("expiresAt"),
        "authorizationRequestId": authorization_request_id,
        "followUp": "The sensitive PrivaNet action was confirmed. Retry that exact action with this confirmation_request_id and the existing authorization_request_id.",
    }


@apps.tool(
    resource_uri=APP_URI,
    visibility=["app"],
    meta={"openai/outputTemplate": APP_URI, "openai/widgetAccessible": True},
    description="App-only helper that grants a prepared one-action destructive confirmation after the user presses Approve.",
)
def grant_action_confirmation(request_id: str, context: Context[Any, Any]) -> dict[str, Any]:
    try:
        return backend.grant_confirmation(request_id, _session_key(context))
    except BrokerError as exc:
        return {"ok": False, "code": exc.code, "error": str(exc)}


@apps.tool(
    resource_uri=APP_URI,
    visibility=["app"],
    meta={"openai/outputTemplate": APP_URI, "openai/widgetAccessible": True},
    description="App-only helper that denies and consumes a prepared destructive confirmation.",
)
def deny_action_confirmation(request_id: str, context: Context[Any, Any]) -> dict[str, Any]:
    try:
        return backend.deny_confirmation(request_id, _session_key(context))
    except BrokerError as exc:
        return {"ok": False, "code": exc.code, "error": str(exc)}


@apps.tool(
    resource_uri=APP_URI,
    visibility=["model", "app"],
    meta={"openai/outputTemplate": APP_URI, "openai/widgetAccessible": True},
    description="Show a fullscreen-capable 2FA approval card for one exact root command. The command cannot run until the user approves it with a TOTP code.",
)
def request_sudo_command(
    command: str,
    reason: str,
    context: Context[Any, Any],
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    try:
        prepared = backend.prepare_sudo_command(command, reason, timeout_seconds, _session_key(context))
    except BrokerError as exc:
        return {"ok": False, "code": exc.code, "error": str(exc), "nextStep": "Run privanet-chat-admin-2fa setup locally as root if 2FA is not configured."}
    return {
        "ok": True,
        "kind": "sudo",
        "state": "PENDING_2FA_APPROVAL",
        "requestId": prepared["requestId"],
        "command": prepared["command"],
        "commandSha256": prepared.get("commandSha256"),
        "reason": reason,
        "timeoutSeconds": prepared.get("timeoutSeconds"),
        "expiresAt": prepared.get("expiresAt"),
    }


@apps.tool(
    resource_uri=APP_URI,
    visibility=["app"],
    meta={"openai/outputTemplate": APP_URI, "openai/widgetAccessible": True},
    description="App-only helper that verifies the user's TOTP and approves one exact prepared root command.",
)
def grant_sudo_command(request_id: str, totp_code: str, context: Context[Any, Any]) -> dict[str, Any]:
    try:
        return backend.grant_sudo_command(request_id, totp_code, _session_key(context))
    except BrokerError as exc:
        return {"ok": False, "code": exc.code, "error": str(exc)}


@apps.tool(
    resource_uri=APP_URI,
    visibility=["app"],
    meta={"openai/outputTemplate": APP_URI, "openai/widgetAccessible": True},
    description="App-only helper that denies and consumes one prepared root-command request.",
)
def deny_sudo_command(request_id: str, context: Context[Any, Any]) -> dict[str, Any]:
    try:
        return backend.deny_sudo_command(request_id, _session_key(context))
    except BrokerError as exc:
        return {"ok": False, "code": exc.code, "error": str(exc)}


apps.add_resource(
    TextResource(
        uri=APP_URI,
        name="PrivaNet Admin approval",
        title="PrivaNet Admin approval",
        description="Scoped authorization, sensitive-action confirmation, and 2FA root-command approval card with explicit fullscreen retry controls.",
        mime_type="text/html;profile=mcp-app",
        text=APP_HTML,
        meta={
            "ui": {"prefersBorder": True},
            "openai/ui": {"availableDisplayModes": ["inline", "fullscreen"], "preferredDisplayMode": "fullscreen"},
        },
    )
)

mcp = MCPServer(
    "PrivaNet Admin",
    version=VERSION,
    extensions=[apps],
    instructions=(
        "Conversational administration for PrivaNet. Read-only diagnostics are available without elevation. "
        "run_command always executes as the locked-down privanet-shell Unix account with a sanitized environment. "
        "Never imply a command or privileged action succeeded unless the returned result says ok=true. "
        "If a privileged tool returns AUTHORIZATION_REQUIRED, call request_admin_access with the returned scope and reason, wait for approval, then retry with authorization_request_id set to the requestId returned by request_admin_access. "
        "If a tool returns DESTRUCTIVE_CONFIRMATION_REQUIRED, call request_action_confirmation with the exact action, target, reason, and authorization_request_id; then retry with both request IDs after confirmation. "
        "For a general root command, call request_sudo_command with the exact command and reason. The user must approve that exact command with TOTP, then run_sudo_command with the resulting sudo_request_id. "
        "Never ask the user to paste their TOTP secret or authenticator seed into chat. run_command itself always remains unprivileged."
    ),
)

@mcp.tool()
def get_privanet_summary() -> dict[str, Any]:
    """One-call operator summary: services, nodes, PrivaSearch, updates, host capacity, and warnings."""
    return backend.privanet_summary()


@mcp.tool()
def get_services() -> list[dict[str, Any]]:
    """List health/status for every allowlisted Priva service."""
    return backend.list_services()


@mcp.tool()
def get_service_status(service: str) -> dict[str, Any]:
    """Get detailed systemd status for one allowlisted Priva service."""
    return backend.service_status(service)


@mcp.tool()
def get_recent_logs(service: str, lines: int = 100, priority: str | None = None) -> dict[str, Any]:
    """Read a bounded, redacted slice of logs from one allowlisted service through the root broker."""
    return backend.recent_logs(service, lines, priority)


@mcp.tool()
def get_system_health() -> dict[str, Any]:
    """Show homeserver uptime, load, memory and disk capacity."""
    return backend.system_health()


@mcp.tool()
def get_command_environment() -> dict[str, Any]:
    """Describe the locked-down Unix account and restrictions used by run_command."""
    return backend.command_environment()


@mcp.tool()
def run_command(command: str, timeout_seconds: int = 20) -> dict[str, Any]:
    """Run a non-interactive shell command as the unprivileged privanet-shell account. This never becomes root."""
    return backend.run_command(command, timeout_seconds)


@mcp.tool()
def get_sudo_2fa_status() -> dict[str, Any]:
    """Report whether local TOTP step-up authentication is configured for root-command approvals. Never returns the secret."""
    return backend.sudo_2fa_status()


@mcp.tool()
def run_sudo_command(sudo_request_id: str, context: Context[Any, Any]) -> dict[str, Any]:
    """Execute one exact root command that the user already approved with 2FA. The command text is stored by the broker and cannot be changed here."""
    try:
        return backend.run_sudo_command(sudo_request_id, _session_key(context))
    except BrokerError as exc:
        return {"ok": False, "code": exc.code, "error": str(exc)}


@mcp.tool()
def get_nodes(include_revoked: bool = True) -> dict[str, Any]:
    """List enrolled nodes. Set include_revoked=false to hide revoked nodes."""
    return backend.list_nodes(include_revoked)


@mcp.tool()
def get_node(node_reference: str) -> dict[str, Any]:
    """Show detailed coordinator telemetry for one node by ID, unique prefix, or exact name."""
    return backend.get_node(node_reference)


@mcp.tool()
def diagnose_node(node_reference: str) -> dict[str, Any]:
    """Explain visible health problems for one node using coordinator telemetry."""
    return backend.diagnose_node(node_reference)


@mcp.tool()
def get_node_version_drift() -> dict[str, Any]:
    """Group active nodes by daemon version and report whether versions differ."""
    return backend.version_drift()


@mcp.tool()
def get_pending_nodes(include_all: bool = False) -> dict[str, Any]:
    """List pending join requests; include_all also returns historical requests."""
    return backend.list_pending_nodes(include_all)


@mcp.tool()
def get_audit_log(limit: int = 50) -> list[dict[str, Any]]:
    """Return recent shell, bridge, authorization, and privileged-broker audit records."""
    return backend.audit_recent(limit)


@mcp.tool()
def get_authorization_status(context: Context[Any, Any], authorization_request_id: str | None = None) -> dict[str, Any]:
    """Show active scoped authorization capabilities, optionally for one approval request ID."""
    return backend.authorization_status(authorization_request_id, _session_key(context))


@mcp.tool()
def revoke_admin_access(context: Context[Any, Any], authorization_request_id: str | None = None) -> dict[str, Any]:
    """Revoke one temporary admin capability, or all current capabilities when no request ID is supplied."""
    return backend.revoke_authorization(authorization_request_id, _session_key(context))



@mcp.tool()
def get_local_node_slots() -> dict[str, Any]:
    """Show the saved/default job-slot setting for the local node when readable without elevation."""
    return backend.local_node_slots()


@mcp.tool()
def get_privasearch_health() -> dict[str, Any]:
    """Read PrivaSearch /health."""
    return backend.privasearch_health()


@mcp.tool()
def get_privasearch_status() -> dict[str, Any]:
    """Read authenticated PrivaSearch operator /status through the root broker without exposing its token."""
    return backend.privasearch_status()


@mcp.tool()
def get_privasearch_summary() -> dict[str, Any]:
    """Return a concise crawler/index summary: queue, throughput, quality, concentration and warnings."""
    return backend.privasearch_summary()


@mcp.tool()
def get_update_status() -> dict[str, Any]:
    """Run a fresh verified update check and return the latest per-app events only."""
    return backend.check_updates()


@mcp.tool()
def get_update_history(limit: int = 100) -> dict[str, Any]:
    """Read bounded historical logs from the Priva application updater."""
    return backend.update_history(limit)


@mcp.tool()
def get_update_schedule() -> dict[str, Any]:
    """Show the systemd schedule/state for the automatic Priva updater."""
    return backend.updater_schedule()


@mcp.tool()
async def restart_service(service: str, context: Context[Any, Any], authorization_request_id: str | None = None) -> dict[str, Any]:
    """Restart one allowlisted Priva service after scoped interactive approval if needed."""
    ok, auth = _ensure_scope(context, "privanet.services", f"Restart {service}", authorization_request_id)
    if not ok:
        return auth
    try:
        result = backend.restart_service(service, str(authorization_request_id), _session_key(context))
    except BrokerError as exc:
        return {"ok": False, "code": exc.code, "error": str(exc)}
    result["authorization"] = auth
    return result


@mcp.tool()
async def apply_available_updates(context: Context[Any, Any]) -> dict[str, Any]:
    """Install verified Priva application updates with the automatic privanet.updates policy."""
    return backend.apply_updates(_session_key(context))


@mcp.tool()
def get_chat_admin_update_status() -> dict[str, Any]:
    """Check the installed and published PrivaNet Chat Admin versions."""
    return backend.chat_admin_update_status()


@mcp.tool()
async def update_chat_admin(context: Context[Any, Any], authorization_request_id: str | None = None) -> dict[str, Any]:
    """Start the Chat Admin self-updater after a broker-verified TOTP approval for the update scope."""
    ok, auth = _ensure_scope(context, "privanet.updates", "Update PrivaNet Chat Admin", authorization_request_id)
    if not ok:
        return auth
    try:
        result = backend.apply_chat_admin_update(str(authorization_request_id), _session_key(context))
    except BrokerError as exc:
        return {"ok": False, "code": exc.code, "error": str(exc)}
    result["authorization"] = auth
    return result


@mcp.tool()
async def approve_node(request_code: str, capabilities: list[str], context: Context[Any, Any], label: str | None = None, authorization_request_id: str | None = None) -> dict[str, Any]:
    """Approve a pending node with explicit capabilities after scoped approval if needed."""
    ok, auth = _ensure_scope(context, "privanet.nodes", f"Approve pending node request {request_code}", authorization_request_id)
    if not ok:
        return auth
    result = backend.approve_node(request_code, capabilities, label, str(authorization_request_id), _session_key(context))
    result["authorization"] = auth
    return result


@mcp.tool()
async def deny_node(request_code: str, context: Context[Any, Any], authorization_request_id: str | None = None) -> dict[str, Any]:
    """Deny a pending node request after scoped approval if needed."""
    ok, auth = _ensure_scope(context, "privanet.nodes", f"Deny pending node request {request_code}", authorization_request_id)
    if not ok:
        return auth
    result = backend.deny_node(request_code, str(authorization_request_id), _session_key(context))
    result["authorization"] = auth
    return result


@mcp.tool()
async def rename_node(node_reference: str, context: Context[Any, Any], name: str | None = None, clear: bool = False, authorization_request_id: str | None = None) -> dict[str, Any]:
    """Rename an enrolled node, or clear its display name, after scoped approval if needed."""
    ok, auth = _ensure_scope(context, "privanet.nodes", f"Rename node {node_reference}", authorization_request_id)
    if not ok:
        return auth
    result = backend.rename_node(node_reference, name, clear, str(authorization_request_id), _session_key(context))
    result["authorization"] = auth
    return result


@mcp.tool()
async def revoke_node(node_reference: str, context: Context[Any, Any], authorization_request_id: str | None = None, confirmation_request_id: str | None = None) -> dict[str, Any]:
    """Revoke a node after node-admin authorization and a separate one-action confirmation."""
    reason = f"Revoke enrolled node {node_reference}"
    ok, auth = _ensure_scope(context, "privanet.nodes", reason, authorization_request_id)
    if not ok:
        return auth
    shown = backend.get_node(node_reference)
    node = shown.get("node") if shown.get("ok") else None
    if not isinstance(node, dict) or not node.get("nodeId"):
        return {"ok": False, "code": "NODE_UNAVAILABLE", "node_reference": node_reference, "error": shown.get("error") or "Node could not be resolved"}
    node_id = str(node["nodeId"])
    try:
        result = backend.revoke_node(node_id, str(authorization_request_id), confirmation_request_id, _session_key(context))
    except BrokerError as exc:
        if exc.code == "CONFIRMATION_REQUIRED":
            return {"ok": False, "code": "DESTRUCTIVE_CONFIRMATION_REQUIRED", "action": "admin.node.revoke", "target": node_id, "reason": f"Revoke node {node.get('displayName') or node_id}. This invalidates its credentials and hands back leased jobs.", "authorizationRequestId": authorization_request_id, "nextTool": "request_action_confirmation"}
        return {"ok": False, "code": exc.code, "error": str(exc)}
    result["authorization"] = auth
    return result


@mcp.tool()
async def set_local_node_slots(slots: int, context: Context[Any, Any], authorization_request_id: str | None = None) -> dict[str, Any]:
    """Save a local job-slot override after scoped approval if needed."""
    ok, auth = _ensure_scope(context, "privanet.node_local", f"Set local node job slots to {slots}", authorization_request_id)
    if not ok:
        return auth
    result = backend.set_local_node_slots(slots, str(authorization_request_id), _session_key(context))
    result["authorization"] = auth
    return result


@mcp.tool()
async def clear_local_node_slots(context: Context[Any, Any], authorization_request_id: str | None = None) -> dict[str, Any]:
    """Clear the local job-slot override after scoped approval if needed."""
    ok, auth = _ensure_scope(context, "privanet.node_local", "Clear the local node job-slot override", authorization_request_id)
    if not ok:
        return auth
    result = backend.clear_local_node_slots(str(authorization_request_id), _session_key(context))
    result["authorization"] = auth
    return result


@mcp.tool()
async def install_system_package(package: str, context: Context[Any, Any], authorization_request_id: str | None = None, confirmation_request_id: str | None = None) -> dict[str, Any]:
    """Install one validated Debian package after package scope and a separate one-action confirmation."""
    package = package.strip().lower()
    reason = f"Install Debian package {package}"
    ok, auth = _ensure_scope(context, "system.packages", reason, authorization_request_id)
    if not ok:
        return auth
    try:
        result = backend.install_package(package, str(authorization_request_id), confirmation_request_id, _session_key(context))
    except BrokerError as exc:
        if exc.code == "CONFIRMATION_REQUIRED":
            return {"ok": False, "code": "DESTRUCTIVE_CONFIRMATION_REQUIRED", "action": "package.install", "target": package, "reason": f"Install system package '{package}' as root using apt-get. Package maintainer scripts run with root privileges.", "authorizationRequestId": authorization_request_id, "nextTool": "request_action_confirmation"}
        return {"ok": False, "code": exc.code, "error": str(exc)}
    result["authorization"] = auth
    return result


app = mcp.streamable_http_app()
