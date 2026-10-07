from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import socket
import sqlite3
import struct
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

SOCKET_PATH = os.environ.get("PRIVANET_CHAT_ADMIN_BROKER_SOCKET", "/run/privanet-chat-admin/broker.sock")
CONFIG_PATH = os.environ.get("PRIVANET_CHAT_ADMIN_CONFIG", "/etc/privanet-chat-admin/config.json")
STATE_DB = os.environ.get("PRIVANET_CHAT_ADMIN_BROKER_DB", "/var/lib/privanet-chat-admin/broker.sqlite3")
TOTP_SECRET_PATH = os.environ.get("PRIVANET_CHAT_ADMIN_TOTP_SECRET", "/var/lib/privanet-chat-admin-broker/totp.secret")
MAX_REQUEST = 128 * 1024

CONFIRMABLE_ACTIONS = {"admin.node.revoke", "package.install"}

SCOPES = {
    "privanet.services",
    "privanet.nodes",
    "privanet.node_local",
    "privanet.updates",
    "system.packages",
    "system.sudo",
}

APPROVAL_SCOPES = SCOPES - {"system.sudo"}
SENSITIVE_APPROVAL_SCOPES = {"privanet.nodes", "privanet.updates", "system.packages"}

REQUIRED_SCOPE = {
    "service.restart": "privanet.services",
    "admin.node.approve": "privanet.nodes",
    "admin.node.deny": "privanet.nodes",
    "admin.node.rename": "privanet.nodes",
    "admin.node.revoke": "privanet.nodes",
    "node.slots.set": "privanet.node_local",
    "node.slots.clear": "privanet.node_local",
    "package.install": "system.packages",
    "update.self_apply": "privanet.updates",
    "root.run": "system.sudo",
}

AUTO_SCOPE = {
    "update.apply": "privanet.updates",
}


class AuthorizationRequired(PermissionError):
    def __init__(self, scope: str):
        super().__init__(f"authorization required: {scope}")
        self.scope = scope


class ConfirmationRequired(PermissionError):
    def __init__(self, action: str, target: str):
        super().__init__(f"confirmation required: {action} {target}")
        self.action = action
        self.target = target


def _config() -> dict[str, Any]:
    with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _ensure_column(db: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row[1] for row in db.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in columns:
        db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _db() -> sqlite3.Connection:
    Path(STATE_DB).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(STATE_DB)
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS auth_requests(
          id TEXT PRIMARY KEY,
          created_at INTEGER NOT NULL,
          session_key TEXT NOT NULL,
          scope TEXT NOT NULL,
          reason TEXT NOT NULL,
          consumed INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS leases(
          id TEXT PRIMARY KEY,
          created_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL,
          session_key TEXT NOT NULL,
          scope TEXT NOT NULL,
          reason TEXT NOT NULL,
          uses_remaining INTEGER
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS confirmation_requests(
          id TEXT PRIMARY KEY,
          created_at INTEGER NOT NULL,
          session_key TEXT NOT NULL,
          action TEXT NOT NULL,
          target TEXT NOT NULL,
          reason TEXT NOT NULL,
          consumed INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS confirmations(
          id TEXT PRIMARY KEY,
          created_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL,
          session_key TEXT NOT NULL,
          action TEXT NOT NULL,
          target TEXT NOT NULL,
          uses_remaining INTEGER NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS audit(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts INTEGER NOT NULL,
          action TEXT NOT NULL,
          scope TEXT,
          session_key TEXT,
          ok INTEGER NOT NULL,
          detail TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS sudo_requests(
          id TEXT PRIMARY KEY,
          created_at INTEGER NOT NULL,
          request_expires_at INTEGER NOT NULL,
          command TEXT NOT NULL,
          command_sha256 TEXT NOT NULL,
          reason TEXT NOT NULL,
          timeout_seconds INTEGER NOT NULL,
          state TEXT NOT NULL DEFAULT 'pending',
          approved_at INTEGER,
          execution_expires_at INTEGER,
          used_at INTEGER,
          totp_counter INTEGER
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS security_meta(
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS totp_attempts(
          ts INTEGER NOT NULL,
          ok INTEGER NOT NULL
        )
        """
    )
    _ensure_column(db, "leases", "request_id", "TEXT")
    _ensure_column(db, "confirmations", "request_id", "TEXT")
    db.execute("CREATE INDEX IF NOT EXISTS idx_leases_request_scope ON leases(request_id,scope,expires_at)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_confirmations_request ON confirmations(request_id,action,target,expires_at)")
    db.commit()
    return db


def _audit(action: str, scope: str | None, session_key: str | None, ok: bool, detail: str) -> None:
    with _db() as db:
        db.execute(
            "INSERT INTO audit(ts,action,scope,session_key,ok,detail) VALUES(?,?,?,?,?,?)",
            (int(time.time()), action, scope, session_key, int(ok), detail[:4000]),
        )


def _clean_session(value: Any) -> str:
    text = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{8,160}", text):
        raise ValueError("invalid session key")
    return text


def _clean_request_id(value: Any, prefix: str = "req_") -> str:
    text = str(value or "").strip()
    if not re.fullmatch(re.escape(prefix) + r"[0-9a-f]{32}", text):
        raise ValueError("invalid approval request id")
    return text


def _active_lease(scope: str, request_id: str | None, consume: bool) -> dict[str, Any] | None:
    if not request_id:
        return None
    try:
        request_id = _clean_request_id(request_id, "req_")
    except ValueError:
        return None
    now = int(time.time())
    with _db() as db:
        db.execute("DELETE FROM leases WHERE expires_at <= ? OR uses_remaining = 0", (now,))
        row = db.execute(
            "SELECT id,created_at,expires_at,scope,reason,uses_remaining,request_id FROM leases "
            "WHERE request_id=? AND scope=? AND expires_at>? AND (uses_remaining IS NULL OR uses_remaining>0) "
            "ORDER BY expires_at DESC LIMIT 1",
            (request_id, scope, now),
        ).fetchone()
        if row is None:
            return None
        if consume and row[5] is not None:
            db.execute("UPDATE leases SET uses_remaining=uses_remaining-1 WHERE id=?", (row[0],))
        db.commit()
    return {
        "id": row[0],
        "createdAt": row[1],
        "expiresAt": row[2],
        "scope": row[3],
        "reason": row[4],
        "usesRemaining": None if row[5] is None else max(0, row[5] - (1 if consume else 0)),
        "requestId": row[6],
    }


def _require_scope(action: str, request_id: str | None, *, consume: bool = True) -> dict[str, Any] | None:
    scope = REQUIRED_SCOPE.get(action)
    if scope is None:
        return None
    lease = _active_lease(scope, request_id, consume=consume)
    if lease is None:
        raise AuthorizationRequired(scope)
    return lease


def _active_confirmation(action: str, target: str, request_id: str | None, consume: bool) -> dict[str, Any] | None:
    if not request_id:
        return None
    try:
        request_id = _clean_request_id(request_id, "confirm_req_")
    except ValueError:
        return None
    now = int(time.time())
    with _db() as db:
        db.execute("DELETE FROM confirmations WHERE expires_at <= ? OR uses_remaining <= 0", (now,))
        row = db.execute(
            "SELECT id,created_at,expires_at,action,target,uses_remaining,request_id FROM confirmations "
            "WHERE request_id=? AND action=? AND target=? AND expires_at>? AND uses_remaining>0 "
            "ORDER BY expires_at DESC LIMIT 1",
            (request_id, action, target, now),
        ).fetchone()
        if row is None:
            return None
        if consume:
            db.execute("UPDATE confirmations SET uses_remaining=uses_remaining-1 WHERE id=?", (row[0],))
        db.commit()
    return {
        "id": row[0], "createdAt": row[1], "expiresAt": row[2], "action": row[3],
        "target": row[4], "usesRemaining": max(0, row[5] - (1 if consume else 0)), "requestId": row[6],
    }


def _require_confirmation(action: str, target: str, request_id: str | None, *, consume: bool = True) -> dict[str, Any]:
    confirmation = _active_confirmation(action, target, request_id, consume=consume)
    if confirmation is None:
        raise ConfirmationRequired(action, target)
    return confirmation


def _totp_secret() -> str | None:
    try:
        secret = Path(TOTP_SECRET_PATH).read_text(encoding="ascii").strip().replace(" ", "").upper()
    except OSError:
        return None
    if not re.fullmatch(r"[A-Z2-7]{16,128}", secret):
        return None
    return secret


def _totp_at(secret: str, counter: int) -> str:
    key = base64.b32decode(secret, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{value:06d}"


def _verify_totp(code: Any) -> int:
    code_text = str(code or "").strip()
    if not re.fullmatch(r"[0-9]{6}", code_text):
        raise PermissionError("invalid two-factor code")
    secret = _totp_secret()
    if secret is None:
        raise PermissionError("two-factor authentication is not configured")
    now = int(time.time())
    with _db() as db:
        db.execute("DELETE FROM totp_attempts WHERE ts < ?", (now - 300,))
        failures = db.execute("SELECT COUNT(*) FROM totp_attempts WHERE ts>=? AND ok=0", (now - 300,)).fetchone()[0]
        if failures >= 5:
            raise PermissionError("too many failed two-factor attempts; try again later")
        last_row = db.execute("SELECT value FROM security_meta WHERE key='last_totp_counter'").fetchone()
        last_counter = int(last_row[0]) if last_row else -1
        current = now // 30
        matched = None
        for counter in (current - 1, current, current + 1):
            if counter > last_counter and hmac.compare_digest(_totp_at(secret, counter), code_text):
                matched = counter
                break
        if matched is None:
            db.execute("INSERT INTO totp_attempts(ts,ok) VALUES(?,0)", (now,))
            db.commit()
            raise PermissionError("invalid or already-used two-factor code")
        db.execute("INSERT INTO totp_attempts(ts,ok) VALUES(?,1)", (now,))
        db.execute("INSERT INTO security_meta(key,value) VALUES('last_totp_counter',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(matched),))
        db.commit()
    return matched


def _run_root_command(command: str, timeout_seconds: int) -> dict[str, Any]:
    unit = "privanet-chat-admin-sudo-" + secrets.token_hex(6) + ".service"
    timeout_seconds = max(1, min(int(timeout_seconds), 300))
    return _run([
        "/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect",
        "--unit", unit,
        f"--property=RuntimeMaxSec={timeout_seconds}s",
        "--property=UMask=0077",
        "--property=StandardInput=null",
        "--property=NoNewPrivileges=yes",
        "/usr/bin/env", "-i",
        "PATH=/opt/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG=C.UTF-8", "HOME=/root",
        "/bin/bash", "--noprofile", "--norc", "-lc", command,
    ], timeout=timeout_seconds + 30)


def _run(argv: list[str], timeout: int = 60, env: dict[str, str] | None = None) -> dict[str, Any]:
    proc = subprocess.run(
        argv,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
        env=env or {"PATH": "/opt/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
    )
    return {
        "ok": proc.returncode == 0,
        "code": proc.returncode,
        "stdout": proc.stdout[-40000:],
        "stderr": proc.stderr[-20000:],
    }




def _run_unit(unit: str, start_timeout: int) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9_.@-]+\.service", unit):
        raise ValueError("invalid unit")
    started_at = int(time.time()) - 1
    started = _run(["systemctl", "start", unit], timeout=start_timeout)
    props = _run(["systemctl", "show", unit, "--no-page", "--property=Result,ExecMainStatus,ActiveState,SubState"], timeout=30)
    values = {}
    for line in props["stdout"].splitlines():
        if "=" in line:
            k,v=line.split("=",1); values[k]=v
    logs = _run(["journalctl", "-u", unit, "--since", f"@{started_at}", "--no-pager", "--output=cat", "-n", "500"], timeout=30)
    ok = started["ok"] and values.get("Result") in {"", "success"} and values.get("ExecMainStatus") in {"", "0"}
    return {"ok": ok, "state": values, "output": logs["stdout"], "error": started["stderr"] or props["stderr"] or logs["stderr"] or None}

def _json_output(result: dict[str, Any]) -> Any:
    if not result["ok"]:
        return None
    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        return result["stdout"]


def _admin(args: list[str], timeout: int = 60) -> dict[str, Any]:
    cfg = _config()
    binary = cfg.get("executables", {}).get("privanet_admin", "/usr/local/bin/privanet-admin")
    return _run([binary, *args], timeout=timeout)


def _service_alias(name: str) -> str:
    cfg = _config()
    services = cfg.get("managed_services", {})
    if name not in services:
        raise ValueError("unknown managed service")
    return str(services[name])


def _node_ref(value: Any) -> str:
    text = str(value or "").strip()
    if not text or len(text) > 160 or text.startswith("-") or not re.fullmatch(r"[A-Za-z0-9_.:@+\- ]+", text):
        raise ValueError("invalid node reference")
    return text


def _request_code(value: Any) -> str:
    text = str(value or "").strip().upper().replace(" ", "-")
    if not re.fullmatch(r"[A-Z0-9]{4}-?[A-Z0-9]{4}", text):
        raise ValueError("invalid request code")
    return text if "-" in text else f"{text[:4]}-{text[4:]}"


def _label(value: Any) -> str:
    text = str(value or "").strip()
    if not text or len(text) > 80 or any(ord(ch) < 32 for ch in text):
        raise ValueError("invalid label")
    return text


def _caps(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError("capabilities required")
    out: list[str] = []
    for item in value:
        text = str(item).strip()
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,95}", text):
            raise ValueError("invalid capability")
        if text not in out:
            out.append(text)
    return out


def _search_status() -> dict[str, Any]:
    cfg = _config()
    search = cfg.get("privasearch", {})
    base = str(search.get("base_url", "http://127.0.0.1:4020")).rstrip("/")
    parsed = urllib.parse.urlsplit(base)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("PrivaSearch URL must be loopback HTTP")
    token = None
    env_path = Path(str(search.get("env_file", "/etc/privasearch/privasearch.env")))
    try:
        for raw in env_path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].lstrip()
            if "=" not in line:
                continue
            key, val = line.split("=", 1)
            if key.strip() == "PRIVASEARCH_API_TOKEN":
                try:
                    parsed_val = shlex.split(val.strip(), posix=True)
                    token = parsed_val[0] if len(parsed_val) == 1 else val.strip().strip("'\"")
                except ValueError:
                    token = val.strip().strip("'\"")
                break
    except OSError:
        pass
    headers = {"Accept": "application/json", "User-Agent": "PrivaNet-Chat-Admin-Broker/0.3.3.1"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(base + "/status", headers=headers, method="GET")
    opener = urllib.request.build_opener(urllib.request.HTTPHandler())
    try:
        with opener.open(req, timeout=5) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
            if len(raw) > 2 * 1024 * 1024:
                raise ValueError("PrivaSearch response too large")
            return {"ok": 200 <= response.status < 300, "http_status": response.status, "data": json.loads(raw.decode("utf-8")), "error": None}
    except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError) as exc:
        return {"ok": False, "http_status": None, "data": None, "error": str(exc)[:1000]}


def handle(request: dict[str, Any]) -> dict[str, Any]:
    action = str(request.get("action", ""))
    params = request.get("params") or {}
    if not isinstance(params, dict):
        raise ValueError("params must be an object")
    session_key = _clean_session(request.get("session_key", "session-unknown"))

    if action == "auth.prepare":
        scope = str(params.get("scope", ""))
        reason = str(params.get("reason", "")).strip()[:500]
        if scope not in APPROVAL_SCOPES or not reason:
            raise ValueError("invalid authorization request")
        req_id = "req_" + secrets.token_hex(16)
        created = int(time.time())
        with _db() as db:
            db.execute(
                "INSERT INTO auth_requests(id,created_at,session_key,scope,reason,consumed) VALUES(?,?,?,?,?,0)",
                (req_id, created, session_key, scope, reason),
            )
            db.commit()
        _audit("auth.prepare", scope, session_key, True, reason)
        return {"ok": True, "requestId": req_id, "scope": scope, "reason": reason, "expiresAt": created + 300}

    if action == "auth.check":
        req_id = str(params.get("request_id", ""))
        scope = str(params.get("scope", ""))
        if scope not in SCOPES:
            raise ValueError("invalid scope")
        lease = _active_lease(scope, req_id, consume=False)
        return {"ok": lease is not None, "scope": scope, "lease": lease}

    if action == "auth.grant":
        req_id = _clean_request_id(params.get("request_id"), "req_")
        duration = str(params.get("duration", ""))
        durations = {"once": (300, 1), "15m": (900, None), "30m": (1800, None), "60m": (3600, None)}
        if duration not in durations:
            raise ValueError("invalid duration")
        now = int(time.time())
        with _db() as db:
            row = db.execute(
                "SELECT session_key,scope,reason,created_at,consumed FROM auth_requests WHERE id=?",
                (req_id,),
            ).fetchone()
            if row is None or row[4] or now - row[3] > 300 or row[1] == "system.sudo":
                raise PermissionError("authorization request expired or invalid")
            if row[1] in SENSITIVE_APPROVAL_SCOPES:
                _verify_totp(params.get("totp_code"))
            seconds, uses = durations[duration]
            lease_id = "lease_" + secrets.token_hex(16)
            db.execute("UPDATE auth_requests SET consumed=1 WHERE id=?", (req_id,))
            db.execute(
                "INSERT INTO leases(id,created_at,expires_at,session_key,scope,reason,uses_remaining,request_id) VALUES(?,?,?,?,?,?,?,?)",
                (lease_id, now, now + seconds, row[0], row[1], row[2], uses, req_id),
            )
            db.commit()
        step_up = "; 2fa=verified" if row[1] in SENSITIVE_APPROVAL_SCOPES else ""
        _audit("auth.grant", row[1], row[0], True, f"request={req_id}; duration={duration}{step_up}; {row[2]}")
        return {"ok": True, "requestId": req_id, "scope": row[1], "expiresAt": now + seconds, "duration": duration, "usesRemaining": uses, "stepUp": "TOTP" if row[1] in SENSITIVE_APPROVAL_SCOPES else None}

    if action == "auth.deny":
        req_id = _clean_request_id(params.get("request_id"), "req_")
        now = int(time.time())
        with _db() as db:
            row = db.execute(
                "SELECT session_key,scope,reason,created_at,consumed FROM auth_requests WHERE id=?",
                (req_id,),
            ).fetchone()
            if row is None or row[4] or now - row[3] > 300:
                raise PermissionError("authorization request expired or invalid")
            db.execute("UPDATE auth_requests SET consumed=1 WHERE id=?", (req_id,))
            db.commit()
        _audit("auth.deny", row[1], row[0], True, f"request={req_id}; {row[2]}")
        return {"ok": True, "denied": True, "requestId": req_id, "scope": row[1]}

    if action == "confirm.prepare":
        confirm_action = str(params.get("action", ""))
        target = str(params.get("target", "")).strip()
        reason = str(params.get("reason", "")).strip()[:500]
        auth_request_id = str(params.get("authorization_request_id", ""))
        if confirm_action not in CONFIRMABLE_ACTIONS or not target or len(target) > 200 or not reason:
            raise ValueError("invalid confirmation request")
        if confirm_action == "package.install":
            target = target.lower()
            if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]{0,127}", target):
                raise ValueError("invalid package confirmation target")
        else:
            target = _node_ref(target)
        required_scope = REQUIRED_SCOPE[confirm_action]
        if _active_lease(required_scope, auth_request_id, consume=False) is None:
            raise AuthorizationRequired(required_scope)
        req_id = "confirm_req_" + secrets.token_hex(16)
        created = int(time.time())
        with _db() as db:
            db.execute(
                "INSERT INTO confirmation_requests(id,created_at,session_key,action,target,reason,consumed) VALUES(?,?,?,?,?,?,0)",
                (req_id, created, session_key, confirm_action, target, reason),
            )
            db.commit()
        _audit("confirm.prepare", required_scope, session_key, True, f"auth={auth_request_id}; {confirm_action} {target}: {reason}")
        return {"ok": True, "requestId": req_id, "action": confirm_action, "target": target, "reason": reason, "expiresAt": created + 300}

    if action == "confirm.grant":
        req_id = _clean_request_id(params.get("request_id"), "confirm_req_")
        now = int(time.time())
        with _db() as db:
            row = db.execute(
                "SELECT session_key,action,target,reason,created_at,consumed FROM confirmation_requests WHERE id=?",
                (req_id,),
            ).fetchone()
            if row is None or row[5] or now - row[4] > 300:
                raise PermissionError("confirmation request expired or invalid")
            confirmation_id = "confirm_" + secrets.token_hex(16)
            db.execute("UPDATE confirmation_requests SET consumed=1 WHERE id=?", (req_id,))
            db.execute(
                "INSERT INTO confirmations(id,created_at,expires_at,session_key,action,target,uses_remaining,request_id) VALUES(?,?,?,?,?,?,1,?)",
                (confirmation_id, now, now + 300, row[0], row[1], row[2], req_id),
            )
            db.commit()
        _audit("confirm.grant", REQUIRED_SCOPE.get(row[1]), row[0], True, f"request={req_id}; {row[1]} {row[2]}")
        return {"ok": True, "requestId": req_id, "action": row[1], "target": row[2], "expiresAt": now + 300, "usesRemaining": 1}

    if action == "confirm.deny":
        req_id = _clean_request_id(params.get("request_id"), "confirm_req_")
        now = int(time.time())
        with _db() as db:
            row = db.execute(
                "SELECT session_key,action,target,reason,created_at,consumed FROM confirmation_requests WHERE id=?",
                (req_id,),
            ).fetchone()
            if row is None or row[5] or now - row[4] > 300:
                raise PermissionError("confirmation request expired or invalid")
            db.execute("UPDATE confirmation_requests SET consumed=1 WHERE id=?", (req_id,))
            db.commit()
        _audit("confirm.deny", REQUIRED_SCOPE.get(row[1]), row[0], True, f"request={req_id}; {row[1]} {row[2]}: {row[3]}")
        return {"ok": True, "denied": True, "requestId": req_id, "action": row[1], "target": row[2]}

    if action == "sudo.2fa_status":
        return {"ok": True, "configured": _totp_secret() is not None, "method": "TOTP", "command": "privanet-chat-admin-2fa setup"}

    if action == "sudo.prepare":
        if _totp_secret() is None:
            raise PermissionError("two-factor authentication is not configured; run privanet-chat-admin-2fa setup locally as root")
        command = str(params.get("command", "")).strip()
        reason = str(params.get("reason", "")).strip()[:500]
        timeout_seconds = max(1, min(int(params.get("timeout_seconds", 30)), 300))
        if not command or len(command) > 8000 or "\x00" in command or not reason:
            raise ValueError("invalid sudo command request")
        req_id = "sudo_req_" + secrets.token_hex(16)
        created = int(time.time())
        digest = hashlib.sha256(command.encode("utf-8")).hexdigest()
        with _db() as db:
            db.execute(
                "INSERT INTO sudo_requests(id,created_at,request_expires_at,command,command_sha256,reason,timeout_seconds,state) VALUES(?,?,?,?,?,?,?,'pending')",
                (req_id, created, created + 300, command, digest, reason, timeout_seconds),
            )
            db.commit()
        _audit("sudo.prepare", "system.sudo", session_key, True, f"request={req_id}; command_sha256={digest}; {reason}")
        return {"ok": True, "requestId": req_id, "command": command, "commandSha256": digest, "reason": reason, "timeoutSeconds": timeout_seconds, "expiresAt": created + 300}

    if action == "sudo.grant":
        req_id = _clean_request_id(params.get("request_id"), "sudo_req_")
        now = int(time.time())
        with _db() as db:
            row = db.execute("SELECT request_expires_at,state,command_sha256,reason FROM sudo_requests WHERE id=?", (req_id,)).fetchone()
        if row is None or row[1] != "pending" or now > row[0]:
            raise PermissionError("sudo request expired or invalid")
        counter = _verify_totp(params.get("totp_code"))
        with _db() as db:
            updated = db.execute(
                "UPDATE sudo_requests SET state='approved',approved_at=?,execution_expires_at=?,totp_counter=? WHERE id=? AND state='pending'",
                (now, now + 120, counter, req_id),
            ).rowcount
            db.commit()
        if updated != 1:
            raise PermissionError("sudo request expired or invalid")
        _audit("sudo.grant", "system.sudo", session_key, True, f"request={req_id}; command_sha256={row[2]}; 2fa=verified")
        return {"ok": True, "requestId": req_id, "scope": "system.sudo", "executionExpiresAt": now + 120, "usesRemaining": 1}

    if action == "sudo.deny":
        req_id = _clean_request_id(params.get("request_id"), "sudo_req_")
        now = int(time.time())
        with _db() as db:
            row = db.execute("SELECT state,request_expires_at,command_sha256 FROM sudo_requests WHERE id=?", (req_id,)).fetchone()
            if row is None or row[0] != "pending" or now > row[1]:
                raise PermissionError("sudo request expired or invalid")
            db.execute("UPDATE sudo_requests SET state='denied' WHERE id=?", (req_id,))
            db.commit()
        _audit("sudo.deny", "system.sudo", session_key, True, f"request={req_id}; command_sha256={row[2]}")
        return {"ok": True, "denied": True, "requestId": req_id}

    if action == "auth.status":
        now = int(time.time())
        request_filter = params.get("request_id")
        with _db() as db:
            db.execute("DELETE FROM leases WHERE expires_at <= ? OR uses_remaining = 0", (now,))
            if request_filter:
                request_filter = _clean_request_id(request_filter, "req_")
                rows = db.execute(
                    "SELECT created_at,expires_at,scope,reason,uses_remaining,request_id FROM leases WHERE request_id=? ORDER BY expires_at DESC",
                    (request_filter,),
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT created_at,expires_at,scope,reason,uses_remaining,request_id FROM leases WHERE request_id IS NOT NULL ORDER BY expires_at DESC"
                ).fetchall()
            db.commit()
        return {"ok": True, "leases": [
            {"createdAt": r[0], "expiresAt": r[1], "scope": r[2], "reason": r[3], "usesRemaining": r[4], "requestId": r[5]}
            for r in rows
        ]}

    if action == "auth.revoke_all":
        request_filter = params.get("request_id")
        with _db() as db:
            if request_filter:
                request_filter = _clean_request_id(request_filter, "req_")
                count = db.execute("DELETE FROM leases WHERE request_id=?", (request_filter,)).rowcount
            else:
                count = db.execute("DELETE FROM leases WHERE request_id IS NOT NULL").rowcount
            db.commit()
        _audit("auth.revoke_all", None, session_key, True, f"request={request_filter or 'all'}; revoked={count}")
        return {"ok": True, "revoked": count, "requestId": request_filter}

    if action == "audit.recent":
        limit = max(1, min(int(params.get("limit", 50)), 200))
        with _db() as db:
            rows = db.execute(
                "SELECT ts,action,scope,session_key,ok,detail FROM audit ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return {"ok": True, "entries": [
            {"ts": r[0], "action": r[1], "scope": r[2], "session": r[3], "ok": bool(r[4]), "detail": r[5]}
            for r in rows
        ]}

    # Read-only broker operations. They do not require an elevation lease.
    if action == "service.status":
        unit = _service_alias(str(params.get("service", "")))
        result = _run(["systemctl", "show", unit, "--no-page", "--property=ActiveState,SubState,MainPID,ExecMainStatus,ActiveEnterTimestamp,Result"])
        return {"ok": result["ok"], "unit": unit, "output": result["stdout"], "error": result["stderr"] or None}
    if action == "logs.read":
        unit = _service_alias(str(params.get("service", "")))
        lines = max(1, min(int(params.get("lines", 100)), 300))
        argv = ["journalctl", "-u", unit, "-n", str(lines), "--no-pager", "--output=short-iso"]
        priority = params.get("priority")
        if priority:
            if priority not in {"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}:
                raise ValueError("invalid priority")
            argv += ["-p", str(priority)]
        result = _run(argv)
        return {"ok": result["ok"], "logs": result["stdout"], "error": result["stderr"] or None}
    if action == "admin.nodes.list":
        result = _admin(["nodes", "list", "--json"])
        return {"ok": result["ok"], "data": _json_output(result), "error": result["stderr"] or None}
    if action == "admin.nodes.show":
        ref = _node_ref(params.get("node_reference"))
        result = _admin(["nodes", "show", ref, "--json"])
        return {"ok": result["ok"], "data": _json_output(result), "error": result["stderr"] or None}
    if action == "admin.requests.list":
        argv = ["requests", "list"]
        if bool(params.get("include_all")):
            argv.append("--all")
        argv.append("--json")
        result = _admin(argv)
        return {"ok": result["ok"], "data": _json_output(result), "error": result["stderr"] or None}
    if action == "search.status":
        return _search_status()
    if action == "node.slots.show":
        cfg = _config()
        binary = cfg.get("executables", {}).get("privanet_node", "/opt/privanet-node/current/bin/privanet-node")
        state_dir = str(cfg.get("local_node_state_dir", "/var/lib/privanet-node"))
        result = _run([binary, "slots", "show", "--json", "--state-dir", state_dir])
        return {"ok": result["ok"], "data": _json_output(result), "error": result["stderr"] or None}
    if action == "update.schedule":
        result = _run(["systemctl", "show", "privanet-update.timer", "--no-page", "--property=LoadState,ActiveState,SubState,LastTriggerUSec,NextElapseUSecRealtime"])
        return {"ok": result["ok"], "output": result["stdout"], "error": result["stderr"] or None}
    if action == "update.check":
        return _run_unit("privanet-chat-admin-update-check.service", 7200)

    if action == "update.self_check":
        result = _run(["/usr/local/bin/privanet-chat-admin-update", "--check"], timeout=120)
        _audit(action, "privanet.updates", session_key, result["ok"], result["stderr"] or result["stdout"])
        return {
            "ok": result["ok"],
            "scope": "privanet.updates",
            "authorization": "automatic",
            "output": result["stdout"],
            "error": result["stderr"] or None,
        }

    if action == "root.run":
        sudo_request_id = str(params.get("sudo_request_id", ""))
        try:
            sudo_request_id = _clean_request_id(sudo_request_id, "sudo_req_")
        except ValueError as exc:
            raise AuthorizationRequired("system.sudo") from exc
        now = int(time.time())
        with _db() as db:
            row = db.execute(
                "SELECT command,command_sha256,reason,timeout_seconds,state,execution_expires_at,used_at FROM sudo_requests WHERE id=?",
                (sudo_request_id,),
            ).fetchone()
            if row is None or row[4] != "approved" or row[5] is None or now > row[5] or row[6] is not None:
                raise AuthorizationRequired("system.sudo")
            updated = db.execute("UPDATE sudo_requests SET state='used',used_at=? WHERE id=? AND state='approved' AND used_at IS NULL", (now, sudo_request_id)).rowcount
            db.commit()
        if updated != 1:
            raise AuthorizationRequired("system.sudo")
        result = _run_root_command(str(row[0]), int(row[3]))
        _audit("root.run", "system.sudo", session_key, result["ok"], f"request={sudo_request_id}; command_sha256={row[1]}; reason={row[2]}")
        return {
            "ok": result["ok"], "executedAs": "root", "privilege": "sudo-2fa",
            "requestId": sudo_request_id, "commandSha256": row[1],
            "exitCode": result["code"], "stdout": result["stdout"], "stderr": result["stderr"],
        }

    destructive = action in CONFIRMABLE_ACTIONS
    authorization_request_id = params.get("authorization_request_id")
    confirmation_request_id = params.get("confirmation_request_id")
    lease = _require_scope(action, authorization_request_id, consume=not destructive)
    scope = REQUIRED_SCOPE.get(action) or AUTO_SCOPE.get(action)

    if action == "service.restart":
        unit = _service_alias(str(params.get("service", "")))
        result = _run(["systemctl", "restart", unit], timeout=120)
        state = _run(["systemctl", "show", unit, "--no-page", "--property=ActiveState,SubState,MainPID,ExecMainStatus,Result"])
        ok = result["ok"] and "ActiveState=active" in state["stdout"]
        _audit(action, scope, session_key, ok, unit)
        return {"ok": ok, "unit": unit, "state": state["stdout"], "error": result["stderr"] or state["stderr"] or None, "lease": lease}

    if action == "admin.node.approve":
        code = _request_code(params.get("request_code"))
        caps = _caps(params.get("capabilities"))
        argv = ["approve", code, "--capabilities", ",".join(caps)]
        if params.get("label") is not None:
            argv += ["--label", _label(params.get("label"))]
        argv.append("--json")
        result = _admin(argv)
        _audit(action, scope, session_key, result["ok"], f"request={code}; capabilities={','.join(caps)}; label={params.get('label') or ''}")
        return {"ok": result["ok"], "data": _json_output(result), "error": result["stderr"] or None, "lease": lease}

    if action == "admin.node.deny":
        code = _request_code(params.get("request_code"))
        result = _admin(["deny", code, "--json"])
        _audit(action, scope, session_key, result["ok"], code)
        return {"ok": result["ok"], "data": _json_output(result), "error": result["stderr"] or None, "lease": lease}

    if action == "admin.node.rename":
        ref = _node_ref(params.get("node_reference"))
        if params.get("clear"):
            argv = ["nodes", "rename", ref, "--clear"]
        else:
            argv = ["nodes", "rename", ref, _label(params.get("name"))]
        result = _admin(argv)
        _audit(action, scope, session_key, result["ok"], ref)
        return {"ok": result["ok"], "output": result["stdout"], "error": result["stderr"] or None, "lease": lease}

    if action == "admin.node.revoke":
        ref = _node_ref(params.get("node_reference"))
        shown = _admin(["nodes", "show", ref, "--json"])
        if not shown["ok"]:
            _audit(action, scope, session_key, False, ref)
            return {"ok": False, "output": shown["stdout"], "error": shown["stderr"] or "node could not be resolved", "lease": lease}
        node = _json_output(shown)
        if not isinstance(node, dict) or not node.get("nodeId"):
            raise ValueError("node lookup did not return a nodeId")
        node_id = _node_ref(node["nodeId"])
        confirmation = _require_confirmation(action, node_id, confirmation_request_id, consume=True)
        lease = _require_scope(action, authorization_request_id, consume=True)
        result = _admin(["nodes", "revoke", node_id])
        _audit(action, scope, session_key, result["ok"], node_id)
        return {"ok": result["ok"], "output": result["stdout"], "error": result["stderr"] or None, "lease": lease, "confirmation": confirmation}

    if action in {"node.slots.set", "node.slots.clear"}:
        cfg = _config()
        binary = cfg.get("executables", {}).get("privanet_node", "/opt/privanet-node/current/bin/privanet-node")
        state_dir = str(cfg.get("local_node_state_dir", "/var/lib/privanet-node"))
        if action == "node.slots.set":
            maximum = int(cfg.get("limits", {}).get("max_job_slots", 32))
            slots = int(params.get("slots"))
            if slots < 1 or slots > maximum:
                raise ValueError("invalid slots")
            argv = [binary, "slots", "set", str(slots), "--json", "--state-dir", state_dir]
        else:
            argv = [binary, "slots", "clear", "--json", "--state-dir", state_dir]
        result = _run(argv)
        _audit(action, scope, session_key, result["ok"], result["stderr"] or result["stdout"])
        return {"ok": result["ok"], "data": _json_output(result), "error": result["stderr"] or None, "lease": lease}

    if action == "update.apply":
        result = _run_unit("privanet-update.service", 7200)
        _audit(action, scope, session_key, result["ok"], result.get("output", "")[-3000:] or str(result.get("error") or ""))
        result["scope"] = scope
        result["authorization"] = "automatic"
        return result

    if action == "update.self_apply":
        result = _run(["systemctl", "start", "--no-block", "privanet-chat-admin-self-update.service"], timeout=30)
        _audit(action, scope, session_key, result["ok"], "queued self-update" if result["ok"] else result["stderr"])
        return {
            "ok": result["ok"],
            "scope": scope,
            "authorization": "interactive-2fa",
            "state": "STARTED" if result["ok"] else "FAILED",
            "unit": "privanet-chat-admin-self-update.service",
            "output": result["stdout"],
            "error": result["stderr"] or None,
        }

    if action == "package.install":
        package = str(params.get("package", "")).strip().lower()
        if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]{0,127}", package):
            raise ValueError("invalid package name")
        confirmation = _require_confirmation(action, package, confirmation_request_id, consume=True)
        lease = _require_scope(action, authorization_request_id, consume=True)
        unit = "privanet-chat-admin-pkg-" + secrets.token_hex(6) + ".service"
        result = _run([
            "/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect",
            "--unit", unit, "/usr/bin/apt-get", "install", "-y", "--no-install-recommends", package
        ], timeout=1800)
        _audit(action, scope, session_key, result["ok"], package)
        return {"ok": result["ok"], "package": package, "output": result["stdout"][-12000:], "error": result["stderr"][-6000:] or None, "lease": lease, "confirmation": confirmation}

    raise ValueError("unsupported broker action")


def _serve_connection(conn: socket.socket) -> None:
    data = b""
    while b"\n" not in data and len(data) <= MAX_REQUEST:
        chunk = conn.recv(65536)
        if not chunk:
            break
        data += chunk
    try:
        if len(data) > MAX_REQUEST:
            raise ValueError("request too large")
        request = json.loads(data.split(b"\n", 1)[0].decode("utf-8"))
        if not isinstance(request, dict):
            raise ValueError("request must be an object")
        result = handle(request)
        response = {"ok": True, "result": result}
    except ConfirmationRequired as exc:
        response = {"ok": False, "error": {"code": "CONFIRMATION_REQUIRED", "message": str(exc), "action": exc.action, "target": exc.target}}
    except AuthorizationRequired as exc:
        response = {"ok": False, "error": {"code": "AUTHORIZATION_REQUIRED", "message": str(exc), "scope": exc.scope}}
    except PermissionError as exc:
        response = {"ok": False, "error": {"code": "AUTHORIZATION_REQUEST_INVALID", "message": str(exc)}}
    except Exception as exc:
        response = {"ok": False, "error": {"code": "BROKER_REQUEST_FAILED", "message": str(exc)[:500]}}
    conn.sendall((json.dumps(response, separators=(",", ":")) + "\n").encode("utf-8"))


def main() -> None:
    path = Path(SOCKET_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_socket():
        path.unlink()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(path))
        os.chmod(path, 0o660)
        server.listen(32)
        while True:
            conn, _ = server.accept()
            with conn:
                _serve_connection(conn)


if __name__ == "__main__":
    main()
