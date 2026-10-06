from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import socket
import sqlite3
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

VERSION = "0.3.3.1"

SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization:\s*bearer\s+)[^\s]+"),
    re.compile(r"(?i)(token|secret|password|api[_-]?key)(\s*[=:]\s*)[^\s,;]+"),
]

CONFIRMABLE_ACTIONS = {"admin.node.revoke", "package.install"}

SCOPES = {
    "privanet.services": "Restart allowlisted PrivaNet services.",
    "privanet.nodes": "Approve, deny, rename, or revoke PrivaNet nodes.",
    "privanet.node_local": "Change the local PrivaNet node's saved job-slot setting.",
    "privanet.updates": "Install verified Priva application and Chat Admin updates.",
    "system.packages": "Install a package from the server's configured APT repositories.",
    "system.sudo": "Run one exact non-interactive root command after per-command two-factor approval.",
}


def redact(text: str) -> str:
    out = text
    for pattern in SECRET_PATTERNS:
        if pattern.groups >= 2:
            out = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", out)
        else:
            out = pattern.sub(lambda m: f"{m.group(1)}[REDACTED]", out)
    return out


@dataclass(frozen=True)
class CommandResult:
    ok: bool
    code: int
    stdout: str
    stderr: str


class Runner:
    """Exact-argv subprocess runner with a deliberately small environment."""

    def __init__(self, timeout: int = 20, command_path: str | None = None, home: str = "/var/lib/privanet-chat-admin"):
        self.timeout = timeout
        self.command_path = command_path or "/opt/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        self.home = home

    def run(self, argv: list[str], timeout: int | None = None, cwd: str | None = None) -> CommandResult:
        proc = subprocess.run(
            argv,
            text=True,
            capture_output=True,
            timeout=timeout or self.timeout,
            check=False,
            cwd=cwd,
            env={"PATH": self.command_path, "LANG": "C.UTF-8", "HOME": self.home, "TMPDIR": "/tmp"},
        )
        return CommandResult(
            ok=proc.returncode == 0,
            code=proc.returncode,
            stdout=redact(proc.stdout[-40000:]),
            stderr=redact(proc.stderr[-20000:]),
        )


class BrokerError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class BrokerClient:
    def __init__(self, socket_path: str = "/run/privanet-chat-admin/broker.sock", timeout: float = 10):
        self.socket_path = socket_path
        self.timeout = timeout

    def call(self, action: str, params: dict[str, Any] | None = None, session_key: str = "session-default") -> dict[str, Any]:
        request = json.dumps({"action": action, "params": params or {}, "session_key": session_key}, separators=(",", ":")) + "\n"
        data = b""
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            sock.connect(self.socket_path)
            sock.sendall(request.encode("utf-8"))
            while b"\n" not in data and len(data) <= 2 * 1024 * 1024:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
        response = json.loads(data.split(b"\n", 1)[0].decode("utf-8"))
        if not response.get("ok"):
            error = response.get("error") or {}
            raise BrokerError(str(error.get("code", "BROKER_ERROR")), str(error.get("message", "Broker request failed")))
        return response.get("result") or {}


class ShellClient:
    def __init__(self, socket_path: str = "/run/privanet-chat-shell/shell.sock", timeout: float = 70):
        self.socket_path = socket_path
        self.timeout = timeout

    def run(self, command: str, timeout_seconds: int) -> dict[str, Any]:
        payload = json.dumps({"action": "run", "command": command, "timeout_seconds": timeout_seconds}, separators=(",", ":")) + "\n"
        data = b""
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            sock.connect(self.socket_path)
            sock.sendall(payload.encode("utf-8"))
            while b"\n" not in data and len(data) <= 2 * 1024 * 1024:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
        response = json.loads(data.split(b"\n", 1)[0].decode("utf-8"))
        if not response.get("ok"):
            err = response.get("error") or {}
            raise RuntimeError(str(err.get("message", "Shell service failed")))
        return response.get("result") or {}


class AuditLog:
    def __init__(self, db_path: str):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        with sqlite3.connect(self.db_path) as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS audit (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  ts INTEGER NOT NULL,
                  action TEXT NOT NULL,
                  target TEXT,
                  args_json TEXT NOT NULL,
                  ok INTEGER NOT NULL,
                  summary TEXT NOT NULL
                )
                """
            )

    def write(self, action: str, target: str | None, args: dict[str, Any], ok: bool, summary: str) -> None:
        safe_args = {
            k: ("[REDACTED]" if any(s in k.lower() for s in ("token", "secret", "password", "key")) else v)
            for k, v in args.items()
        }
        with sqlite3.connect(self.db_path) as db:
            db.execute(
                "INSERT INTO audit(ts,action,target,args_json,ok,summary) VALUES(?,?,?,?,?,?)",
                (int(time.time()), action, target, json.dumps(safe_args, sort_keys=True), int(ok), redact(summary)[:4000]),
            )

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 200))
        with sqlite3.connect(self.db_path) as db:
            rows = db.execute(
                "SELECT ts,action,target,args_json,ok,summary FROM audit ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [
            {"ts": row[0], "action": row[1], "target": row[2], "args": json.loads(row[3]), "ok": bool(row[4]), "summary": row[5]}
            for row in rows
        ]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


def _default_http_json(url: str, headers: dict[str, str], timeout: float, max_bytes: int) -> dict[str, Any]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("PrivaSearch URL must be loopback HTTP")
    request = urllib.request.Request(url, headers=headers, method="GET")
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(max_bytes + 1)
            if len(raw) > max_bytes:
                raise ValueError("PrivaSearch response too large")
            return {"ok": 200 <= response.status < 300, "http_status": response.status, "data": json.loads(raw.decode("utf-8")), "error": None}
    except urllib.error.HTTPError as exc:
        raw = exc.read(min(max_bytes, 8192)) if exc.fp else b""
        body = redact(raw.decode("utf-8", errors="replace"))
        return {"ok": False, "http_status": exc.code, "data": None, "error": body or str(exc.reason)}
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError, ValueError) as exc:
        return {"ok": False, "http_status": None, "data": None, "error": redact(str(exc))}


class AdminBackend:
    """PrivaNet administration with an unprivileged shell and a root broker for scoped mutations."""

    def __init__(
        self,
        config: dict[str, Any],
        runner: Runner | None = None,
        broker: BrokerClient | Any | None = None,
        shell: ShellClient | Any | None = None,
        http_json: Callable[[str, dict[str, str], float, int], dict[str, Any]] | None = None,
    ):
        self.config = config
        self.services: dict[str, str] = config.get("managed_services", {})
        executables = config.get("executables", {})
        self.admin_bin = executables.get("privanet_admin", "/usr/local/bin/privanet-admin")
        self.node_bin = executables.get("privanet_node", "/opt/privanet-node/current/bin/privanet-node")
        self.updater_bin = executables.get("privanet_update", "/usr/local/bin/privanet-update")
        updater = config.get("updater", {})
        self.updater_config_file = str(updater.get("config_file", "/etc/privanet/updater.json"))
        self.node_state_dir = config.get("local_node_state_dir", "/var/lib/privanet-node")
        limits = config.get("limits", {})
        self.max_log_lines = int(limits.get("max_log_lines", 300))
        self.max_job_slots = int(limits.get("max_job_slots", 32))
        self.update_timeout = int(limits.get("update_timeout_seconds", 7200))
        self.http_timeout = float(limits.get("http_timeout_seconds", 5))
        self.http_max_bytes = int(limits.get("http_max_bytes", 2 * 1024 * 1024))
        self.max_command_timeout = int(limits.get("max_command_timeout_seconds", 60))
        command_path = config.get("command_path", "/opt/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        self.command_home = str(config.get("command_home", "/var/lib/privanet-chat-admin"))
        self.command_cwd = str(config.get("command_cwd", "/var/lib/privanet-chat-admin/work"))
        self.runner = runner or Runner(int(limits.get("command_timeout_seconds", 20)), command_path, self.command_home)
        broker_cfg = config.get("broker", {})
        self.broker = broker or BrokerClient(str(broker_cfg.get("socket", "/run/privanet-chat-admin/broker.sock")), float(broker_cfg.get("timeout_seconds", 10)))
        shell_cfg = config.get("shell", {})
        self.shell = shell or ShellClient(str(shell_cfg.get("socket", "/run/privanet-chat-shell/shell.sock")), float(shell_cfg.get("timeout_seconds", 70)))
        self.audit = AuditLog(config.get("audit_db", "/var/lib/privanet-chat-admin/audit.sqlite3"))
        search = config.get("privasearch", {})
        self.search_base_url = str(search.get("base_url", "http://127.0.0.1:4020")).rstrip("/")
        self.http_json = http_json or _default_http_json
        self.diagnostic_paths = [str(p) for p in config.get("diagnostic_paths", ["/", "/var", "/opt"])]

    @staticmethod
    def _json_or_text(result: CommandResult) -> Any:
        if not result.ok:
            return None
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return result.stdout

    @staticmethod
    def _json_lines(text: str) -> list[Any]:
        rows: list[Any] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                rows.append({"message": redact(line)})
        return rows

    def broker_call(self, action: str, params: dict[str, Any] | None = None, session_key: str = "session-default") -> dict[str, Any]:
        return self.broker.call(action, params or {}, session_key=session_key)

    def authorization_status(self, authorization_request_id: str | None = None, session_key: str = "session-default") -> dict[str, Any]:
        params: dict[str, Any] = {}
        if authorization_request_id:
            params["request_id"] = authorization_request_id
        result = self.broker_call("auth.status", params, session_key=session_key)
        now = int(time.time())
        for lease in result.get("leases", []):
            lease["remainingSeconds"] = max(0, int(lease.get("expiresAt", now)) - now)
        result["availableScopes"] = SCOPES
        result["scopePolicies"] = {scope: ("automatic" if scope == "privanet.updates" else "step-up-2fa" if scope == "system.sudo" else "approval") for scope in SCOPES}
        result["executedAs"] = "privanet-chat"
        return result

    def check_authorization(self, request_id: str, scope: str, session_key: str = "session-default") -> dict[str, Any]:
        if scope not in SCOPES:
            raise ValueError("Unknown authorization scope")
        return self.broker_call("auth.check", {"request_id": request_id, "scope": scope}, session_key=session_key)

    def prepare_authorization(self, scope: str, reason: str, session_key: str) -> dict[str, Any]:
        if scope not in SCOPES or scope in {"privanet.updates", "system.sudo"}:
            raise ValueError("Unknown or non-interactive authorization scope")
        reason = reason.strip()
        if not reason or len(reason) > 500:
            raise ValueError("Authorization reason must be 1-500 characters")
        return self.broker_call("auth.prepare", {"scope": scope, "reason": reason}, session_key=session_key)

    def grant_authorization(self, request_id: str, duration: str, session_key: str = "session-default") -> dict[str, Any]:
        return self.broker_call("auth.grant", {"request_id": request_id, "duration": duration}, session_key=session_key)

    def deny_authorization(self, request_id: str, session_key: str = "session-default") -> dict[str, Any]:
        return self.broker_call("auth.deny", {"request_id": request_id}, session_key=session_key)

    def revoke_authorization(self, request_id: str | None = None, session_key: str = "session-default") -> dict[str, Any]:
        params: dict[str, Any] = {}
        if request_id:
            params["request_id"] = request_id
        return self.broker_call("auth.revoke_all", params, session_key=session_key)

    def prepare_confirmation(self, action: str, target: str, reason: str, authorization_request_id: str, session_key: str) -> dict[str, Any]:
        if action not in CONFIRMABLE_ACTIONS:
            raise ValueError("Unknown confirmable action")
        target = target.strip()
        reason = reason.strip()
        if not target or len(target) > 200 or any(ord(ch) < 32 for ch in target):
            raise ValueError("Confirmation target must be 1-200 printable characters")
        if not reason or len(reason) > 500:
            raise ValueError("Confirmation reason must be 1-500 characters")
        return self.broker_call(
            "confirm.prepare",
            {"action": action, "target": target, "reason": reason, "authorization_request_id": authorization_request_id},
            session_key=session_key,
        )

    def grant_confirmation(self, request_id: str, session_key: str = "session-default") -> dict[str, Any]:
        return self.broker_call("confirm.grant", {"request_id": request_id}, session_key=session_key)

    def deny_confirmation(self, request_id: str, session_key: str = "session-default") -> dict[str, Any]:
        return self.broker_call("confirm.deny", {"request_id": request_id}, session_key=session_key)

    def sudo_2fa_status(self) -> dict[str, Any]:
        return self.broker_call("sudo.2fa_status")

    def prepare_sudo_command(self, command: str, reason: str, timeout_seconds: int, session_key: str) -> dict[str, Any]:
        command = command.strip()
        reason = reason.strip()
        if not command or len(command) > 8000 or "\x00" in command:
            raise ValueError("Command must be 1-8000 characters")
        if not reason or len(reason) > 500:
            raise ValueError("Reason must be 1-500 characters")
        timeout_seconds = max(1, min(int(timeout_seconds), 300))
        return self.broker_call("sudo.prepare", {"command": command, "reason": reason, "timeout_seconds": timeout_seconds}, session_key=session_key)

    def grant_sudo_command(self, request_id: str, totp_code: str, session_key: str = "session-default") -> dict[str, Any]:
        return self.broker_call("sudo.grant", {"request_id": request_id, "totp_code": totp_code}, session_key=session_key)

    def deny_sudo_command(self, request_id: str, session_key: str = "session-default") -> dict[str, Any]:
        return self.broker_call("sudo.deny", {"request_id": request_id}, session_key=session_key)

    def run_sudo_command(self, sudo_request_id: str, session_key: str) -> dict[str, Any]:
        result = self.broker_call("root.run", {"sudo_request_id": sudo_request_id}, session_key=session_key)
        stdout = redact(str(result.get("stdout", "")))
        stderr = redact(str(result.get("stderr", "")))
        self.audit.write(
            "run_sudo_command",
            "root",
            {"sudo_request_id": sudo_request_id, "command_sha256": result.get("commandSha256")},
            bool(result.get("ok")),
            stderr or stdout[-1000:],
        )
        return {
            "ok": bool(result.get("ok")),
            "executedAs": "root",
            "privilege": "sudo-2fa",
            "requestId": sudo_request_id,
            "commandSha256": result.get("commandSha256"),
            "exitCode": int(result.get("exitCode", 1)),
            "stdout": stdout,
            "stderr": stderr,
        }

    def command_environment(self) -> dict[str, Any]:
        return {
            "ok": True,
            "bridgeVersion": VERSION,
            "mcpServiceUser": os.environ.get("USER") or "privanet-chat",
            "executedAs": "privanet-shell",
            "home": self.command_home,
            "cwd": self.command_cwd,
            "privilege": "unprivileged",
            "rootShellAvailable": False,
            "stepUpRootCommandAvailable": True,
            "notes": [
                "run_command always uses the separate privanet-shell service account and a sanitized environment.",
                "privanet-shell cannot access the privileged broker socket.",
                "Privileged PrivaNet operations require an explicit capability request ID through the broker.",
                "General root commands require a separate per-command TOTP approval and never turn run_command into root.",
                "Executable releases and systemd units remain root-owned.",
            ],
        }

    def run_command(self, command: str, timeout_seconds: int = 20) -> dict[str, Any]:
        command = command.strip()
        if not command or len(command) > 8000 or "\x00" in command:
            raise ValueError("Command must be 1-8000 characters")
        timeout_seconds = max(1, min(int(timeout_seconds), self.max_command_timeout))
        result = self.shell.run(command, timeout_seconds)
        result["stdout"] = redact(str(result.get("stdout", "")))
        result["stderr"] = redact(str(result.get("stderr", "")))
        self.audit.write("run_command", "unprivileged-shell", {"command": command[:1000], "timeout": timeout_seconds}, bool(result.get("ok")), result["stderr"] or result["stdout"][-1000:])
        return {
            "ok": bool(result.get("ok")), "executedAs": "privanet-shell", "privilege": "unprivileged",
            "exitCode": int(result.get("exitCode", 1)), "durationSeconds": result.get("durationSeconds"),
            "stdout": result["stdout"], "stderr": result["stderr"],
        }

    def _service(self, name: str) -> str:
        try:
            return self.services[name]
        except KeyError:
            raise ValueError(f"Unknown managed service: {name}") from None

    def service_status(self, name: str) -> dict[str, Any]:
        self._service(name)
        result = self.broker_call("service.status", {"service": name})
        data: dict[str, str] = {}
        for line in str(result.get("output", "")).splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                data[k] = v
        return {"service": name, "unit": result.get("unit"), "ok": result.get("ok", False), "state": data, "error": redact(str(result.get("error"))) if result.get("error") else None}

    def list_services(self) -> list[dict[str, Any]]:
        return [self.service_status(name) for name in sorted(self.services)]

    def recent_logs(self, name: str, lines: int = 100, priority: str | None = None) -> dict[str, Any]:
        self._service(name)
        lines = max(1, min(int(lines), self.max_log_lines))
        result = self.broker_call("logs.read", {"service": name, "lines": lines, "priority": priority})
        return {"service": name, "ok": result.get("ok", False), "logs": redact(str(result.get("logs", ""))), "error": redact(str(result.get("error"))) if result.get("error") else None}

    def restart_service(self, name: str, authorization_request_id: str, session_key: str) -> dict[str, Any]:
        self._service(name)
        result = self.broker_call("service.restart", {"service": name, "authorization_request_id": authorization_request_id}, session_key=session_key)
        self.audit.write("restart_service", name, {}, bool(result.get("ok")), str(result.get("error") or result.get("state") or ""))
        state: dict[str, str] = {}
        for line in str(result.get("state", "")).splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                state[k] = v
        return {"service": name, "ok": result.get("ok", False), "state": state, "error": redact(str(result.get("error"))) if result.get("error") else None}

    def list_nodes(self, include_revoked: bool = True) -> dict[str, Any]:
        result = self.broker_call("admin.nodes.list")
        data = result.get("data")
        nodes = data.get("nodes", []) if isinstance(data, dict) else data if isinstance(data, list) else []
        if not include_revoked:
            nodes = [n for n in nodes if isinstance(n, dict) and n.get("status") != "REVOKED"]
        return {"ok": result.get("ok", False), "nodes": nodes, "error": redact(str(result.get("error"))) if result.get("error") else None}

    def get_node(self, node_reference: str) -> dict[str, Any]:
        reference = self._node_reference(node_reference)
        result = self.broker_call("admin.nodes.show", {"node_reference": reference})
        return {"ok": result.get("ok", False), "node": result.get("data"), "error": redact(str(result.get("error"))) if result.get("error") else None}

    def list_pending_nodes(self, include_all: bool = False) -> dict[str, Any]:
        result = self.broker_call("admin.requests.list", {"include_all": include_all})
        return {"ok": result.get("ok", False), "pending": result.get("data"), "error": redact(str(result.get("error"))) if result.get("error") else None}

    @staticmethod
    def _node_reference(reference: str) -> str:
        value = reference.strip()
        if not value or len(value) > 160 or value.startswith("-") or not re.fullmatch(r"[A-Za-z0-9_.:@+\- ]+", value):
            raise ValueError("Invalid node reference")
        return value

    @staticmethod
    def _request_code(request_code: str) -> str:
        value = request_code.strip().upper().replace(" ", "-")
        if not re.fullmatch(r"[A-Z0-9]{4}-?[A-Z0-9]{4}", value):
            raise ValueError("Invalid request code format")
        if "-" not in value:
            value = f"{value[:4]}-{value[4:]}"
        return value

    @staticmethod
    def _capabilities(capabilities: list[str]) -> list[str]:
        if not capabilities:
            raise ValueError("At least one capability is required")
        clean: list[str] = []
        for capability in capabilities:
            value = capability.strip()
            if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,95}", value):
                raise ValueError(f"Invalid capability: {capability}")
            if value not in clean:
                clean.append(value)
        return clean

    def approve_node(self, request_code: str, capabilities: list[str], label: str | None, authorization_request_id: str, session_key: str) -> dict[str, Any]:
        code = self._request_code(request_code)
        caps = self._capabilities(capabilities)
        result = self.broker_call("admin.node.approve", {"request_code": code, "capabilities": caps, "label": label, "authorization_request_id": authorization_request_id}, session_key=session_key)
        self.audit.write("approve_node", code, {"capabilities": caps, "label": label}, bool(result.get("ok")), str(result.get("error") or result.get("data") or ""))
        return {"ok": result.get("ok", False), "request_code": code, "capabilities": caps, "label": label, "output": result.get("data"), "error": result.get("error")}

    def deny_node(self, request_code: str, authorization_request_id: str, session_key: str) -> dict[str, Any]:
        code = self._request_code(request_code)
        result = self.broker_call("admin.node.deny", {"request_code": code, "authorization_request_id": authorization_request_id}, session_key=session_key)
        self.audit.write("deny_node", code, {}, bool(result.get("ok")), str(result.get("error") or result.get("data") or ""))
        return {"ok": result.get("ok", False), "request_code": code, "output": result.get("data"), "error": result.get("error")}

    def rename_node(self, node_reference: str, name: str | None, clear: bool, authorization_request_id: str, session_key: str) -> dict[str, Any]:
        reference = self._node_reference(node_reference)
        if not clear:
            clean = (name or "").strip()
            if not clean or len(clean) > 80 or any(ord(ch) < 32 for ch in clean):
                raise ValueError("Invalid node label")
        else:
            clean = None
        result = self.broker_call("admin.node.rename", {"node_reference": reference, "name": clean, "clear": clear, "authorization_request_id": authorization_request_id}, session_key=session_key)
        self.audit.write("rename_node", reference, {"name": clean, "clear": clear}, bool(result.get("ok")), str(result.get("error") or result.get("output") or ""))
        return {"ok": result.get("ok", False), "node_reference": reference, "name": clean, "cleared": clear, "output": result.get("output"), "error": result.get("error")}

    def revoke_node(self, node_reference: str, authorization_request_id: str, confirmation_request_id: str | None, session_key: str) -> dict[str, Any]:
        reference = self._node_reference(node_reference)
        result = self.broker_call("admin.node.revoke", {"node_reference": reference, "authorization_request_id": authorization_request_id, "confirmation_request_id": confirmation_request_id}, session_key=session_key)
        self.audit.write("revoke_node", reference, {}, bool(result.get("ok")), str(result.get("error") or result.get("output") or ""))
        return {"ok": result.get("ok", False), "node_reference": reference, "output": result.get("output"), "error": result.get("error")}

    def diagnose_node(self, node_reference: str) -> dict[str, Any]:
        shown = self.get_node(node_reference)
        node = shown.get("node") if shown.get("ok") else None
        if not isinstance(node, dict):
            return {"ok": False, "node": node_reference, "diagnosis": [], "error": shown.get("error") or "Node unavailable"}
        issues: list[dict[str, str]] = []
        status = str(node.get("status", "UNKNOWN"))
        if status == "REVOKED":
            issues.append({"severity": "critical", "code": "REVOKED", "message": "The node is revoked and cannot authenticate."})
        elif status not in {"ONLINE", "OFFLINE_EXPECTED"}:
            issues.append({"severity": "warning", "code": "OFFLINE", "message": f"Node status is {status}. Check connectivity, service state, and enrollment."})
        slots = int(node.get("jobSlots") or 0)
        jobs = int(node.get("currentJobs") or 0)
        if slots <= 0:
            issues.append({"severity": "warning", "code": "NO_SLOTS", "message": "The node advertises no job slots."})
        elif jobs >= slots:
            issues.append({"severity": "info", "code": "SLOTS_FULL", "message": "All advertised job slots are currently occupied."})
        pressure = str(node.get("pressure") or node.get("resourcePressure") or "").upper()
        if pressure in {"ELEVATED", "HIGH", "CRITICAL"}:
            issues.append({"severity": "warning", "code": "RESOURCE_PRESSURE", "message": f"The node reports {pressure.lower()} resource pressure."})
        if not issues:
            issues.append({"severity": "ok", "code": "HEALTHY", "message": "No obvious node-health problems are visible from coordinator telemetry."})
        return {"ok": True, "node": node, "diagnosis": issues}

    def version_drift(self) -> dict[str, Any]:
        listing = self.list_nodes(include_revoked=False)
        nodes = listing.get("nodes", []) if listing.get("ok") else []
        versions: dict[str, list[str]] = {}
        for node in nodes:
            if not isinstance(node, dict):
                continue
            version = str(node.get("daemonVersion") or "unknown")
            versions.setdefault(version, []).append(str(node.get("displayName") or node.get("nodeId") or "unknown"))
        return {"ok": listing.get("ok", False), "versions": versions, "drift": len([v for v in versions if v != "unknown"]) > 1, "error": listing.get("error")}

    def local_node_slots(self) -> dict[str, Any]:
        result = self.broker_call("node.slots.show")
        return {"ok": result.get("ok", False), "slots": result.get("data"), "error": result.get("error")}

    def set_local_node_slots(self, slots: int, authorization_request_id: str, session_key: str) -> dict[str, Any]:
        slots = int(slots)
        if slots < 1 or slots > self.max_job_slots:
            raise ValueError(f"slots must be between 1 and {self.max_job_slots}")
        result = self.broker_call("node.slots.set", {"slots": slots, "authorization_request_id": authorization_request_id}, session_key=session_key)
        self.audit.write("set_local_node_slots", "local-node", {"slots": slots}, bool(result.get("ok")), str(result.get("error") or result.get("data") or ""))
        return {"ok": result.get("ok", False), "slots": slots, "result": result.get("data"), "note": "The saved slot count applies at the node's next start and PRIVANODE_JOB_SLOTS, if set, takes priority.", "error": result.get("error")}

    def clear_local_node_slots(self, authorization_request_id: str, session_key: str) -> dict[str, Any]:
        result = self.broker_call("node.slots.clear", {"authorization_request_id": authorization_request_id}, session_key=session_key)
        self.audit.write("clear_local_node_slots", "local-node", {}, bool(result.get("ok")), str(result.get("error") or result.get("data") or ""))
        return {"ok": result.get("ok", False), "result": result.get("data"), "error": result.get("error")}

    def privasearch_health(self) -> dict[str, Any]:
        headers = {"Accept": "application/json", "User-Agent": f"PrivaNet-Chat-Admin/{VERSION}"}
        result = self.http_json(self.search_base_url + "/health", headers, self.http_timeout, self.http_max_bytes)
        if isinstance(result.get("error"), str):
            result["error"] = redact(result["error"])
        return result

    def privasearch_status(self) -> dict[str, Any]:
        result = self.broker_call("search.status")
        if isinstance(result.get("error"), str):
            result["error"] = redact(result["error"])
        return result

    def privasearch_summary(self) -> dict[str, Any]:
        health = self.privasearch_health()
        status = self.privasearch_status()
        data = status.get("data") if isinstance(status.get("data"), dict) else {}
        frontier = data.get("frontier", {}) if isinstance(data, dict) else {}
        quality = data.get("quality", {}) if isinstance(data, dict) else {}
        throughput = data.get("throughput", {}) if isinstance(data, dict) else {}
        concentration = data.get("domainConcentration") or data.get("concentration") or {}
        return {
            "ok": bool(health.get("ok")) and bool(status.get("ok")),
            "health": health.get("data"),
            "queue": frontier,
            "throughput": throughput,
            "quality": quality,
            "domainConcentration": concentration,
            "warnings": data.get("warnings", []) if isinstance(data, dict) else [],
            "error": status.get("error") or health.get("error"),
        }

    def system_health(self) -> dict[str, Any]:
        uptime_sec: float | None = None
        try:
            uptime_sec = float(Path("/proc/uptime").read_text().split()[0])
        except (OSError, ValueError, IndexError):
            pass
        memory: dict[str, int] = {}
        try:
            for line in Path("/proc/meminfo").read_text().splitlines():
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                pieces = value.strip().split()
                if pieces and pieces[0].isdigit():
                    multiplier = 1024 if len(pieces) > 1 and pieces[1].lower() == "kb" else 1
                    memory[key] = int(pieces[0]) * multiplier
        except OSError:
            pass
        disks: dict[str, Any] = {}
        for raw in self.diagnostic_paths[:16]:
            path = Path(raw)
            if not path.is_absolute() or ".." in path.parts or not path.exists():
                continue
            try:
                usage = shutil.disk_usage(path)
                disks[str(path)] = {"totalBytes": usage.total, "usedBytes": usage.used, "freeBytes": usage.free}
            except OSError:
                continue
        try:
            load = list(os.getloadavg())
        except OSError:
            load = []
        return {
            "ok": True, "bridgeVersion": VERSION, "hostname": os.uname().nodename, "uptimeSec": uptime_sec,
            "loadAverage": load, "cpuCount": os.cpu_count(),
            "memory": {"totalBytes": memory.get("MemTotal"), "availableBytes": memory.get("MemAvailable"), "freeBytes": memory.get("MemFree"), "swapTotalBytes": memory.get("SwapTotal"), "swapFreeBytes": memory.get("SwapFree")},
            "disks": disks,
        }

    def updater_schedule(self) -> dict[str, Any]:
        result = self.broker_call("update.schedule")
        data: dict[str, str] = {}
        for line in str(result.get("output", "")).splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                data[key] = value
        return {"ok": result.get("ok", False), "timer": data, "error": result.get("error")}

    def _updater_prerequisite_error(self) -> dict[str, Any] | None:
        updater = Path(self.updater_bin)
        if not updater.is_file() or not os.access(updater, os.X_OK):
            return {"ok": False, "apps": [], "events": [{"app": "all", "code": "UPDATER_NOT_INSTALLED"}], "error": f"Updater executable is missing or not executable at {self.updater_bin}"}
        config = Path(self.updater_config_file)
        if not config.is_file():
            return {"ok": False, "apps": [], "events": [{"app": "all", "code": "UPDATER_CONFIG_MISSING"}], "error": f"Updater config not found at {self.updater_config_file}"}
        return None

    def check_updates(self) -> dict[str, Any]:
        prerequisite = self._updater_prerequisite_error()
        if prerequisite is not None:
            return prerequisite
        result = self.broker_call("update.check")
        events = self._json_lines(str(result.get("output", "")))
        apps = [row for row in events if isinstance(row, dict) and row.get("app")]
        return {"ok": result.get("ok", False), "apps": apps, "events": events, "error": redact(str(result.get("error"))) if result.get("error") else None}

    def update_history(self, limit: int = 100) -> dict[str, Any]:
        limit = max(1, min(int(limit), 300))
        result = self.broker_call("logs.read", {"service": "updater", "lines": limit})
        return {"ok": result.get("ok", False), "events": self._json_lines(str(result.get("logs", ""))), "error": result.get("error")}

    def apply_updates(self, session_key: str = "session-default") -> dict[str, Any]:
        prerequisite = self._updater_prerequisite_error()
        if prerequisite is not None:
            return prerequisite
        result = self.broker_call("update.apply", {}, session_key=session_key)
        events = self._json_lines(str(result.get("output", "")))
        self.audit.write("apply_updates", "priva-apps", {"scope": "privanet.updates", "authorization": "automatic"}, bool(result.get("ok")), json.dumps(events)[:4000])
        return {
            "ok": result.get("ok", False),
            "scope": "privanet.updates",
            "authorization": "automatic",
            "apps": [e for e in events if isinstance(e, dict) and e.get("app")],
            "events": events,
            "error": result.get("error"),
        }

    def chat_admin_update_status(self) -> dict[str, Any]:
        result = self.broker_call("update.self_check")
        values: dict[str, str] = {}
        for raw in str(result.get("output", "")).splitlines():
            if ":" in raw:
                key, value = raw.split(":", 1)
                values[key.strip().lower()] = value.strip()
        return {
            "ok": result.get("ok", False),
            "scope": "privanet.updates",
            "authorization": "automatic",
            "installed": values.get("installed"),
            "published": values.get("published"),
            "status": values.get("status"),
            "error": redact(str(result.get("error"))) if result.get("error") else None,
        }

    def apply_chat_admin_update(self, session_key: str = "session-default") -> dict[str, Any]:
        result = self.broker_call("update.self_apply", {}, session_key=session_key)
        self.audit.write(
            "apply_chat_admin_update",
            "chat-admin",
            {"scope": "privanet.updates", "authorization": "automatic"},
            bool(result.get("ok")),
            str(result.get("error") or result.get("state") or ""),
        )
        return {
            "ok": result.get("ok", False),
            "scope": "privanet.updates",
            "authorization": "automatic",
            "state": result.get("state"),
            "unit": result.get("unit"),
            "error": redact(str(result.get("error"))) if result.get("error") else None,
        }

    def install_package(self, package: str, authorization_request_id: str, confirmation_request_id: str | None, session_key: str) -> dict[str, Any]:
        package = package.strip().lower()
        if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]{0,127}", package):
            raise ValueError("Invalid Debian package name")
        result = self.broker_call("package.install", {"package": package, "authorization_request_id": authorization_request_id, "confirmation_request_id": confirmation_request_id}, session_key=session_key)
        self.audit.write("install_package", package, {}, bool(result.get("ok")), str(result.get("error") or result.get("output") or ""))
        return {"ok": result.get("ok", False), "package": package, "output": redact(str(result.get("output", ""))), "error": redact(str(result.get("error"))) if result.get("error") else None}

    def privanet_summary(self) -> dict[str, Any]:
        services = self.list_services()
        nodes_result = self.list_nodes(include_revoked=True)
        nodes = nodes_result.get("nodes", []) if nodes_result.get("ok") else []
        search = self.privasearch_health()
        updates = self.check_updates()
        system = self.system_health()
        counts: dict[str, int] = {}
        for node in nodes:
            if isinstance(node, dict):
                status = str(node.get("status", "UNKNOWN"))
                counts[status] = counts.get(status, 0) + 1
        warnings: list[str] = []
        for svc in services:
            if svc.get("state", {}).get("ActiveState") != "active" and svc.get("service") != "updater":
                warnings.append(f"Service {svc.get('service')} is not active.")
        if counts.get("OFFLINE", 0):
            warnings.append(f"{counts['OFFLINE']} node(s) are offline.")
        if not search.get("ok"):
            warnings.append("PrivaSearch health check failed.")
        if any(isinstance(app, dict) and app.get("code") == "UPDATE_AVAILABLE" for app in updates.get("apps", [])):
            warnings.append("Verified application updates are available.")
        return {
            "ok": not warnings,
            "overall": "HEALTHY" if not warnings else "ATTENTION",
            "services": services,
            "nodes": {"counts": counts, "total": len(nodes)},
            "search": search,
            "updates": updates.get("apps", []),
            "system": system,
            "warnings": warnings,
        }

    def audit_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        local = self.audit.recent(limit)
        try:
            broker = self.broker_call("audit.recent", {"limit": limit}).get("entries", [])
        except Exception:
            broker = []
        merged = [{**row, "source": "bridge"} for row in local] + [{**row, "source": "broker"} for row in broker]
        return sorted(merged, key=lambda row: int(row.get("ts", 0)), reverse=True)[: max(1, min(limit, 200))]
