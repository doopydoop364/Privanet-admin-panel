#!/usr/bin/env python3
"""Root-only fallback approval utility for PrivaNet Chat Admin."""
from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import sys

SOCKET = "/run/privanet-chat-admin/broker.sock"
SCOPES = ["privanet.services", "privanet.nodes", "privanet.node_local", "privanet.updates", "system.packages"]


def call(action: str, params: dict[str, object]) -> dict[str, object]:
    session_key = "local_" + secrets.token_hex(8)
    payload = json.dumps({"action": action, "params": params, "session_key": session_key}) + "\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(SOCKET)
        s.sendall(payload.encode())
        data = b""
        while b"\n" not in data:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    return json.loads(data.split(b"\n", 1)[0])


def main() -> int:
    if os.geteuid() != 0:
        print("Run as root.", file=sys.stderr)
        return 1
    p = argparse.ArgumentParser(description=__doc__)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--request", help="Grant an existing req_... admin approval request")
    mode.add_argument("--confirm-request", help="Grant an existing confirm_req_... action confirmation request")
    mode.add_argument("--sudo-request", help="Grant an existing sudo_req_... root-command request with TOTP")
    mode.add_argument("--create-scope", choices=SCOPES, help="Create and grant a fallback admin approval request")
    p.add_argument("--duration", choices=["once", "15m", "30m", "60m"], default="once")
    p.add_argument("--reason", default="Local operator fallback approval")
    p.add_argument("--totp", help="6-digit TOTP for --sudo-request; enter locally, never in ChatGPT")
    args = p.parse_args()

    if args.request:
        result = call("auth.grant", {"request_id": args.request, "duration": args.duration})
    elif args.confirm_request:
        result = call("confirm.grant", {"request_id": args.confirm_request})
    elif args.sudo_request:
        if not args.totp:
            p.error("--totp is required with --sudo-request")
        result = call("sudo.grant", {"request_id": args.sudo_request, "totp_code": args.totp})
    else:
        prep = call("auth.prepare", {"scope": args.create_scope, "reason": args.reason})
        if not prep.get("ok"):
            print(json.dumps(prep, indent=2))
            return 1
        request_id = prep["result"]["requestId"]
        result = call("auth.grant", {"request_id": request_id, "duration": args.duration})
        if result.get("ok"):
            result["result"]["requestId"] = request_id

    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
