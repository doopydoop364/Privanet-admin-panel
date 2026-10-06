#!/usr/bin/env python3
"""Local root-only TOTP enrollment utility for PrivaNet Chat Admin root-command approval."""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import os
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

SECRET_PATH = Path(os.environ.get("PRIVANET_CHAT_ADMIN_TOTP_SECRET", "/var/lib/privanet-chat-admin-broker/totp.secret"))
ISSUER = "PrivaNet Chat Admin"


def _require_root() -> None:
    if os.geteuid() != 0:
        raise SystemExit("Run as root.")


def _read_secret() -> str:
    try:
        secret = SECRET_PATH.read_text(encoding="ascii").strip().replace(" ", "").upper()
    except OSError as exc:
        raise SystemExit(f"2FA is not configured at {SECRET_PATH}") from exc
    if not secret:
        raise SystemExit("2FA secret file is empty")
    return secret


def _totp(secret: str, counter: int) -> str:
    key = base64.b32decode(secret, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{value:06d}"


def setup() -> int:
    _require_root()
    SECRET_PATH.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(SECRET_PATH.parent, 0o700)
    if SECRET_PATH.exists():
        print(f"2FA is already configured at {SECRET_PATH}")
        print("Use 'privanet-chat-admin-2fa rotate' to replace it.")
        return 1
    return _write_new_secret()


def rotate() -> int:
    _require_root()
    SECRET_PATH.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(SECRET_PATH.parent, 0o700)
    return _write_new_secret()


def _write_new_secret() -> int:
    secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
    tmp = SECRET_PATH.with_name("." + SECRET_PATH.name + ".tmp")
    with open(tmp, "w", encoding="ascii") as fh:
        fh.write(secret + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, SECRET_PATH)
    label = f"{socket.gethostname()} root approval"
    uri = "otpauth://totp/" + urllib.parse.quote(f"{ISSUER}:{label}") + "?" + urllib.parse.urlencode({
        "secret": secret,
        "issuer": ISSUER,
        "algorithm": "SHA1",
        "digits": "6",
        "period": "30",
    })
    print("PrivaNet Chat Admin root-command 2FA configured.")
    print("Keep this enrollment secret off ChatGPT and out of logs.")
    print(f"Secret: {secret}")
    print(f"URI: {uri}")
    qr = shutil.which("qrencode")
    if qr:
        print("\nScan this QR code with your authenticator app:\n")
        subprocess.run([qr, "-t", "ANSIUTF8", uri], check=False)
    print("\nVerify enrollment locally with: privanet-chat-admin-2fa verify 123456")
    return 0


def verify(code: str) -> int:
    _require_root()
    secret = _read_secret()
    if not code.isdigit() or len(code) != 6:
        print("Code must be exactly 6 digits.", file=sys.stderr)
        return 2
    current = int(time.time()) // 30
    ok = any(hmac.compare_digest(_totp(secret, c), code) for c in (current - 1, current, current + 1))
    print("TOTP verified." if ok else "TOTP did not verify.")
    return 0 if ok else 1


def status() -> int:
    _require_root()
    configured = SECRET_PATH.is_file() and SECRET_PATH.stat().st_size > 0
    print(f"configured={'yes' if configured else 'no'}")
    print(f"secret_path={SECRET_PATH}")
    return 0 if configured else 1


def disable(yes: bool) -> int:
    _require_root()
    if not yes:
        print("Refusing to disable without --yes.", file=sys.stderr)
        return 2
    try:
        SECRET_PATH.unlink()
    except FileNotFoundError:
        pass
    print("PrivaNet Chat Admin root-command 2FA disabled.")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("setup", help="Generate a new TOTP secret if none exists")
    sub.add_parser("rotate", help="Replace the TOTP secret and re-enroll your authenticator")
    v = sub.add_parser("verify", help="Verify a 6-digit TOTP locally")
    v.add_argument("code")
    sub.add_parser("status", help="Show whether TOTP is configured")
    d = sub.add_parser("disable", help="Delete the TOTP secret")
    d.add_argument("--yes", action="store_true")
    args = p.parse_args()
    if args.cmd == "setup": return setup()
    if args.cmd == "rotate": return rotate()
    if args.cmd == "verify": return verify(args.code)
    if args.cmd == "status": return status()
    if args.cmd == "disable": return disable(args.yes)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
