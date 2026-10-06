#!/usr/bin/env bash
set -euo pipefail

MANIFEST_URL=${PRIVANET_CHAT_ADMIN_MANIFEST_URL:-https://doopydoop364.github.io/privanet-chat-admin-latest.json}
PREFIX=${PREFIX:-/opt/privanet-chat-admin}
CHECK_ONLY=0
FORCE=0

usage() {
  cat <<'EOF'
Usage: privanet-chat-admin-update [--check] [--force]

  --check   Only report the installed and published versions.
  --force   Reinstall the published version even if already installed.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check) CHECK_ONLY=1 ;;
    --force) FORCE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

for cmd in curl unzip sha256sum python3; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "Missing required command: $cmd" >&2; exit 1; }
done

TMP=$(mktemp -d /tmp/privanet-chat-admin-update.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

curl -fsSL --proto '=https' --tlsv1.2 "$MANIFEST_URL" -o "$TMP/latest.json"

mapfile -t META < <(python3 - "$TMP/latest.json" <<'PY'
import json, re, sys, urllib.parse
with open(sys.argv[1], encoding='utf-8') as f:
    data = json.load(f)
version = data.get('version')
release_version = data.get('releaseVersion', version)
url = data.get('url')
sha = data.get('sha256')
version_pattern = r'\d+(?:\.\d+){2,3}(?:-[0-9A-Za-z.-]+)?'
if not isinstance(version, str) or not re.fullmatch(version_pattern, version):
    raise SystemExit('invalid manifest version')
if not isinstance(release_version, str) or not re.fullmatch(version_pattern, release_version):
    raise SystemExit('invalid manifest releaseVersion')
if not isinstance(url, str):
    raise SystemExit('invalid manifest URL')
p = urllib.parse.urlsplit(url)
if p.scheme != 'https' or p.hostname != 'doopydoop364.github.io' or p.username or p.password or p.port not in (None, 443):
    raise SystemExit('manifest URL origin refused')
if not isinstance(sha, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', sha):
    raise SystemExit('invalid manifest sha256')
print(release_version)
print(url)
print(sha.lower())
PY
)
LATEST=${META[0]}
URL=${META[1]}
EXPECTED_SHA=${META[2]}

CURRENT=none
if [[ -f "$PREFIX/current/VERSION" ]]; then
  CURRENT=$(tr -d '\r\n' < "$PREFIX/current/VERSION")
elif [[ -f "$PREFIX/app/agent/core.py" ]]; then
  CURRENT=$(python3 - "$PREFIX/app/agent/core.py" <<'PY'
import re, sys
text=open(sys.argv[1], encoding='utf-8').read()
m=re.search(r'^VERSION\s*=\s*["\x27]([^"\x27]+)', text, re.M)
print(m.group(1) if m else '0.1.0')
PY
)
fi

echo "Installed: $CURRENT"
echo "Published: $LATEST"

if [[ $CHECK_ONLY -eq 1 ]]; then
  [[ "$CURRENT" == "$LATEST" ]] && echo "Status: up to date" || echo "Status: update available"
  exit 0
fi

if [[ $EUID -ne 0 ]]; then
  echo "Run as root to install updates." >&2
  exit 1
fi

if [[ "$CURRENT" == "$LATEST" && $FORCE -ne 1 ]]; then
  echo "Already up to date."
  exit 0
fi

curl -fsSL --proto '=https' --tlsv1.2 "$URL" -o "$TMP/release.zip"
ACTUAL_SHA=$(sha256sum "$TMP/release.zip" | awk '{print $1}')
if [[ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]]; then
  echo "SHA256 mismatch; refusing update." >&2
  exit 1
fi

unzip -q "$TMP/release.zip" -d "$TMP/unpacked"
DEPLOY="$TMP/unpacked/privanet-chat-admin/deploy.sh"
if [[ ! -f "$DEPLOY" || ! -f "$TMP/unpacked/privanet-chat-admin/agent/core.py" ]]; then
  echo "Unexpected release layout; refusing update." >&2
  exit 1
fi

cd "$TMP/unpacked/privanet-chat-admin"
chmod +x deploy.sh
./deploy.sh

if systemctl is-enabled --quiet privanet-chat-admin.service 2>/dev/null; then
  systemctl enable --now privanet-chat-admin.service >/dev/null
fi
if systemctl is-active --quiet privanet-chat-admin.service; then
  echo "PrivaNet Chat Admin is active on version $LATEST."
else
  echo "Update installed, but privanet-chat-admin.service is not active." >&2
  exit 1
fi
