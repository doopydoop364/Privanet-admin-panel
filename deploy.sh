#!/usr/bin/env bash
set -euo pipefail

VERSION=0.3.3.2
PREFIX=${PREFIX:-/opt/privanet-chat-admin}
CONFIG_DIR=${CONFIG_DIR:-/etc/privanet-chat-admin}
STATE_DIR=${STATE_DIR:-/var/lib/privanet-chat-admin}
RELEASE_DIR="$PREFIX/releases/$VERSION"
CURRENT_LINK="$PREFIX/current"
SERVICE_USER=${SERVICE_USER:-privanet-chat}
SERVICE_GROUP=${SERVICE_GROUP:-privanet-chat}
BROKER_GROUP=${BROKER_GROUP:-privanet-chat-broker}
SHELL_GROUP=${SHELL_GROUP:-privanet-chat-shell}
SHELL_USER=${SHELL_USER:-privanet-shell}
BROKER_STATE_DIR=${BROKER_STATE_DIR:-/var/lib/privanet-chat-admin-broker}
SHELL_STATE_DIR=${SHELL_STATE_DIR:-/var/lib/privanet-chat-shell}
COMMAND_PATH=/opt/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

if [[ $EUID -ne 0 ]]; then echo "Run as root." >&2; exit 1; fi
for cmd in python3 systemctl install useradd groupadd; do command -v "$cmd" >/dev/null 2>&1 || { echo "Missing required command: $cmd" >&2; exit 1; }; done

WAS_ACTIVE=0
systemctl is-active --quiet privanet-chat-admin.service 2>/dev/null && WAS_ACTIVE=1 || true
PREVIOUS_TARGET=""
[[ -L "$CURRENT_LINK" ]] && PREVIOUS_TARGET=$(readlink -f "$CURRENT_LINK" || true)

for group in "$SERVICE_GROUP" "$BROKER_GROUP" "$SHELL_GROUP"; do
  getent group "$group" >/dev/null 2>&1 || groupadd --system "$group"
done
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --gid "$SERVICE_GROUP" --home-dir "$STATE_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
fi
if ! id "$SHELL_USER" >/dev/null 2>&1; then
  useradd --system --gid "$SHELL_GROUP" --home-dir "$SHELL_STATE_DIR" --shell /usr/sbin/nologin "$SHELL_USER"
fi
usermod -L "$SERVICE_USER" >/dev/null 2>&1 || true
usermod -L "$SHELL_USER" >/dev/null 2>&1 || true
usermod -a -G "$BROKER_GROUP,$SHELL_GROUP" "$SERVICE_USER"

install -d -m 0755 "$PREFIX" "$PREFIX/releases" "$CONFIG_DIR"
install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0700 "$STATE_DIR"
install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0700 "$STATE_DIR/backups"
if compgen -G "$STATE_DIR/audit.sqlite3*" >/dev/null; then
  chown "$SERVICE_USER:$SERVICE_GROUP" "$STATE_DIR"/audit.sqlite3*
  chmod 0600 "$STATE_DIR"/audit.sqlite3* || true
fi
install -d -o root -g root -m 0700 "$BROKER_STATE_DIR"
install -d -o "$SHELL_USER" -g "$SHELL_GROUP" -m 0700 "$SHELL_STATE_DIR" "$SHELL_STATE_DIR/work"

if [[ ! -x "$PREFIX/venv/bin/python" ]]; then python3 -m venv "$PREFIX/venv"; fi
"$PREFIX/venv/bin/pip" install --upgrade pip
"$PREFIX/venv/bin/pip" install 'mcp>=2,<3' 'pydantic>=2.10,<3' 'uvicorn>=0.30,<1'

rm -rf "$RELEASE_DIR.tmp"
install -d -m 0755 "$RELEASE_DIR.tmp/app/agent"
install -m 0644 agent/__init__.py agent/core.py agent/server.py agent/broker.py agent/shell.py "$RELEASE_DIR.tmp/app/agent/"
printf '%s\n' "$VERSION" > "$RELEASE_DIR.tmp/VERSION"
chmod 0644 "$RELEASE_DIR.tmp/VERSION"
chown -R root:root "$RELEASE_DIR.tmp"
chmod -R go-w "$RELEASE_DIR.tmp"
rm -rf "$RELEASE_DIR"
mv "$RELEASE_DIR.tmp" "$RELEASE_DIR"

if [[ ! -e "$CONFIG_DIR/config.json" ]]; then
  install -m 0640 -o root -g "$SERVICE_GROUP" agent/config.example.json "$CONFIG_DIR/config.json"
  echo "Created $CONFIG_DIR/config.json"
else
  cp -a "$CONFIG_DIR/config.json" "$STATE_DIR/backups/config-pre-$VERSION-$(date +%Y%m%d-%H%M%S).json"
  python3 - "$CONFIG_DIR/config.json" agent/config.example.json <<'PY'
import json, os, sys, tempfile
current_path, defaults_path = sys.argv[1:]
with open(current_path, encoding='utf-8') as f: current=json.load(f)
with open(defaults_path, encoding='utf-8') as f: defaults=json.load(f)
def merge(dst, src):
    for k,v in src.items():
        if k not in dst: dst[k]=v
        elif isinstance(dst[k],dict) and isinstance(v,dict): merge(dst[k],v)
merge(current, defaults)
fd,tmp=tempfile.mkstemp(prefix='.config.',dir=os.path.dirname(current_path),text=True)
try:
    with os.fdopen(fd,'w',encoding='utf-8') as f: json.dump(current,f,indent=2); f.write('\n')
    os.chmod(tmp,0o640); os.chown(tmp,0,os.stat(current_path).st_gid)
    os.replace(tmp,current_path)
finally:
    if os.path.exists(tmp): os.unlink(tmp)
PY
  chown root:"$SERVICE_GROUP" "$CONFIG_DIR/config.json"
  chmod 0640 "$CONFIG_DIR/config.json"
fi

[[ -f update.sh ]] && install -m 0755 -o root -g root update.sh /usr/local/bin/privanet-chat-admin-update
[[ -f authorize.py ]] && install -m 0755 -o root -g root authorize.py /usr/local/bin/privanet-chat-admin-authorize
[[ -f twofactor.py ]] && install -m 0755 -o root -g root twofactor.py /usr/local/bin/privanet-chat-admin-2fa

cat > /etc/systemd/system/privanet-chat-admin-self-update.service <<UNIT
[Unit]
Description=Apply verified PrivaNet Chat Admin self-update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStartPre=/usr/bin/sleep 2
ExecStart=/usr/local/bin/privanet-chat-admin-update
UMask=0022
PrivateTmp=true
ProtectHome=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictRealtime=true
LockPersonality=true

UNIT

cat > /etc/systemd/system/privanet-chat-admin-broker.service <<UNIT
[Unit]
Description=PrivaNet Chat Admin privileged broker
After=network-online.target privanet-coordinator.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=$BROKER_GROUP
WorkingDirectory=$CURRENT_LINK/app
Environment=PYTHONPATH=$CURRENT_LINK/app
Environment=PRIVANET_CHAT_ADMIN_CONFIG=$CONFIG_DIR/config.json
Environment=PRIVANET_CHAT_ADMIN_BROKER_DB=$BROKER_STATE_DIR/broker.sqlite3
Environment=PRIVANET_CHAT_ADMIN_BROKER_SOCKET=/run/privanet-chat-admin/broker.sock
Environment=PRIVANET_CHAT_ADMIN_TOTP_SECRET=$BROKER_STATE_DIR/totp.secret
Environment="PATH=$COMMAND_PATH"
ExecStart=$PREFIX/venv/bin/python -m agent.broker
Restart=on-failure
RestartSec=3
RuntimeDirectory=privanet-chat-admin
RuntimeDirectoryMode=0750
UMask=0007
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=$BROKER_STATE_DIR /var/lib/privanet-node /run/privanet-chat-admin
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictRealtime=true
LockPersonality=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/privanet-chat-shell.service <<UNIT
[Unit]
Description=PrivaNet Chat Admin unprivileged command sandbox
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SHELL_USER
Group=$SHELL_GROUP
WorkingDirectory=$CURRENT_LINK/app
Environment=PYTHONPATH=$CURRENT_LINK/app
Environment=PRIVANET_CHAT_ADMIN_SHELL_SOCKET=/run/privanet-chat-shell/shell.sock
Environment=PRIVANET_CHAT_ADMIN_SHELL_HOME=$SHELL_STATE_DIR
Environment=PRIVANET_CHAT_ADMIN_SHELL_WORK=$SHELL_STATE_DIR/work
Environment=PRIVANET_CHAT_ADMIN_COMMAND_PATH=$COMMAND_PATH
ExecStart=$PREFIX/venv/bin/python -m agent.shell
Restart=on-failure
RestartSec=3
RuntimeDirectory=privanet-chat-shell
RuntimeDirectoryMode=0750
UMask=0007
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=$SHELL_STATE_DIR /run/privanet-chat-shell
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictRealtime=true
LockPersonality=true
RestrictSUIDSGID=true
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/privanet-chat-admin.service <<UNIT
[Unit]
Description=PrivaNet conversational admin MCP service (LOCALHOST ONLY)
After=network-online.target privanet-chat-admin-broker.service privanet-chat-shell.service
Wants=network-online.target privanet-chat-admin-broker.service privanet-chat-shell.service

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
SupplementaryGroups=$BROKER_GROUP $SHELL_GROUP
WorkingDirectory=$CURRENT_LINK/app
Environment=PYTHONPATH=$CURRENT_LINK/app
Environment=PRIVANET_CHAT_ADMIN_CONFIG=$CONFIG_DIR/config.json
Environment="PATH=$COMMAND_PATH"
Environment=HOME=$STATE_DIR
ExecStart=$PREFIX/venv/bin/uvicorn agent.server:app --host 127.0.0.1 --port 8787
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=$STATE_DIR
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictRealtime=true
LockPersonality=true
RestrictSUIDSGID=true
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
UNIT

# Read-only helper used by the broker for a fresh updater check.
cat > /etc/systemd/system/privanet-chat-admin-update-check.service <<'UNIT'
[Unit]
Description=Check verified Priva application releases for Chat Admin
After=network-online.target
Wants=network-online.target
ConditionPathExists=/etc/privanet/updater.json

[Service]
Type=oneshot
ExecStart=/usr/local/bin/privanet-update --check
User=root
Group=root
UMask=0077
TimeoutStartSec=2h
Environment=PATH=/opt/node/bin:/usr/local/bin:/usr/bin:/bin
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/privanet-updater /run
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
ProtectKernelTunables=yes
ProtectControlGroups=yes
UNIT

ln -sfnT "$RELEASE_DIR" "$CURRENT_LINK"
systemctl daemon-reload
systemctl enable privanet-chat-admin-broker.service privanet-chat-shell.service >/dev/null

if [[ $WAS_ACTIVE -eq 1 ]]; then
  if ! systemctl restart privanet-chat-admin-broker.service privanet-chat-shell.service privanet-chat-admin.service || ! systemctl is-active --quiet privanet-chat-admin.service; then
    echo "New release failed to start; attempting rollback." >&2
    if [[ -n "$PREVIOUS_TARGET" && -d "$PREVIOUS_TARGET" ]]; then
      ln -sfnT "$PREVIOUS_TARGET" "$CURRENT_LINK"
      systemctl daemon-reload
      systemctl restart privanet-chat-admin-broker.service privanet-chat-shell.service privanet-chat-admin.service || true
    fi
    exit 1
  fi
  echo "Updated and restarted PrivaNet Chat Admin to $VERSION"
else
  systemctl enable --now privanet-chat-admin-broker.service privanet-chat-shell.service privanet-chat-admin.service
  echo "Installed and started PrivaNet Chat Admin $VERSION"
fi

echo "MCP frontend user: $SERVICE_USER (locked, no shell, no sudo)"
echo "Command sandbox user: $SHELL_USER (cannot access privileged broker socket)"
echo "Fallback authorization command: privanet-chat-admin-authorize"
echo "Root-command 2FA setup: privanet-chat-admin-2fa setup"
echo "Updater command: privanet-chat-admin-update"
