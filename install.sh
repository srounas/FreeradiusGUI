#!/usr/bin/env bash
set -euo pipefail

# --------------------------------------------------------------------------
# FreeRADIUS GUI installer
# Run as root on the same host where FreeRADIUS is installed (apt/yum).
# --------------------------------------------------------------------------

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="/opt/freeradius-gui"
STATE_DIR="/etc/freeradius-gui"

if [[ $EUID -ne 0 ]]; then
  echo "Please run this script as root (sudo ./install.sh)" >&2
  exit 1
fi

echo "== FreeRADIUS GUI installer =="

# --- detect FreeRADIUS config dir -----------------------------------------
RADDB=""
for candidate in /etc/freeradius/3.0 /etc/raddb /etc/freeradius; do
  if [[ -d "$candidate" && -f "$candidate/clients.conf" ]]; then
    RADDB="$candidate"
    break
  fi
done
if [[ -z "$RADDB" ]]; then
  echo "Could not auto-detect a FreeRADIUS config directory (looked for" >&2
  echo "clients.conf under /etc/freeradius/3.0, /etc/raddb, /etc/freeradius)." >&2
  read -rp "Enter your FreeRADIUS config directory manually: " RADDB
  if [[ ! -f "$RADDB/clients.conf" ]]; then
    echo "clients.conf not found in $RADDB - aborting." >&2
    exit 1
  fi
fi
echo "Detected FreeRADIUS config dir: $RADDB"

# --- detect service name ----------------------------------------------------
SERVICE_NAME=""
for svc in freeradius radiusd; do
  if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}\.service"; then
    SERVICE_NAME="$svc"
    break
  fi
done
if [[ -z "$SERVICE_NAME" ]]; then
  read -rp "Could not detect systemd service name. Enter it manually (e.g. freeradius or radiusd): " SERVICE_NAME
fi
echo "Detected service name: $SERVICE_NAME"

# --- detect radiusd binary --------------------------------------------------
RADIUSD_BIN=""
for bin in freeradius radiusd; do
  if command -v "$bin" >/dev/null 2>&1; then
    RADIUSD_BIN="$(command -v "$bin")"
    break
  fi
done
if [[ -z "$RADIUSD_BIN" ]]; then
  echo "Could not find freeradius/radiusd binary in PATH - config test won't work until fixed." >&2
  RADIUSD_BIN="freeradius"
fi
echo "Using radiusd binary: $RADIUSD_BIN"

# --- python venv -------------------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required but not found." >&2
  exit 1
fi

echo "Deploying app to $APP_DIR ..."
mkdir -p "$APP_DIR"
cp -r "$SRC_DIR"/app.py "$SRC_DIR"/templates "$SRC_DIR"/static "$SRC_DIR"/requirements.txt "$APP_DIR"/

python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip >/dev/null
"$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt"

# --- admin credentials -------------------------------------------------------
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"

BIND_PORT=8443
UPGRADE=false

if [[ -f "$STATE_DIR/config.json" ]]; then
  UPGRADE=true
  echo "Existing installation detected at $STATE_DIR - keeping your admin credentials,"
  echo "bind settings, and existing config.json untouched. Only the app code, and"
  echo "any new settings this version needs, will be updated."
else
  read -rp "Choose an admin username [admin]: " ADMIN_USER
  ADMIN_USER="${ADMIN_USER:-admin}"

  ADMIN_PASS="$(python3 -c 'import secrets; print(secrets.token_urlsafe(12))')"
  read -rp "Choose an admin password [press Enter to auto-generate]: " ADMIN_PASS_INPUT
  if [[ -n "$ADMIN_PASS_INPUT" ]]; then
    ADMIN_PASS="$ADMIN_PASS_INPUT"
  fi

  ADMIN_PASS_HASH="$("$APP_DIR/venv/bin/python" -c "
from werkzeug.security import generate_password_hash
import sys
print(generate_password_hash(sys.argv[1]))
" "$ADMIN_PASS")"

  SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"

  GUI_CERT="$STATE_DIR/gui-cert.pem"
  GUI_KEY="$STATE_DIR/gui-key.pem"
  echo "Generating self-signed TLS certificate for the GUI itself ..."
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -subj "/CN=freeradius-gui" \
    -keyout "$GUI_KEY" -out "$GUI_CERT" >/dev/null 2>&1
  chmod 600 "$GUI_KEY"

  python3 - "$STATE_DIR/config.json" <<PYEOF
import json, sys
path = sys.argv[1]
data = {
    "admin_user": "$ADMIN_USER",
    "admin_pass_hash": "$ADMIN_PASS_HASH",
    "secret_key": "$SECRET_KEY",
    "raddb_dir": "$RADDB",
    "service_name": "$SERVICE_NAME",
    "radiusd_bin": "$RADIUSD_BIN",
    "bind_host": "0.0.0.0",
    "bind_port": $BIND_PORT,
    "gui_tls_cert": "$GUI_CERT",
    "gui_tls_key": "$GUI_KEY",
    "last_key_password": "",
}
with open(path, "w") as f:
    json.dump(data, f, indent=2)
PYEOF
  chmod 600 "$STATE_DIR/config.json"
fi

# --- import existing clients.conf into clients.json ---------------------
if [[ ! -f "$STATE_DIR/clients.json" ]]; then
  echo "Importing existing clients.conf entries ..."
  cp "$RADDB/clients.conf" "$RADDB/clients.conf.bak-$(date +%Y%m%d%H%M%S)"
  python3 - "$RADDB/clients.conf" "$STATE_DIR/clients.json" <<'PYEOF'
import json, re, sys

conf_path, out_path = sys.argv[1], sys.argv[2]
text = open(conf_path).read()

clients = []
for m in re.finditer(r'client\s+(\S+)\s*\{([^}]*)\}', text, re.DOTALL):
    name = m.group(1)
    body = m.group(2)

    def field(key):
        fm = re.search(rf'{key}\s*=\s*(\S+)', body)
        return fm.group(1).strip('"') if fm else ""

    ipaddr = field("ipaddr") or field("ipv4addr") or field("ipv6addr")
    if not ipaddr:
        continue
    clients.append({
        "name": name,
        "ipaddr": ipaddr,
        "secret": field("secret"),
        "shortname": field("shortname"),
        "nas_type": field("nas_type"),
        "require_message_authenticator": "yes" in field("require_message_authenticator"),
    })

with open(out_path, "w") as f:
    json.dump(clients, f, indent=2)
print(f"Imported {len(clients)} existing client(s)")
PYEOF
  chmod 600 "$STATE_DIR/clients.json"
fi

# --- systemd unit -------------------------------------------------------
cat > /etc/systemd/system/freeradius-gui.service <<UNIT
[Unit]
Description=FreeRADIUS GUI
After=network.target ${SERVICE_NAME}.service

[Service]
Type=simple
User=root
WorkingDirectory=${APP_DIR}
Environment=FRGUI_STATE_DIR=${STATE_DIR}
ExecStart=${APP_DIR}/venv/bin/python ${APP_DIR}/app.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable freeradius-gui.service
# IMPORTANT: 'enable --now' only starts the service if it isn't already
# running - on an upgrade it would leave the OLD code running in memory
# until the next reboot. Always explicitly restart so new code takes
# effect immediately.
systemctl restart freeradius-gui.service
sleep 1
if ! systemctl is-active --quiet freeradius-gui.service; then
  echo "" >&2
  echo "WARNING: freeradius-gui.service did not start. Check the logs with:" >&2
  echo "  journalctl -u freeradius-gui -n 50 --no-pager" >&2
fi

IP_ADDR="$(hostname -I 2>/dev/null | awk '{print $1}')"
ACTUAL_PORT="$(python3 -c "import json; print(json.load(open('$STATE_DIR/config.json')).get('bind_port', $BIND_PORT))")"
ACTUAL_USER="$(python3 -c "import json; print(json.load(open('$STATE_DIR/config.json')).get('admin_user', 'admin'))")"

echo ""
echo "================================================================"
if [[ "$UPGRADE" == "true" ]]; then
  echo " FreeRADIUS GUI upgraded and running."
  echo ""
  echo "   URL:      https://${IP_ADDR:-<this-host>}:${ACTUAL_PORT}"
  echo "   Username: ${ACTUAL_USER}"
  echo "   Password: (unchanged)"
else
  echo " FreeRADIUS GUI installed and running."
  echo ""
  echo "   URL:      https://${IP_ADDR:-<this-host>}:${ACTUAL_PORT}"
  echo "   Username: ${ADMIN_USER}"
  echo "   Password: ${ADMIN_PASS}"
fi
echo ""
echo " The GUI uses a self-signed certificate, so your browser will warn"
echo " you the first time - that's expected for a local admin tool."
echo ""
echo " IMPORTANT: this tool runs as root and can read/write your RADIUS"
echo " server's private key. Restrict access with a firewall rule to your"
echo " admin IP/subnet, or put it behind a VPN, e.g.:"
echo "   ufw allow from <your-ip> to any port ${ACTUAL_PORT} proto tcp"
echo "================================================================"
