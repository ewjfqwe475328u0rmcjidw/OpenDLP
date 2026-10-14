#!/bin/bash
# Leakwarden agent installer for macOS (launchd) and Linux (systemd). Run from the extracted release folder:
#
#   sudo ./install.sh --server-url https://dlp.example.com --enrollment-code "CODE"
#   sudo ./install.sh --server-url ... --enrollment-code ... --paths "{AllUsers}/Documents,/srv/finance" --agent-id mac-042
#
# The enrollment code is exchanged for a per-machine token on first start (stored root-only, mode 0600).
# macOS: grant the agent "Full Disk Access" (System Settings > Privacy & Security) or deploy a PPPC profile via MDM,
# otherwise macOS privacy protection (TCC) hides Desktop/Documents/Downloads from it.
set -euo pipefail

SERVER_URL=""; ENROLL=""; AGENT_ID="$(hostname -s 2>/dev/null || hostname)"; DISPLAY_NAME=""; PATHS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --server-url) SERVER_URL="$2"; shift 2 ;;
    --enrollment-code) ENROLL="$2"; shift 2 ;;
    --agent-id) AGENT_ID="$2"; shift 2 ;;
    --display-name) DISPLAY_NAME="$2"; shift 2 ;;
    --paths) PATHS="$2"; shift 2 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo." >&2; exit 1; }
[ -n "$SERVER_URL" ] && [ -n "$ENROLL" ] || { echo "--server-url and --enrollment-code are required." >&2; exit 2; }

SRC="$(cd "$(dirname "$0")" && pwd)"
[ -x "$SRC/leakwarden-agent" ] || chmod +x "$SRC/leakwarden-agent" 2>/dev/null || true
[ -f "$SRC/leakwarden-agent" ] || { echo "leakwarden-agent binary not found next to this script." >&2; exit 1; }

OS="$(uname -s)"
if [ "$OS" = "Darwin" ]; then
  DATA="/Library/Application Support/Leakwarden"; BIN="$DATA/bin"; LABEL="org.leakwarden.agent"
  PLIST="/Library/LaunchDaemons/$LABEL.plist"
  DEFAULT_PATHS='"{AllUsers}/Desktop","{AllUsers}/Documents","{AllUsers}/Downloads"'
else
  DATA="/var/lib/leakwarden"; BIN="/opt/leakwarden"; UNIT="/etc/systemd/system/leakwarden-agent.service"
  DEFAULT_PATHS='"{AllUsers}/Desktop","{AllUsers}/Documents","{AllUsers}/Downloads"'
fi

json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }
if [ -n "$PATHS" ]; then
  PATHS_JSON=""
  IFS=',' read -r -a parts <<< "$PATHS"
  for p in "${parts[@]}"; do PATHS_JSON="$PATHS_JSON${PATHS_JSON:+,}\"$(json_escape "$p")\""; done
else
  PATHS_JSON="$DEFAULT_PATHS"
fi

# ---- stop a previous installation ----
if [ "$OS" = "Darwin" ]; then
  launchctl bootout system "$PLIST" 2>/dev/null || true
else
  systemctl stop leakwarden-agent 2>/dev/null || true
fi

# ---- files ----
mkdir -p "$BIN" "$DATA/logs" "$DATA/policy"
chmod 755 "$DATA"
for f in "$SRC"/*; do
  case "$(basename "$f")" in agent.config.json|install.sh|uninstall.sh) ;; *) cp -R "$f" "$BIN/" ;; esac
done
cp "$SRC/uninstall.sh" "$BIN/" 2>/dev/null || true
chmod 755 "$BIN/leakwarden-agent"
chown -R root "$BIN" "$DATA"
[ "$OS" = "Darwin" ] && xattr -dr com.apple.quarantine "$BIN" 2>/dev/null || true

CFG="$DATA/agent.config.json"
umask 077
cat > "$CFG" <<JSON
{
  "AgentId": "$(json_escape "$AGENT_ID")",
  "DisplayName": "$(json_escape "$DISPLAY_NAME")",
  "ServerUrl": "$(json_escape "$SERVER_URL")",
  "EnrollmentCode": "$(json_escape "$ENROLL")",
  "TelemetryEnabled": true,
  "SensitivePaths": [ $PATHS_JSON ],
  "PolicyPollSeconds": 60,
  "LogRetentionDays": 30
}
JSON
chmod 600 "$CFG"
umask 022

# ---- service ----
if [ "$OS" = "Darwin" ]; then
  cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array><string>$BIN/leakwarden-agent</string><string>--config</string><string>$CFG</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>5</integer>
  <key>StandardOutPath</key><string>$DATA/logs/agent.out.log</string>
  <key>StandardErrorPath</key><string>$DATA/logs/agent.err.log</string>
</dict>
</plist>
PLISTEOF
  chmod 644 "$PLIST"; chown root:wheel "$PLIST"
  launchctl bootstrap system "$PLIST"
  launchctl enable "system/$LABEL" || true
  echo "Installed. Status: launchctl print system/$LABEL | grep state"
  echo "Grant Full Disk Access to $BIN/leakwarden-agent (or deploy a PPPC profile) so protected folders can be monitored."
else
  cat > "$UNIT" <<UNITEOF
[Unit]
Description=Leakwarden endpoint agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$BIN/leakwarden-agent --config $CFG
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
UNITEOF
  systemctl daemon-reload
  systemctl enable --now leakwarden-agent
  echo "Installed. Status: systemctl status leakwarden-agent"
fi
echo "Logs: $DATA/logs   Uninstall: sudo \"$BIN/uninstall.sh\""
