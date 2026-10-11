#!/bin/bash
# Removes the OpenDLP agent. Add --remove-data to also delete logs, cached policy and the machine token.
set -u
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo." >&2; exit 1; }
if [ "$(uname -s)" = "Darwin" ]; then
  DATA="/Library/Application Support/OpenDLP"; PLIST="/Library/LaunchDaemons/org.opendlp.agent.plist"
  launchctl bootout system "$PLIST" 2>/dev/null || true
  rm -f "$PLIST"
  rm -rf "${DATA:?}/bin"
else
  DATA="/var/lib/opendlp"
  systemctl disable --now opendlp-agent 2>/dev/null || true
  rm -f /etc/systemd/system/opendlp-agent.service
  systemctl daemon-reload 2>/dev/null || true
  rm -rf /opt/opendlp
fi
pkill -f opendlp-agent 2>/dev/null || true
if [ "${1:-}" = "--remove-data" ]; then rm -rf "$DATA"; else rm -f "$DATA/agent.config.json"; fi
echo "OpenDLP agent removed."
