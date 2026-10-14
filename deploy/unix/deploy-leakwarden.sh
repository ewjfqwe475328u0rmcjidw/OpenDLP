#!/bin/bash
# Silent Leakwarden agent deployment for many Macs / Linux machines (Jamf, Kandji, Intune for Mac, Mosyle, SSH, Ansible).
#
#   curl -fsSL https://github.com/<owner>/<repo>/releases/download/v0.15.0/deploy-leakwarden.sh \
#     | sudo bash -s -- --server-url https://dlp.example.com --enrollment-code "CODE"
#
# Picks the right package for the CPU/OS, verifies its SHA-256 and runs install.sh. Re-running on a machine that
# already has this version does nothing. Any other options (--paths, --agent-id, --display-name) go to install.sh.
#   --package FILE --sha256 HASH   use a local / file-share copy instead of downloading
set -euo pipefail

VERSION="v0.15.0"; REPO="leakwarden/leakwarden"; PACKAGE=""; SHA=""; FORCE=0
INSTALL_ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --repo) REPO="$2"; shift 2 ;;
    --package) PACKAGE="$2"; shift 2 ;;
    --sha256) SHA="$2"; shift 2 ;;
    --force) FORCE=1; shift ;;
    *) INSTALL_ARGS+=("$1"); shift ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo." >&2; exit 1; }

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) NAME="Leakwarden-macos-arm64-$VERSION.tar.gz"; MARK="/Library/Application Support/Leakwarden/bin/installed-version.txt" ;;
  Darwin-x86_64) NAME="Leakwarden-macos-x64-$VERSION.tar.gz"; MARK="/Library/Application Support/Leakwarden/bin/installed-version.txt" ;;
  Linux-x86_64) NAME="Leakwarden-linux-x64-$VERSION.tar.gz"; MARK="/opt/leakwarden/installed-version.txt" ;;
  *) echo "Unsupported platform: $(uname -s) $(uname -m)" >&2; exit 1 ;;
esac

if [ "$FORCE" -eq 0 ] && [ -f "$MARK" ] && [ "$(cat "$MARK")" = "$VERSION" ] && pgrep -f "leakwarden-agent --config" >/dev/null; then
  echo "Leakwarden $VERSION already installed - nothing to do"; exit 0
fi

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
if [ -z "$PACKAGE" ]; then
  BASE="https://github.com/$REPO/releases/download/$VERSION"
  echo "Downloading $BASE/$NAME"
  curl -fsSL -o "$TMP/$NAME" "$BASE/$NAME"
  if [ -z "$SHA" ]; then
    curl -fsSL -o "$TMP/SHA256SUMS.txt" "$BASE/SHA256SUMS.txt"
    SHA="$(awk -v n="$NAME" '$2==n || $2=="*"n {print $1}' "$TMP/SHA256SUMS.txt")"
    [ -n "$SHA" ] || { echo "No checksum for $NAME" >&2; exit 1; }
  fi
  PACKAGE="$TMP/$NAME"
fi
[ -f "$PACKAGE" ] || { echo "Package not found: $PACKAGE" >&2; exit 1; }

if [ -n "$SHA" ]; then
  if command -v sha256sum >/dev/null; then ACTUAL="$(sha256sum "$PACKAGE" | awk '{print $1}')"; else ACTUAL="$(shasum -a 256 "$PACKAGE" | awk '{print $1}')"; fi
  [ "$(echo "$ACTUAL" | tr 'A-F' 'a-f')" = "$(echo "$SHA" | tr 'A-F' 'a-f')" ] || { echo "Checksum mismatch: expected $SHA, got $ACTUAL" >&2; exit 1; }
  echo "Checksum verified"
else
  echo "WARNING: no --sha256 given for a local package; integrity not verified"
fi

tar -xzf "$PACKAGE" -C "$TMP"
INSTALLER="$(find "$TMP" -name install.sh -type f | head -1)"
[ -n "$INSTALLER" ] || { echo "install.sh not found in package" >&2; exit 1; }
bash "$INSTALLER" ${INSTALL_ARGS[@]+"${INSTALL_ARGS[@]}"}   # bash 3.2 (macOS) safe with an empty array
echo "$VERSION" > "$MARK"
echo "Leakwarden $VERSION installed"
