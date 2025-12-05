#!/usr/bin/env bash
#
# list-backups.sh
#
# Show a clean list of Borg backups (archives) in the configured repository.
#

set -euo pipefail

log() { echo "[+] $*"; }
err() { echo "[-] $*" >&2; }

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    err "This script must be run as root (sudo)."
    exit 1
  fi
}

require_root

BORG_PASSFILE="/root/.borg-passphrase"
REPO_FILE="/root/.borg-repository"

if [[ ! -f "$BORG_PASSFILE" ]]; then
  err "Borg passphrase file not found at $BORG_PASSFILE"
  exit 1
fi

if [[ ! -f "$REPO_FILE" ]]; then
  err "Borg repository file not found at $REPO_FILE"
  exit 1
fi

export BORG_PASSPHRASE="$(<"$BORG_PASSFILE")"
REPOSITORY="$(<"$REPO_FILE")"
BORG_BIN="$(command -v borg || echo /usr/bin/borg)"

log "Listing backups in repository: $REPOSITORY"
echo

# Name + timestamp; adjust format if you want more details
"$BORG_BIN" list --format='{archive:<40} {time:%Y-%m-%d %H:%M:%S}\n' "$REPOSITORY" || {
  err "Failed to list archives."
  exit 1
}

echo
exit 0
