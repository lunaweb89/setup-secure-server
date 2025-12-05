#!/usr/bin/env bash
#
# restore-backup.sh – Safe Borg restore with auto-increment restore directory
# and automatic cleanup of older restore folders.
#

set -euo pipefail

err() { echo "[-] $*" >&2; }
log() { echo "[+] $*"; }

BORG_PASSFILE="/root/.borg-passphrase"
REPO_FILE="/root/.borg-repository"
KEEP_RESTORES=3   # how many restore folders per archive prefix to keep

# -------------------------------------------------------------
# Validation
# -------------------------------------------------------------

if [[ ! -f "$BORG_PASSFILE" ]]; then
  err "Passphrase file missing: $BORG_PASSFILE"
  exit 1
fi

if [[ ! -f "$REPO_FILE" ]]; then
  err "Repository file missing: $REPO_FILE"
  exit 1
fi

export BORG_PASSPHRASE="$(<"$BORG_PASSFILE")"
REPOSITORY="$(<"$REPO_FILE")"

echo "============================================"
echo " Borg Restore Helper"
echo "============================================"
echo "Repository: $REPOSITORY"
echo

# -------------------------------------------------------------
# Fetch archive list
# -------------------------------------------------------------

log "Fetching archive list..."
if ! borg list --short "$REPOSITORY" > /tmp/borg-archives.$$; then
  err "Cannot list archives. Incorrect passphrase or connectivity issue."
  rm -f /tmp/borg-archives.$$
  exit 1
fi

mapfile -t ARCHIVES < /tmp/borg-archives.$$
rm -f /tmp/borg-archives.$$

if (( ${#ARCHIVES[@]} == 0 )); then
  err "No archives found."
  exit 1
fi

echo "Available archives:"
for i in "${!ARCHIVES[@]}"; do
  printf "  %2d) %s\n" "$((i+1))" "${ARCHIVES[i]}"
done
echo

read -rp "Select archive number (or q to quit): " CHOICE
if [[ "$CHOICE" =~ ^[Qq]$ ]]; then exit 0; fi
if ! [[ "$CHOICE" =~ ^[0-9]+$ ]]; then err "Invalid choice."; exit 1; fi

INDEX=$((CHOICE - 1))
if (( INDEX < 0 || INDEX >= ${#ARCHIVES[@]} )); then err "Out of range."; exit 1; fi

ARCHIVE="${ARCHIVES[$INDEX]}"

log "Selected: $ARCHIVE"
echo

# -------------------------------------------------------------
# Base restore directory
# -------------------------------------------------------------

read -rp "Base restore directory [/restore]: " BASE
BASE="${BASE:-/restore}"
BASE="${BASE%/}"

# -------------------------------------------------------------
# Automatic cleanup of old restore folders
# -------------------------------------------------------------

ARCHIVE_PREFIX="$(basename "$ARCHIVE")"

if [[ -d "$BASE" ]]; then
  # Find dirs in BASE starting with ARCHIVE_PREFIX, sorted by mtime (newest first)
  mapfile -t OLD_DIRS < <(
    find "$BASE" -maxdepth 1 -mindepth 1 -type d -name "${ARCHIVE_PREFIX}*" -printf '%T@ %p\n' \
      | sort -nr \
      | awk '{ $1=""; sub(/^ /, ""); print }'
  )

  if (( ${#OLD_DIRS[@]} > KEEP_RESTORES )); then
    TO_DELETE_COUNT=$(( ${#OLD_DIRS[@]} - KEEP_RESTORES ))
    log "Found ${#OLD_DIRS[@]} existing restore dirs for prefix '${ARCHIVE_PREFIX}'."
    log "Keeping newest ${KEEP_RESTORES}, deleting oldest ${TO_DELETE_COUNT}."

    for ((i=KEEP_RESTORES; i<${#OLD_DIRS[@]}; i++)); do
      DIR="${OLD_DIRS[i]}"
      if [[ -d "$DIR" ]]; then
        log "Deleting old restore dir: $DIR"
        rm -rf -- "$DIR"
      fi
    done
  fi
fi

# -------------------------------------------------------------
# Determine restore target (with auto-increment)
# -------------------------------------------------------------

TARGET="${BASE}/${ARCHIVE_PREFIX}"

if [[ -e "$TARGET" ]]; then
  log "Target exists, choosing next available name..."

  n=1
  NEW_TARGET="${TARGET}-${n}"

  while [[ -e "$NEW_TARGET" ]]; do
    n=$((n+1))
    NEW_TARGET="${TARGET}-${n}"
  done

  TARGET="$NEW_TARGET"
fi

log "Restore directory will be: $TARGET"
mkdir -p "$TARGET"

# -------------------------------------------------------------
# Extract archive
# -------------------------------------------------------------

log "Starting restore…"
cd "$TARGET"

START=$(date +%s)

if borg extract --list "$REPOSITORY::$ARCHIVE"; then
  END=$(date +%s)
  DUR=$((END - START))
  MIN=$((DUR / 60))
  SEC=$((DUR % 60))

  echo
  log "Restore completed successfully!"
  log "Restored to: $TARGET"
  echo "[INFO] Time taken: ${MIN}m ${SEC}s"
else
  err "Restore failed."
  exit 1
fi

exit 0
