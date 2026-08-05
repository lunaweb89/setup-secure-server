#!/usr/bin/env bash
#
# wp-auto-update.sh
#
# Updates WordPress core, plugins, and themes across all installs under /home/.
# Before each site is updated, a compressed MySQL dump is saved to
# /root/wp-update-backups/ so you can restore if anything breaks.
# After updating, HTTP response is checked; failures are flagged prominently.
#
# WP-CLI is installed automatically if not present.
# Backups older than 7 days are pruned automatically.
#
# Usage:
#   bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server/main/wp-auto-update.sh)
#
# Weekly cron is installed on first run (Monday 03:00 UTC).
# To disable the cron: rm /etc/cron.d/weekly-wp-updates
#

set -uo pipefail

log()  { echo "[+] $*"; }
warn() { echo "[-] $*"; }
err()  { echo "[ERROR] $*" >&2; }

# Safe mode: skip major version bumps (e.g. WooCommerce 8→9, Elementor 3→4).
# Major updates can introduce breaking changes and should be reviewed manually.
# Default: ON (safe). Pass --all to include major updates.
SAFE_MODE=true
for arg in "$@"; do
  [[ "$arg" == "--all" ]] && SAFE_MODE=false
done

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  err "This script must be run as root (sudo)."
  exit 1
fi

LOG_FILE="/var/log/wp-auto-update.log"
BACKUP_DIR="/root/wp-update-backups"
mkdir -p "$(dirname "$LOG_FILE")" "$BACKUP_DIR"
exec > >(tee -a "$LOG_FILE") 2>&1

echo
echo "============================================================"
echo "  LunaServers – WordPress Auto-Updater"
echo "  Started: $(date -Is)"
echo "============================================================"
echo

# ---------------------------------------------------------------
# Ensure WP-CLI is available
# ---------------------------------------------------------------
WP_CLI=""
if command -v wp >/dev/null 2>&1; then
  WP_CLI="$(command -v wp)"
  log "WP-CLI: $WP_CLI"
else
  log "WP-CLI not found — installing..."
  curl -fsSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar \
    -o /usr/local/bin/wp 2>&1
  chmod +x /usr/local/bin/wp
  WP_CLI="/usr/local/bin/wp"
  if ! "$WP_CLI" --info >/dev/null 2>&1; then
    err "WP-CLI installation failed. Aborting."
    exit 1
  fi
  log "WP-CLI installed: $WP_CLI"
fi

# CyberPanel MySQL password
MYSQL_PW_FILE="/etc/cyberpanel/mysqlPassword"
[[ ! -f "$MYSQL_PW_FILE" ]] && { err "CyberPanel MySQL password not found at $MYSQL_PW_FILE"; exit 1; }
MYSQL_PW="$(<"$MYSQL_PW_FILE")"

# ---------------------------------------------------------------
# Find all WordPress installs under /home
# ---------------------------------------------------------------
log "Scanning for WordPress installs under /home..."
mapfile -t WP_CONFIGS < <(find /home -maxdepth 5 -name wp-config.php 2>/dev/null | sort)

if (( ${#WP_CONFIGS[@]} == 0 )); then
  warn "No WordPress installs found under /home."
  exit 0
fi
log "Found ${#WP_CONFIGS[@]} WordPress install(s)."

# ---------------------------------------------------------------
# Counters
# ---------------------------------------------------------------
UPDATED=()
SKIPPED=()
FAILED=()

# ---------------------------------------------------------------
# Process each install
# ---------------------------------------------------------------
for config_path in "${WP_CONFIGS[@]}"; do
  install_dir="$(dirname "$config_path")"

  echo
  echo "------------------------------------------------------------"
  log "WordPress: $install_dir"

  # Get site URL
  site_url=$("$WP_CLI" option get siteurl --path="$install_dir" --allow-root 2>/dev/null || echo "")
  if [[ -z "$site_url" ]]; then
    warn "  Cannot get siteurl — skipping (may be a partial install)"
    SKIPPED+=("$install_dir")
    continue
  fi
  log "  URL: $site_url"

  # Determine database name from wp-config.php
  db_name=$(grep -E "^define\s*\(\s*['\"]DB_NAME['\"]" "$config_path" \
    | grep -oP "(?<='|\")\w+(?='|\")" | tail -n1 || echo "")

  # --- Pre-update database backup ---
  timestamp=$(date +%Y%m%d-%H%M%S)
  safe_name=$(echo "$install_dir" | tr '/' '_' | sed 's/^_//')
  backup_file="${BACKUP_DIR}/${safe_name}-${timestamp}.sql.gz"

  if [[ -n "$db_name" ]]; then
    log "  Backing up: $db_name → $(basename "$backup_file")"
    if mysqldump -u root -p"$MYSQL_PW" "$db_name" 2>/dev/null | gzip > "$backup_file"; then
      log "  Backup OK ($(du -sh "$backup_file" | cut -f1))"
    else
      warn "  Backup failed — proceeding without backup"
      rm -f "$backup_file"
    fi
  else
    warn "  DB_NAME not found in wp-config.php — skipping backup"
  fi

  # --- Update WordPress core ---
  # Safe mode: --minor only applies security/minor releases (e.g. 6.5.4 → 6.5.5).
  # Full mode: updates to the latest major release too (e.g. 6.5 → 6.6).
  if $SAFE_MODE; then
    log "  Updating core (minor/security only)..."
    "$WP_CLI" core update --minor --path="$install_dir" --allow-root 2>&1 | sed 's/^/    /' || true
  else
    log "  Updating core (all versions)..."
    "$WP_CLI" core update --path="$install_dir" --allow-root 2>&1 | sed 's/^/    /' || true
  fi
  "$WP_CLI" core update-db --path="$install_dir" --allow-root 2>&1 | sed 's/^/    /' || true

  # --- Update plugins ---
  # Safe mode: skip any plugin whose major version number changes (X.y.z → X+1.y.z).
  # Those are reviewed and updated manually. Minor/patch updates apply automatically.
  log "  Updating plugins..."
  local plugin_skipped=()
  if $SAFE_MODE; then
    while IFS=',' read -r name cur_ver new_ver; do
      [[ "$name" == "name" || -z "${name:-}" ]] && continue
      cur_major="${cur_ver%%.*}"
      new_major="${new_ver%%.*}"
      if [[ "$cur_major" != "$new_major" ]]; then
        warn "  SKIP plugin (major update: $name $cur_ver → $new_ver — update manually)"
        plugin_skipped+=("$name ($cur_ver → $new_ver)")
      else
        "$WP_CLI" plugin update "$name" --path="$install_dir" --allow-root 2>&1 | sed 's/^/    /' || true
      fi
    done < <("$WP_CLI" plugin list --update=available \
        --fields=name,version,update_version --format=csv \
        --path="$install_dir" --allow-root 2>/dev/null || true)
  else
    "$WP_CLI" plugin update --all --path="$install_dir" --allow-root 2>&1 | sed 's/^/    /' || true
  fi

  # --- Update themes ---
  log "  Updating themes..."
  local theme_skipped=()
  if $SAFE_MODE; then
    while IFS=',' read -r name cur_ver new_ver; do
      [[ "$name" == "name" || -z "${name:-}" ]] && continue
      cur_major="${cur_ver%%.*}"
      new_major="${new_ver%%.*}"
      if [[ "$cur_major" != "$new_major" ]]; then
        warn "  SKIP theme (major update: $name $cur_ver → $new_ver — update manually)"
        theme_skipped+=("$name ($cur_ver → $new_ver)")
      else
        "$WP_CLI" theme update "$name" --path="$install_dir" --allow-root 2>&1 | sed 's/^/    /' || true
      fi
    done < <("$WP_CLI" theme list --update=available \
        --fields=name,version,update_version --format=csv \
        --path="$install_dir" --allow-root 2>/dev/null || true)
  else
    "$WP_CLI" theme update --all --path="$install_dir" --allow-root 2>&1 | sed 's/^/    /' || true
  fi

  if (( ${#plugin_skipped[@]} + ${#theme_skipped[@]} > 0 )); then
    warn "  Major updates skipped (safe mode — update these manually):"
    for s in "${plugin_skipped[@]}" "${theme_skipped[@]}"; do
      printf "    [--] %s\n" "$s"
    done
  fi

  # --- Post-update HTTP check ---
  log "  Checking HTTP response..."
  http_code=$(curl -skL --max-time 15 -o /dev/null -w "%{http_code}" "$site_url" 2>/dev/null || echo "000")

  if [[ "$http_code" =~ ^(200|301|302)$ ]]; then
    log "  HTTP $http_code ✓  Site responding normally"
    UPDATED+=("$site_url")
  else
    warn "  HTTP $http_code — site may be broken after update!"
    warn "  Inspect: $site_url"
    [[ -f "$backup_file" ]] && warn "  Restore DB: zcat $backup_file | mysql -u root -p${MYSQL_PW} $db_name"
    FAILED+=("$site_url  [HTTP $http_code]")
  fi

  echo
done

# ---------------------------------------------------------------
# Prune old backups (> 7 days)
# ---------------------------------------------------------------
log "Pruning backups older than 7 days in $BACKUP_DIR..."
find "$BACKUP_DIR" -name "*.sql.gz" -mtime +7 -delete 2>/dev/null || true

# ---------------------------------------------------------------
# Touch marker
# ---------------------------------------------------------------
touch /root/.wp_auto_update_last_run 2>/dev/null || true

# ---------------------------------------------------------------
# Summary
# ---------------------------------------------------------------
echo "============================================================"
echo "  WordPress Auto-Update Summary — $(date -Is)"
echo "============================================================"

printf "\n  Updated / verified OK (%d):\n" "${#UPDATED[@]}"
for u in "${UPDATED[@]}"; do printf "    [OK] %s\n" "$u"; done

printf "\n  Skipped (%d):\n" "${#SKIPPED[@]}"
for u in "${SKIPPED[@]}"; do printf "    [--] %s\n" "$u"; done

printf "\n  FAILED — check immediately (%d):\n" "${#FAILED[@]}"
for u in "${FAILED[@]}"; do printf "    [!!] %s\n" "$u"; done

echo
log "Database backups: $BACKUP_DIR"
log "Full log: $LOG_FILE"
echo

# ---------------------------------------------------------------
# Install weekly cron (idempotent)
# ---------------------------------------------------------------
CRON_WP="/etc/cron.d/weekly-wp-updates"

if [[ ! -f "$CRON_WP" ]]; then
  log "Installing weekly WordPress update cron (Monday 03:00)..."
  cat > "$CRON_WP" << 'CRONEOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MAILTO=root

# Weekly WordPress core + plugin + theme updates (Monday 03:00)
# Pre-update DB backups saved to /root/wp-update-backups/
# To disable: rm /etc/cron.d/weekly-wp-updates
0 3 * * 1 root bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server/main/wp-auto-update.sh) >> /var/log/wp-auto-update.log 2>&1
CRONEOF
  chmod 644 "$CRON_WP"
  log "Cron installed: $CRON_WP (weekly, Monday 03:00)"
  warn "NOTE: Auto-updates run unattended. Review /var/log/wp-auto-update.log each week."
  warn "      Disable the cron if you prefer manual control: rm $CRON_WP"
else
  log "Weekly WP update cron already present: $CRON_WP"
fi

log "Done."
