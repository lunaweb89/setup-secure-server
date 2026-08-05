#!/usr/bin/env bash
#
# server-toolkit.sh
#
# Simple menu wrapper for:
#   - setup-secure-server.sh          (full hardening)
#   - setup-backup-module.sh          (backup + storage box)
#   - restore-backup.sh               (disaster recovery)
#   - server-optimizer.sh             (performance tuning)
#   - server-optimizer-rollback.sh    (rollback optimizer changes)
#   - ssl-auto-issue.sh               (issue & auto-renew SSL certs)
#   - setup-mail-ssl.sh               (fix SMTP/SSL mismatch, Dovecot SNI)
#   - check-mail-health.sh            (SPF/DKIM/DMARC/DNSBL checks)
#   - wp-auto-update.sh               (update WordPress core/plugins/themes)
#   - db-maintenance.sh               (optimize MariaDB, report orphans)
#

set -euo pipefail

BASE_URL="https://raw.githubusercontent.com/lunaweb89/setup-secure-server/main"

log() { echo "[+] $*"; }

run_full_secure_setup() {
  log "Starting full secure server setup..."
  bash <(curl -fsSL "${BASE_URL}/setup-secure-server.sh")
}

run_backup_setup_only() {
  log "Starting backup module setup..."
  bash <(curl -fsSL "${BASE_URL}/setup-backup-module.sh")
}

run_restore_module_only() {
  log "Starting restore module..."
  bash <(curl -fsSL "${BASE_URL}/restore-backup.sh")
}

run_optimizer_only() {
  log "Starting performance optimizer..."
  bash <(curl -fsSL "${BASE_URL}/server-optimizer.sh")
}

run_optimizer_rollback() {
  log "Starting performance optimizer rollback..."
  bash <(curl -fsSL "${BASE_URL}/server-optimizer-rollback.sh")
}

run_ssl_auto_issue() {
  log "Starting SSL auto-issue & renewal setup..."
  bash <(curl -fsSL "${BASE_URL}/ssl-auto-issue.sh")
}

run_mail_ssl_fix() {
  log "Starting mail SSL fix (Dovecot SNI + Postfix TLS)..."
  bash <(curl -fsSL "${BASE_URL}/setup-mail-ssl.sh")
}

run_mail_health_check() {
  log "Starting mail deliverability health check..."
  bash <(curl -fsSL "${BASE_URL}/check-mail-health.sh")
}

run_wp_auto_update() {
  log "Starting WordPress auto-updater..."
  bash <(curl -fsSL "${BASE_URL}/wp-auto-update.sh")
}

run_db_maintenance() {
  log "Starting database maintenance..."
  bash <(curl -fsSL "${BASE_URL}/db-maintenance.sh")
}

show_status() {
  echo "============================================================"
  echo "                 LunaServers – Status"
  echo "============================================================"

  # Markers (optional – adapt if you use different marker files)
  for f in \
    /root/.secure_server_setup_done \
    /root/.backup_module_setup_done \
    /root/.restore_module_last_run \
    /root/.server_optimizer_last_run \
    /root/.server_optimizer_rollback_last_run \
    /root/.ssl_auto_issue_last_run \
    /root/.mail_ssl_setup_last_run \
    /root/.wp_auto_update_last_run \
    /root/.db_maintenance_last_run
  do
    if [[ -f "$f" ]]; then
      echo "  [OK]  Marker present: $f"
    else
      echo "  [--]  Marker missing: $f"
    fi
  done

  echo
  echo "Cronjob presence:"
  for cron_file in \
    /etc/cron.d/daily-borg-backup \
    /etc/cron.d/auto-security-updates \
    /etc/cron.d/weekly-malware-scan \
    /etc/cron.d/daily-ssl-renew \
    /etc/cron.d/weekly-wp-updates \
    /etc/cron.d/weekly-db-maintenance
  do
    if [[ -f "$cron_file" ]]; then
      echo "  [OK]  Present: $cron_file"
    else
      echo "  [--]  Missing: $cron_file"
    fi
  done

  echo
  echo "Borg backup connectivity:"
  if [[ -f /root/.borg-repository ]]; then
    echo "  Repo: $(<"/root/.borg-repository")"
    if [[ -x /usr/local/bin/borg-passphrase-test.sh ]]; then
      /usr/local/bin/borg-passphrase-test.sh \
        && echo "  [OK]  Borg connectivity verified." \
        || echo "  [!!]  Borg connectivity FAILED — check passphrase/SSH key."
    else
      echo "  [--]  borg-passphrase-test.sh not installed (run backup setup first)."
    fi
  else
    echo "  [--]  /root/.borg-repository not found (run backup setup first)."
  fi

  echo
  echo "UFW status (if installed):"
  if command -v ufw >/dev/null 2>&1; then
    ufw status verbose || true
  else
    echo "  UFW not installed."
  fi

  echo
  echo "Fail2Ban status (if installed):"
  if systemctl list-unit-files | grep -q '^fail2ban\.service'; then
    systemctl status fail2ban --no-pager || true
  else
    echo "  Fail2Ban not installed."
  fi

  echo
  read -r -p "Press ENTER to return to menu..." _
}

while :; do
  cat <<'MENU'

============================================================
              LunaServers – Server Toolkit Menu
============================================================

  1) Full Secure Server Setup
     - Runs setup-secure-server.sh
     - Hardens SSH (custom port), UFW, Fail2Ban
     - Sets up auto security updates, ClamAV, Maldet
     - Optionally runs Backup + Storage Box module from inside
     - Optionally runs Performance Optimizer from inside

  2) Run Auto Backup Setup Only
     - Runs setup-backup-module.sh for automated backup
     - Sets up Borg + Hetzner Storage Box backups
     - Creates daily backup cronjob and helper scripts

  3) Run Restore Module Only
     - Runs restore-backup.sh
     - Restores selected sites from Borg backups
     - For disaster recovery / migrations
     NOTE: Running this repeatedly will NOT 'break' the OS,
           but CAN overwrite site files/databases each time.

  4) Run Performance Optimizer Only
     - Runs server-optimizer.sh
     - Auto-tunes sysctl, limits, OpenLiteSpeed, PHP LSAPI
     - Auto-tunes MariaDB (60% RAM) & Redis (15% RAM, capped at 2GB)

  5) Run Performance Optimizer Rollback
     - Runs server-optimizer-rollback.sh
     - Restores last known-good configs for sysctl, OLS, PHP, MariaDB, Redis

  6) View Status
     - Shows markers, Borg repo & connectivity, cronjob presence

  7) SSL Auto-Issue & Renewal Setup
     - Issues Let's Encrypt SSL for server hostname + all CyberPanel sites
     - Verifies DNS points to this server before each attempt
     - Installs a daily cron (02:00) to auto-renew expiring certs
     - Safe to re-run; skips domains with valid certs

  8) Mail SSL Fix (SMTP mismatch / Outlook rejection)
     - Configures Postfix TLS using the server hostname cert
     - Configures Dovecot SNI: each domain presents its own SSL cert
       for IMAP/POP3 (fixes Outlook "certificate mismatch" errors)
     - Enables LMTP delivery pipeline between Postfix and Dovecot
     - Run AFTER option 7 (ssl-auto-issue) so certs are already issued
     - Re-run any time you add new domains to pick up new certs

  9) Mail Deliverability Health Check
     - Checks SPF, DKIM, DMARC DNS records for every CyberPanel domain
     - Checks IP against 5 major DNSBL / spam blacklists (Spamhaus, etc.)
     - Checks PTR / reverse DNS matches hostname
     - Reports SSL cert expiry for each mail.<domain>
     - No external APIs — pure dig queries

  10) WordPress Auto-Updater
     - Updates WordPress core, plugins, and themes on all sites under /home
     - Creates a compressed MySQL dump before each site is updated
     - Verifies HTTP 200 after updating; flags failures with restore command
     - Installs a weekly cron (Monday 03:00) on first run
     - WP-CLI is auto-installed if not present

  11) Database Maintenance
     - Runs mysqlcheck --optimize --auto-repair on all user databases
     - Reports database sizes and top 15 largest tables
     - Identifies orphaned databases with no matching CyberPanel site
     - Reports slow query log status
     - Installs a weekly cron (Sunday 04:00) on first run

  12) Exit Toolkit
============================================================
MENU

  read -r -p "Select an option [1-12]: " choice

  case "$choice" in
    1)  run_full_secure_setup ;;
    2)  run_backup_setup_only ;;
    3)  run_restore_module_only ;;
    4)  run_optimizer_only ;;
    5)  run_optimizer_rollback ;;
    6)  show_status ;;
    7)  run_ssl_auto_issue ;;
    8)  run_mail_ssl_fix ;;
    9)  run_mail_health_check ;;
    10) run_wp_auto_update ;;
    11) run_db_maintenance ;;
    12) exit 0 ;;
    *) echo "Invalid choice. Please enter 1–12." ;;
  esac
done
