#!/usr/bin/env bash
#
# db-maintenance.sh
#
# MariaDB maintenance for CyberPanel servers:
#   1. Optimize and repair all user tables (mysqlcheck)
#   2. Report database sizes
#   3. Report top 15 largest tables
#   4. Identify orphaned databases (no matching CyberPanel website)
#   5. Report slow query log status
#
# Safe to run weekly. Installs a weekly cron (Sunday 04:00 UTC) on first run.
# To disable the cron: rm /etc/cron.d/weekly-db-maintenance
#
# Usage:
#   bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server/main/db-maintenance.sh)
#

set -uo pipefail

log()  { echo "[+] $*"; }
warn() { echo "[-] $*"; }
err()  { echo "[ERROR] $*" >&2; }

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  err "This script must be run as root (sudo)."
  exit 1
fi

LOG_FILE="/var/log/db-maintenance.log"
mkdir -p "$(dirname "$LOG_FILE")"
exec > >(tee -a "$LOG_FILE") 2>&1

echo
echo "============================================================"
echo "  LunaServers – Database Maintenance"
echo "  Started: $(date -Is)"
echo "============================================================"
echo

MYSQL_PW_FILE="/etc/cyberpanel/mysqlPassword"
[[ ! -f "$MYSQL_PW_FILE" ]] && { err "CyberPanel MySQL password not found at $MYSQL_PW_FILE"; exit 1; }
MYSQL_PW="$(<"$MYSQL_PW_FILE")"

mysql_q() {
  mysql -u root -p"$MYSQL_PW" -N -B "$@" 2>/dev/null
}

# ---------------------------------------------------------------
# Get all user databases (exclude system DBs)
# ---------------------------------------------------------------
SYSTEM_DBS="mysql|information_schema|performance_schema|sys|cyberpanel"

log "Fetching database list..."
mapfile -t USER_DBS < <(
  mysql_q -e "SHOW DATABASES;" | grep -Ev "^(${SYSTEM_DBS})$" || true
)

if (( ${#USER_DBS[@]} == 0 )); then
  warn "No user databases found."
  exit 0
fi
log "Found ${#USER_DBS[@]} user database(s)."

# ---------------------------------------------------------------
# 1. Optimize and repair all tables
# ---------------------------------------------------------------
echo
echo "============================================================"
echo "  Optimizing & repairing tables"
echo "============================================================"

for db in "${USER_DBS[@]}"; do
  [[ -z "${db:-}" ]] && continue
  log "  $db"
  # InnoDB always says "note: Table does not support optimize, doing recreate + analyze instead"
  # followed by "status: OK" — both are normal and suppressed; only actual problems are shown.
  mysqlcheck -u root -p"$MYSQL_PW" --optimize --auto-repair "$db" 2>&1 \
    | grep -Ev "^\s*$| OK$|note: Table does not support optimize" \
    | sed 's/^/    /' || true
done

# ---------------------------------------------------------------
# 2. Database sizes
# ---------------------------------------------------------------
echo
echo "============================================================"
echo "  Database sizes"
echo "============================================================"
echo

mysql_q -e "
SELECT
  table_schema                                                        AS 'Database',
  CONCAT(ROUND(SUM(data_length + index_length) / 1024 / 1024, 2), ' MB') AS 'Size',
  SUM(table_rows)                                                     AS 'Approx rows'
FROM information_schema.tables
WHERE table_schema NOT REGEXP '^(${SYSTEM_DBS})$'
GROUP BY table_schema
ORDER BY SUM(data_length + index_length) DESC;
" 2>/dev/null | column -t -s $'\t' | sed 's/^/  /' || true

# ---------------------------------------------------------------
# 3. Top 15 largest tables
# ---------------------------------------------------------------
echo
echo "============================================================"
echo "  Top 15 largest tables"
echo "============================================================"
echo

mysql_q -e "
SELECT
  CONCAT(table_schema, '.', table_name)                              AS 'Table',
  CONCAT(ROUND((data_length + index_length) / 1024 / 1024, 2), ' MB') AS 'Size',
  table_rows                                                          AS 'Rows'
FROM information_schema.tables
WHERE table_schema NOT REGEXP '^(${SYSTEM_DBS})$'
  AND table_type = 'BASE TABLE'
ORDER BY (data_length + index_length) DESC
LIMIT 15;
" 2>/dev/null | column -t -s $'\t' | sed 's/^/  /' || true

# ---------------------------------------------------------------
# 4. Orphaned databases
# ---------------------------------------------------------------
echo
echo "============================================================"
echo "  Orphaned database check"
echo "============================================================"

mapfile -t CYBERPANEL_DBS < <(
  mysql_q cyberpanel -e \
    "SELECT defaultDatabase FROM websiteFunctions_websites;" 2>/dev/null || true
)

ORPHANED=()
for db in "${USER_DBS[@]}"; do
  [[ -z "${db:-}" ]] && continue
  found=false
  for cp_db in "${CYBERPANEL_DBS[@]}"; do
    [[ "$cp_db" == "$db" ]] && { found=true; break; }
  done
  $found || ORPHANED+=("$db")
done

if (( ${#ORPHANED[@]} == 0 )); then
  log "All user databases match a CyberPanel website — no orphans."
else
  warn "Found ${#ORPHANED[@]} database(s) with no matching CyberPanel site:"
  for db in "${ORPHANED[@]}"; do
    printf "  [-] %s\n" "$db"
  done
  warn "Verify before deleting — some may be shared or staging databases."
  warn "To remove: mysql -u root -p -e \"DROP DATABASE \`<name>\`;\""
fi

# ---------------------------------------------------------------
# 5. Slow query log status
# ---------------------------------------------------------------
echo
echo "============================================================"
echo "  Slow query log"
echo "============================================================"

slow_enabled=$(mysql_q -e "SHOW VARIABLES LIKE 'slow_query_log';"    | awk '{print $2}' || echo "OFF")
slow_file=$(mysql_q    -e "SHOW VARIABLES LIKE 'slow_query_log_file';" | awk '{print $2}' || echo "")
long_time=$(mysql_q    -e "SHOW VARIABLES LIKE 'long_query_time';"   | awk '{print $2}' || echo "?")

log "slow_query_log:   $slow_enabled"
log "long_query_time:  ${long_time}s"
log "log file:         ${slow_file:-not set}"

if [[ "$slow_enabled" == "ON" && -n "$slow_file" && -f "$slow_file" ]]; then
  slow_count=$(grep -c "^# Query_time" "$slow_file" 2>/dev/null || echo 0)
  log "Slow queries logged so far: $slow_count"
  if (( slow_count > 0 )); then
    warn "Last 3 slow queries:"
    grep -A3 "^# Query_time" "$slow_file" 2>/dev/null | tail -12 | sed 's/^/  /' || true
  fi
else
  log "Slow query logging is OFF."
  log "To enable, add to /etc/mysql/mariadb.conf.d/50-server.cnf:"
  log "  slow_query_log = 1"
  log "  long_query_time = 2"
fi

# ---------------------------------------------------------------
# Touch marker
# ---------------------------------------------------------------
touch /root/.db_maintenance_last_run 2>/dev/null || true

echo
echo "============================================================"
echo "  Database Maintenance Complete — $(date -Is)"
echo "============================================================"
log "Full log: $LOG_FILE"
echo

# ---------------------------------------------------------------
# Install weekly cron (idempotent)
# ---------------------------------------------------------------
CRON_DB="/etc/cron.d/weekly-db-maintenance"

if [[ ! -f "$CRON_DB" ]]; then
  log "Installing weekly database maintenance cron (Sunday 04:00)..."
  cat > "$CRON_DB" << 'CRONEOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MAILTO=root

# Weekly MariaDB optimize, repair, and health check (Sunday 04:00)
# To disable: rm /etc/cron.d/weekly-db-maintenance
0 4 * * 0 root bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server/main/db-maintenance.sh) >> /var/log/db-maintenance.log 2>&1
CRONEOF
  chmod 644 "$CRON_DB"
  log "Cron installed: $CRON_DB (weekly, Sunday 04:00)"
else
  log "Weekly DB maintenance cron already present: $CRON_DB"
fi

log "Done."
