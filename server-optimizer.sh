#!/usr/bin/env bash
#
# server-optimizer.sh (v2)
#
# Auto-Optimization Script for:
#   - Ubuntu 20.04 / 22.04 / 24.04
#   - OpenLiteSpeed
#   - CyberPanel
#   - MariaDB
#   - Redis
#   - WordPress / WooCommerce workloads
#
# Auto-detects CPU/RAM and tunes server based on:
#   - MariaDB = 60% RAM
#   - Redis = 15% RAM (capped at 2GB)
#   - Leaves ~25% RAM for OS + PHP + OLS spikes
#
# Fully automatic — only warns on unsafe conditions, does not crash the server.
#

set -euo pipefail

log()  { echo -e "[+] $*"; }
warn() { echo -e "[-] $*"; }
err()  { echo -e "[ERROR] $*" >&2; }

timestamp="$(date +%Y%m%d-%H%M%S)"

###############################################
# 1. DETECT CPU & RAM
###############################################

log "Detecting system resources..."

TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_RAM_MB=$((TOTAL_RAM_KB / 1024))
TOTAL_RAM_GB=$((TOTAL_RAM_MB / 1024))

CPU_CORES=$(nproc)

log "Total RAM: ${TOTAL_RAM_MB} MB (${TOTAL_RAM_GB} GB)"
log "CPU cores: ${CPU_CORES}"

if (( TOTAL_RAM_MB < 2048 )); then
  warn "Server has less than 2GB RAM. Optimization may be limited."
fi

###############################################
# 2. CALCULATE ALLOCATIONS
###############################################

log "Calculating dynamic RAM allocations..."

# MariaDB = 60%
MARIADB_MB=$(( TOTAL_RAM_MB * 60 / 100 ))
# Redis = 15% but max 2GB
REDIS_MB=$(( TOTAL_RAM_MB * 15 / 100 ))
if (( REDIS_MB > 2048 )); then REDIS_MB=2048; fi

RESERVED_MB=$(( TOTAL_RAM_MB - MARIADB_MB - REDIS_MB ))

log "MariaDB Allocation: ${MARIADB_MB} MB"
log "Redis Allocation: ${REDIS_MB} MB"
log "Reserved for OS/spikes: ${RESERVED_MB} MB"

###############################################
# 3. SAFETY CHECK — DISK SPACE
###############################################

DISK_PCT=$(df / | awk 'NR==2{print $5}' | sed 's/%//')

if (( DISK_PCT > 85 )); then
    warn "Disk usage above 85%. This is unsafe for optimization."
    read -rp "Proceed anyway? (y/N): " ans
    if [[ ! "$ans" =~ ^[Yy]$ ]]; then
        err "Aborting to avoid breaking server."
        exit 1
    fi
fi

###############################################
# 4. SYSCTL OPTIMIZATION
###############################################

log "Applying sysctl tuning..."

SYSCTL_FILE="/etc/sysctl.d/99-ols-optimized.conf"

cp "$SYSCTL_FILE" "$SYSCTL_FILE.bak-$timestamp" 2>/dev/null || true

cat > "$SYSCTL_FILE" <<EOF
fs.file-max = 1048576

net.core.somaxconn = 65535
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_fin_timeout = 15

vm.swappiness = 10
vm.vfs_cache_pressure = 50
EOF

sysctl --system >/dev/null || warn "sysctl --system reported warnings (often safe on some kernels)."

###############################################
# 5. LIMITS CONFIGURATION
###############################################

log "Updating /etc/security/limits.conf..."

cat > /etc/security/limits.conf <<EOF
* soft nofile 1024000
* hard nofile 1024000
root soft nofile 1024000
root hard nofile 1024000
EOF

###############################################
# 6. OPENLITESPEED OPTIMIZATION
###############################################

log "Optimizing OpenLiteSpeed..."

OLS_CONF="/usr/local/lsws/conf/httpd_config.conf"

if [[ -f "$OLS_CONF" ]]; then
    cp "$OLS_CONF" "$OLS_CONF.bak-$timestamp"

    MAX_CONN=$((CPU_CORES * 4000))
    MAX_SSL=$((CPU_CORES * 1000))

    # maxConnections (handle indentation and also your 'maxConnections <value>' line)
    if grep -Eq "^[[:space:]]*maxConnections" "$OLS_CONF"; then
        sed -i -E "s/^[[:space:]]*maxConnections.*/    maxConnections               ${MAX_CONN}/" "$OLS_CONF"
    else
        echo "    maxConnections               ${MAX_CONN}" >>"$OLS_CONF"
    fi

    # maxSSLConnections
    if grep -Eq "^[[:space:]]*maxSSLConnections" "$OLS_CONF"; then
        sed -i -E "s/^[[:space:]]*maxSSLConnections.*/    maxSSLConnections          ${MAX_SSL}/" "$OLS_CONF"
    else
        echo "    maxSSLConnections          ${MAX_SSL}" >>"$OLS_CONF"
    fi

else
    warn "OpenLiteSpeed config not found at $OLS_CONF. Skipping OLS tuning."
fi

###############################################
# 7. PHP LSAPI OPTIMIZATION (AUTO-DETECT)
###############################################

log "Optimizing all detected PHP LSAPI php.ini files..."

mapfile -t PHPINIS < <(find /usr/local/lsws -type f -name php.ini 2>/dev/null || true)

if ((${#PHPINIS[@]} == 0)); then
  warn "No php.ini found under /usr/local/lsws; skipping PHP LSAPI tuning."
else
  for PHPINI in "${PHPINIS[@]}"; do
    [[ -f "$PHPINI" ]] || continue

    cp "$PHPINI" "$PHPINI.bak-$timestamp"

    # memory_limit and max_execution_time
    if grep -Eq "^memory_limit" "$PHPINI"; then
      sed -i "s/^memory_limit.*/memory_limit = 512M/" "$PHPINI"
    else
      echo "memory_limit = 512M" >>"$PHPINI"
    fi

    if grep -Eq "^max_execution_time" "$PHPINI"; then
      sed -i "s/^max_execution_time.*/max_execution_time = 300/" "$PHPINI"
    else
      echo "max_execution_time = 300" >>"$PHPINI"
    fi

    # lsapi_children = CPU * 10
    if grep -iEq "lsapi_children" "$PHPINI"; then
      sed -i -E "s/^[[:space:];]*lsapi_children.*/lsapi_children = $((CPU_CORES * 10))/" "$PHPINI"
    else
      echo "lsapi_children = $((CPU_CORES * 10))" >>"$PHPINI"
    fi
  done
fi

###############################################
# 8. REDIS OPTIMIZATION
###############################################

log "Optimizing Redis..."

REDIS_CONF="/etc/redis/redis.conf"

if [[ -f "$REDIS_CONF" ]]; then
  cp "$REDIS_CONF" "$REDIS_CONF.bak-$timestamp"

  # maxmemory
  if grep -Eq "^[[:space:]]*maxmemory[[:space:]]" "$REDIS_CONF"; then
    sed -i -E "s/^[[:space:]]*maxmemory[[:space:]].*/maxmemory ${REDIS_MB}mb/" "$REDIS_CONF"
  else
    printf "\nmaxmemory %smb\n" "${REDIS_MB}" >>"$REDIS_CONF"
  fi

  # maxmemory-policy
  if grep -Eq "^[[:space:]]*maxmemory-policy" "$REDIS_CONF"; then
    sed -i -E "s/^[[:space:]]*maxmemory-policy.*/maxmemory-policy allkeys-lru/" "$REDIS_CONF"
  else
    printf "maxmemory-policy allkeys-lru\n" >>"$REDIS_CONF"
  fi
else
  warn "Redis config not found at $REDIS_CONF; skipping Redis tuning."
fi

###############################################
# 9. MARIADB OPTIMIZATION
###############################################

log "Optimizing MariaDB..."

MARIADB_CONF="/etc/mysql/mariadb.conf.d/99-optimized.cnf"
cp "$MARIADB_CONF" "$MARIADB_CONF.bak-$timestamp" 2>/dev/null || true

cat > "$MARIADB_CONF" <<EOF
[mysqld]
max_connections         = 300
connect_timeout         = 5
wait_timeout            = 60
interactive_timeout     = 180
thread_cache_size       = 50

query_cache_type        = 0
query_cache_size        = 0

innodb_buffer_pool_size = ${MARIADB_MB}M
innodb_log_file_size    = 256M
innodb_flush_method     = O_DIRECT
innodb_flush_log_at_trx_commit = 2
innodb_file_per_table   = 1

innodb_io_capacity      = 4000
innodb_io_capacity_max  = 8000
EOF

###############################################
# 10. CONFIG VALIDATION
###############################################

log "Validating configurations..."

if ! mysqld --verbose --help >/dev/null 2>&1; then
    err "MariaDB config test failed. To restore previous config, run:"
    echo "cp $MARIADB_CONF.bak-$timestamp $MARIADB_CONF"
    exit 1
fi

# Light Redis sanity check (does not read redis.conf, just memory self-test)
redis-server --test-memory 64 >/dev/null 2>&1 || warn "Redis memory self-test reported a warning."

###############################################
# 11. RESTART SERVICES
###############################################

log "Restarting Redis..."
if systemctl restart redis-server; then
  :
else
  err "Redis restart failed! Please check: journalctl -u redis-server"
fi

log "Restarting MariaDB..."
if systemctl restart mariadb; then
  :
else
  err "MariaDB restart failed! Please check: journalctl -u mariadb"
fi

if systemctl status lsws >/dev/null 2>&1 || systemctl status lshttpd >/dev/null 2>&1; then
  log "Restarting OpenLiteSpeed..."
  # service name is lshttpd on CyberPanel systems
  if systemctl restart lshttpd 2>/dev/null || systemctl restart lsws 2>/dev/null; then
    :
  else
    err "OpenLiteSpeed restart failed! Please check: journalctl -u lshttpd"
  fi
else
  warn "OpenLiteSpeed service not detected; skipping restart."
fi

###############################################
# 12. HEALTH REPORT
###############################################

log "Optimization completed. Generating health summary..."

echo "------ HEALTH SUMMARY ------"
echo "CPU cores: $CPU_CORES"
echo "Total RAM: ${TOTAL_RAM_MB} MB"
echo "MariaDB: ${MARIADB_MB} MB"
echo "Redis: ${REDIS_MB} MB"
echo "Reserved: ${RESERVED_MB} MB"
echo

echo "MariaDB threads_running:"
mysql -uroot -e "SHOW GLOBAL STATUS LIKE 'Threads_running';" 2>/dev/null || true
echo

echo "Redis usage:"
redis-cli info memory | egrep "used_memory_human|maxmemory_human|mem_fragmentation_ratio" || true
echo

echo "OpenLiteSpeed status:"
if systemctl status lshttpd >/dev/null 2>&1; then
  systemctl status lshttpd --no-pager 2>/dev/null | head -n 8 || true
elif systemctl status lsws >/dev/null 2>&1; then
  systemctl status lsws --no-pager 2>/dev/null | head -n 8 || true
else
  echo "OpenLiteSpeed service not detected."
fi
echo

echo "System failed services:"
systemctl --failed || true

touch /root/.server_optimizer_last_run 2>/dev/null || true

log "Server optimization finished successfully."
