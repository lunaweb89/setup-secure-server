#!/usr/bin/env bash
#
# ssl-auto-issue.sh
#
# Auto-issue Let's Encrypt SSL certificates via CyberPanel for:
#   - The server hostname
#   - All websites registered in CyberPanel
#
# Safety rules:
#   - DNS is verified before each attempt: only proceeds if the domain
#     resolves to THIS server's IP (avoids Let's Encrypt failures for
#     domains not yet pointed here)
#   - Safe to re-run: CyberPanel skips domains that already have a
#     valid cert and are not close to expiry
#   - One domain failing does not abort the rest
#
# Run directly:
#   bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server/main/ssl-auto-issue.sh)
#

set -uo pipefail   # no -e so one domain failure never aborts the whole run

log()  { echo "[+] $*"; }
warn() { echo "[-] $*"; }
err()  { echo "[ERROR] $*" >&2; }

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  err "This script must be run as root (sudo)."
  exit 1
fi

LOG_FILE="/var/log/ssl-auto-issue.log"
mkdir -p "$(dirname "$LOG_FILE")"
exec > >(tee -a "$LOG_FILE") 2>&1

echo
echo "============================================================"
echo "  LunaServers – SSL Auto-Issue"
echo "  Started: $(date -Is)"
echo "============================================================"
echo

# -------------------------------------------------------------
# Detect this server's public IP
# -------------------------------------------------------------

log "Detecting server's public IP..."
SERVER_IP=$(curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null \
         || curl -fsSL --max-time 5 https://checkip.amazonaws.com 2>/dev/null \
         || hostname -I | awk '{print $1}')

if [[ -z "${SERVER_IP:-}" ]]; then
  err "Could not detect server's public IP. Aborting."
  exit 1
fi
log "Server IP: ${SERVER_IP}"

# -------------------------------------------------------------
# CyberPanel check
# -------------------------------------------------------------

MYSQL_PW_FILE="/etc/cyberpanel/mysqlPassword"
if [[ ! -f "$MYSQL_PW_FILE" ]]; then
  err "CyberPanel MySQL password not found at $MYSQL_PW_FILE"
  err "Is CyberPanel installed on this server?"
  exit 1
fi
MYSQL_PW="$(<"$MYSQL_PW_FILE")"

# -------------------------------------------------------------
# Ensure dig is available for DNS checks
# -------------------------------------------------------------

if ! command -v dig >/dev/null 2>&1; then
  log "Installing dnsutils (dig)..."
  apt-get install -y -qq dnsutils
fi

# -------------------------------------------------------------
# Collect all domains: hostname + every CyberPanel website
# -------------------------------------------------------------

log "Fetching websites from CyberPanel database..."

mapfile -t SITE_DOMAINS < <(
  mysql -u root -p"$MYSQL_PW" cyberpanel -N -B \
    -e "SELECT domain FROM websiteFunctions_websites;" 2>/dev/null || true
)

HOSTNAME_FQDN="$(hostname -f 2>/dev/null || hostname)"

declare -A _SEEN
ALL_DOMAINS=()
for d in "$HOSTNAME_FQDN" "${SITE_DOMAINS[@]}"; do
  [[ -z "${d:-}" ]] && continue
  [[ -n "${_SEEN[$d]+x}" ]] && continue
  _SEEN["$d"]=1
  ALL_DOMAINS+=("$d")
done

log "Hostname: $HOSTNAME_FQDN"
log "CyberPanel sites found: ${#SITE_DOMAINS[@]}"
log "Total unique domains to process: ${#ALL_DOMAINS[@]}"
echo

# -------------------------------------------------------------
# Helper: check domain resolves to this server
# -------------------------------------------------------------

resolves_here() {
  local domain="$1"
  local resolved_ip
  resolved_ip=$(dig +short A "$domain" 2>/dev/null | grep -E '^[0-9]+\.' | tail -n1 || true)
  [[ "$resolved_ip" == "$SERVER_IP" ]]
}

get_resolved_ip() {
  dig +short A "$1" 2>/dev/null | grep -E '^[0-9]+\.' | tail -n1 || echo "unresolvable"
}

# -------------------------------------------------------------
# Helper: issue SSL via CyberPanel
#
# CyberPanel handles OLS vhost cert config automatically when
# SSL is issued through its own mechanism.
# -------------------------------------------------------------

issue_ssl_for() {
  local domain="$1"

  # Method 1: CyberPanel CLI (preferred, CyberPanel 2.x+)
  if command -v cyberpanel >/dev/null 2>&1; then
    if cyberpanel issueSSL --domainName "$domain" 2>/dev/null; then
      return 0
    fi
  fi

  # Method 2: CyberPanel Python management command (fallback)
  local CYBERCP_PY="/usr/local/CyberCP/bin/python"
  local CYBERCP_MG="/usr/local/CyberCP/manage.py"
  if [[ -f "$CYBERCP_PY" && -f "$CYBERCP_MG" ]]; then
    if "$CYBERCP_PY" "$CYBERCP_MG" issueSSL --domainName "$domain" 2>/dev/null; then
      return 0
    fi
  fi

  return 1
}

# -------------------------------------------------------------
# Process each domain
# -------------------------------------------------------------

SUCCESS=()
SKIPPED_DNS=()
FAILED=()

for domain in "${ALL_DOMAINS[@]}"; do
  echo "------------------------------------------------------------"
  log "Processing: $domain"

  if ! resolves_here "$domain"; then
    resolved="$(get_resolved_ip "$domain")"
    warn "DNS mismatch: $domain resolves to $resolved, not $SERVER_IP — skipping."
    warn "Point the domain's A record to $SERVER_IP and re-run to issue SSL."
    SKIPPED_DNS+=("$domain (resolves to: $resolved)")
    echo
    continue
  fi

  log "$domain → $SERVER_IP ✓  Proceeding with SSL issuance..."

  if issue_ssl_for "$domain"; then
    log "SSL issued successfully for $domain"
    SUCCESS+=("$domain")
  else
    warn "SSL issuance failed for $domain"
    warn "Check CyberPanel logs or issue manually via:"
    warn "  https://<server-ip>:8090 → SSL → Manage SSL → $domain"
    FAILED+=("$domain")
  fi
  echo
done

# -------------------------------------------------------------
# Touch marker
# -------------------------------------------------------------

touch /root/.ssl_auto_issue_last_run 2>/dev/null || true

# -------------------------------------------------------------
# Summary
# -------------------------------------------------------------

echo "============================================================"
echo "  SSL Auto-Issue Summary — $(date -Is)"
echo "============================================================"

printf "\n  Issued successfully (%d):\n" "${#SUCCESS[@]}"
for d in "${SUCCESS[@]}"; do printf "    [OK] %s\n" "$d"; done

printf "\n  Skipped — DNS not pointed here yet (%d):\n" "${#SKIPPED_DNS[@]}"
for d in "${SKIPPED_DNS[@]}"; do printf "    [--] %s\n" "$d"; done

printf "\n  Failed (%d):\n" "${#FAILED[@]}"
for d in "${FAILED[@]}"; do printf "    [!!] %s\n" "$d"; done

echo
log "Full log: $LOG_FILE"
echo

if (( ${#FAILED[@]} > 0 )); then
  echo "For any failed domains, you can:"
  echo "  1. Issue manually in CyberPanel: https://<server-ip>:8090 → SSL → Manage SSL"
  echo "  2. Re-run this script after fixing the issue"
  echo
fi

# -------------------------------------------------------------
# Install daily renewal cron (idempotent)
# -------------------------------------------------------------

CRON_SSL="/etc/cron.d/daily-ssl-renew"

if [[ ! -f "$CRON_SSL" ]]; then
  log "Installing daily SSL renewal cron (02:00)..."
  cat > "$CRON_SSL" << 'CRONEOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MAILTO=root

# Daily SSL check & renewal — CyberPanel skips certs that are still valid
0 2 * * * root bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server/main/ssl-auto-issue.sh) >> /var/log/ssl-auto-issue.log 2>&1
CRONEOF
  chmod 644 "$CRON_SSL"
  log "Cron installed: $CRON_SSL (runs daily at 02:00)"
else
  log "Daily SSL renewal cron already present: $CRON_SSL"
fi

log "Done."
