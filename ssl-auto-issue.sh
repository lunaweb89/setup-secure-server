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
  local output

  # Method 1: CyberPanel CLI (preferred, CyberPanel 2.x+)
  # CyberPanel prints JSON: {"success": 1} on success, {"success": 0} on failure.
  # Exit code alone is unreliable — must check the JSON "success" field.
  if command -v cyberpanel >/dev/null 2>&1; then
    output="$(cyberpanel issueSSL --domainName "$domain" 2>&1 || true)"
    echo "$output"
    if echo "$output" | grep -q '"success"[[:space:]]*:[[:space:]]*1'; then
      return 0
    fi
    # If CLI gave no JSON at all (older CyberPanel), treat non-empty success output as OK
    if [[ -z "$(echo "$output" | grep -i '"success"')" ]] && \
       echo "$output" | grep -qi "success\|issued\|completed"; then
      return 0
    fi
  fi

  # Method 2: CyberPanel Python management command (fallback)
  local CYBERCP_PY="/usr/local/CyberCP/bin/python"
  local CYBERCP_MG="/usr/local/CyberCP/manage.py"
  if [[ -f "$CYBERCP_PY" && -f "$CYBERCP_MG" ]]; then
    output="$("$CYBERCP_PY" "$CYBERCP_MG" issueSSL --domainName "$domain" 2>&1 || true)"
    echo "$output"
    if echo "$output" | grep -q '"success"[[:space:]]*:[[:space:]]*1'; then
      return 0
    fi
  fi

  return 1
}

# -------------------------------------------------------------
# Helper: issue SSL for the server hostname
# cyberpanel issueSSL only works for registered CyberPanel websites;
# the hostname is not a website so we use CyberPanel's own acme.sh.
# -------------------------------------------------------------

issue_ssl_hostname() {
  local domain="$1"
  local cert_file="/etc/letsencrypt/live/${domain}/fullchain.pem"

  # Skip if cert already exists and is not expiring within 30 days
  if [[ -f "$cert_file" ]]; then
    if openssl x509 -checkend 2592000 -noout -in "$cert_file" 2>/dev/null; then
      log "Cert for $domain already valid and not expiring soon — skipping."
      return 0
    fi
    log "Cert for $domain exists but expiring soon — renewing..."
  fi

  # Find acme.sh (CyberPanel installs it for root)
  local ACME=""
  for candidate in \
    /root/.acme.sh/acme.sh \
    /usr/local/CyberCP/bin/acme.sh \
    "$(command -v acme.sh 2>/dev/null || true)"
  do
    [[ -x "$candidate" ]] && { ACME="$candidate"; break; }
  done

  if [[ -z "$ACME" ]]; then
    warn "acme.sh not found. Cannot issue hostname cert automatically."
    warn "Issue SSL for the hostname manually via CyberPanel or certbot."
    return 1
  fi

  mkdir -p "/etc/letsencrypt/live/${domain}"

  # Method 1: webroot (preferred — no service interruption)
  # OLS serves the default host at /usr/local/lsws/DEFAULT/html/
  local WEBROOT="/usr/local/lsws/DEFAULT/html"
  if [[ -d "$WEBROOT" ]]; then
    log "Issuing hostname cert via acme.sh webroot (no service interruption)..."
    mkdir -p "${WEBROOT}/.well-known/acme-challenge"
    if "$ACME" --issue --webroot "$WEBROOT" -d "$domain" 2>&1; then
      "$ACME" --installcert -d "$domain" \
        --fullchain-file "/etc/letsencrypt/live/${domain}/fullchain.pem" \
        --key-file       "/etc/letsencrypt/live/${domain}/privkey.pem" 2>&1 || true
      [[ -f "$cert_file" ]] && return 0
    fi
  fi

  # Method 2: standalone (stops OLS briefly if needed)
  log "Trying acme.sh standalone for hostname cert (brief OLS pause)..."
  local ols_was_running=false
  if systemctl is-active --quiet lsws 2>/dev/null; then
    ols_was_running=true
    systemctl stop lsws
  fi

  local result=1
  if "$ACME" --issue --standalone -d "$domain" 2>&1; then
    "$ACME" --installcert -d "$domain" \
      --fullchain-file "/etc/letsencrypt/live/${domain}/fullchain.pem" \
      --key-file       "/etc/letsencrypt/live/${domain}/privkey.pem" 2>&1 || true
    [[ -f "$cert_file" ]] && result=0
  fi

  $ols_was_running && systemctl start lsws
  return $result
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
    if [[ "$resolved" == "172.67."* || "$resolved" == "104.21."* || "$resolved" == "172.64."* ]]; then
      warn "This IP appears to be Cloudflare. If this domain uses Cloudflare proxy,"
      warn "temporarily disable the orange cloud (DNS only) then re-run to issue SSL."
    else
      warn "Point the domain's A record to $SERVER_IP and re-run to issue SSL."
    fi
    SKIPPED_DNS+=("$domain (resolves to: $resolved)")
    echo
    continue
  fi

  log "$domain → $SERVER_IP ✓  Proceeding with SSL issuance..."

  # Hostname is not a CyberPanel website — use certbot directly
  if [[ "$domain" == "$HOSTNAME_FQDN" ]]; then
    if issue_ssl_hostname "$domain"; then
      log "SSL issued successfully for $domain"
      SUCCESS+=("$domain")
    else
      warn "SSL issuance failed for $domain"
      FAILED+=("$domain")
    fi
    echo
    continue
  fi

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

# -------------------------------------------------------------
# Rebuild Postfix SNI map if mail SSL fix has been applied
# This ensures renewed certs are picked up by Postfix overnight
# -------------------------------------------------------------

if [[ -f /root/.mail_ssl_setup_last_run && -f /etc/postfix/sni_map ]]; then
  log "Rebuilding Postfix SNI map (mail SSL fix is installed)..."
  POSTFIX_SNI_DIR="/etc/postfix/sni"
  POSTFIX_SNI_MAP="/etc/postfix/sni_map"
  mkdir -p "$POSTFIX_SNI_DIR"
  > "$POSTFIX_SNI_MAP"
  SNI_REBUILT=0
  declare -A _SNI_PEM
  for domain_path in /etc/letsencrypt/live/*/; do
    domain=$(basename "$domain_path")
    [[ "$domain" == "README" ]] && continue
    cert="${domain_path}fullchain.pem"
    key="${domain_path}privkey.pem"
    [[ -f "$cert" && -f "$key" ]] || continue
    openssl x509 -checkend 0 -noout -in "$cert" 2>/dev/null || continue
    combined="${POSTFIX_SNI_DIR}/${domain}.pem"
    cat "$key" "$cert" > "$combined"
    chmod 640 "$combined"
    openssl x509 -noout -in "$combined" 2>/dev/null || { rm -f "$combined"; continue; }
    echo "${domain} ${combined}" >> "$POSTFIX_SNI_MAP"
    _SNI_PEM["$domain"]="$combined"
    SNI_REBUILT=$(( SNI_REBUILT + 1 ))
  done
  # Add mail.<domain> fallback entries for bare domains that have no dedicated cert
  for domain in "${!_SNI_PEM[@]}"; do
    [[ "$domain" == mail.* || "$domain" == www.* || "$domain" == smtp.* ]] && continue
    dots="${domain//[^.]/}"; [[ "${#dots}" -ne 1 ]] && continue
    mail_key="mail.${domain}"
    [[ -n "${_SNI_PEM[$mail_key]+x}" ]] && continue
    echo "${mail_key} ${_SNI_PEM[$domain]}" >> "$POSTFIX_SNI_MAP"
    SNI_REBUILT=$(( SNI_REBUILT + 1 ))
  done
  chmod 640 "$POSTFIX_SNI_MAP"
  postmap hash:"$POSTFIX_SNI_MAP"
  systemctl reload postfix 2>/dev/null || systemctl restart postfix 2>/dev/null || true
  log "Postfix SNI map rebuilt: $SNI_REBUILT entry(ies). Postfix reloaded."
fi

log "Done."
