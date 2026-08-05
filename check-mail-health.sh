#!/usr/bin/env bash
#
# check-mail-health.sh
#
# Checks email deliverability for every CyberPanel domain:
#   - PTR / reverse DNS (checked once for server IP)
#   - IP blacklist / DNSBL (checked once for server IP)
#   - MX record
#   - SPF record (v=spf1)
#   - DKIM record (selector: default)
#   - DMARC record
#   - SSL cert status for mail.<domain>
#
# No external APIs — all checks via public DNS (dig).
#
# Usage:
#   bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server/main/check-mail-health.sh)
#

set -uo pipefail

_ok()   { printf "  \033[32m[OK]\033[0m  %s\n" "$*"; }
_fail() { printf "  \033[31m[!!]\033[0m  %s\n" "$*"; }
_warn() { printf "  \033[33m[--]\033[0m  %s\n" "$*"; }
log()   { echo "[+] $*"; }
warn()  { echo "[-] $*"; }
err()   { echo "[ERROR] $*" >&2; }

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  err "This script must be run as root (sudo)."
  exit 1
fi

LOG_FILE="/var/log/mail-health-check.log"
mkdir -p "$(dirname "$LOG_FILE")"
exec > >(tee -a "$LOG_FILE") 2>&1

echo
echo "============================================================"
echo "  LunaServers – Mail Deliverability Health Check"
echo "  Started: $(date -Is)"
echo "============================================================"
echo

# Ensure dig is available
if ! command -v dig >/dev/null 2>&1; then
  log "Installing dnsutils (dig)..."
  apt-get install -y -qq dnsutils
fi

# Server IP and hostname
log "Detecting server public IP..."
SERVER_IP=$(curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null \
         || curl -fsSL --max-time 5 https://checkip.amazonaws.com 2>/dev/null \
         || hostname -I | awk '{print $1}')
[[ -z "${SERVER_IP:-}" ]] && { err "Could not detect server IP."; exit 1; }
SERVER_HOSTNAME="$(hostname -f 2>/dev/null || hostname)"
log "Server IP:       $SERVER_IP"
log "Server hostname: $SERVER_HOSTNAME"
echo

# Reverse IP octets for DNSBL queries (1.2.3.4 → 4.3.2.1)
REVERSED_IP=$(echo "$SERVER_IP" | awk -F. '{print $4"."$3"."$2"."$1}')

# ---------------------------------------------------------------
# Server-level checks (PTR + DNSBL) — done once
# ---------------------------------------------------------------
echo "============================================================"
echo "  Server-level checks  (IP: ${SERVER_IP})"
echo "============================================================"

# PTR / reverse DNS
PTR=$(dig +short -x "$SERVER_IP" 2>/dev/null | sed 's/\.$//' | head -n1 || true)
if [[ -z "$PTR" ]]; then
  _fail "PTR/rDNS: No reverse DNS record for $SERVER_IP"
  _warn "  Set in Hetzner Console → Servers → IP Addresses → PTR → $SERVER_HOSTNAME"
elif [[ "$PTR" == "$SERVER_HOSTNAME" ]]; then
  _ok "PTR/rDNS: $SERVER_IP → $PTR"
else
  _warn "PTR/rDNS: $SERVER_IP → $PTR  (expected $SERVER_HOSTNAME)"
  _warn "  PTR exists but mismatches hostname — Outlook prefers an exact match"
fi

echo
echo "  DNSBL checks:"
DNSBLS=(
  "zen.spamhaus.org"
  "b.barracudacentral.org"
  "bl.spamcop.net"
  "dnsbl.sorbs.net"
  "cbl.abuseat.org"
)
BLACKLISTED=()
for dnsbl in "${DNSBLS[@]}"; do
  result=$(dig +short A "${REVERSED_IP}.${dnsbl}" 2>/dev/null | grep -E '^127\.' | head -n1 || true)
  if [[ -n "$result" ]]; then
    _fail "BLACKLISTED on ${dnsbl}  (code: ${result})"
    BLACKLISTED+=("$dnsbl")
  else
    _ok "Not listed: ${dnsbl}"
  fi
done

if (( ${#BLACKLISTED[@]} > 0 )); then
  echo
  warn "IP $SERVER_IP is on ${#BLACKLISTED[@]} DNSBL(s) — this will cause mail rejection."
  warn "Request delisting: https://mxtoolbox.com/blacklists.aspx"
fi

# ---------------------------------------------------------------
# CyberPanel domain list
# ---------------------------------------------------------------
MYSQL_PW_FILE="/etc/cyberpanel/mysqlPassword"
[[ ! -f "$MYSQL_PW_FILE" ]] && { err "CyberPanel MySQL password not found."; exit 1; }
MYSQL_PW="$(<"$MYSQL_PW_FILE")"

mapfile -t DOMAINS < <(
  mysql -u root -p"$MYSQL_PW" cyberpanel -N -B \
    -e "SELECT domain FROM websiteFunctions_websites;" 2>/dev/null || true
)

if (( ${#DOMAINS[@]} == 0 )); then
  warn "No CyberPanel websites found — nothing to check."
  exit 0
fi

log "Found ${#DOMAINS[@]} CyberPanel domain(s)."

# ---------------------------------------------------------------
# Counters
# ---------------------------------------------------------------
PASS_MX=0; FAIL_MX=0
PASS_SPF=0; FAIL_SPF=0
PASS_DKIM=0; FAIL_DKIM=0
PASS_DMARC=0; FAIL_DMARC=0

# ---------------------------------------------------------------
# Per-domain checks
# ---------------------------------------------------------------
for domain in "${DOMAINS[@]}"; do
  [[ -z "${domain:-}" ]] && continue

  echo
  echo "------------------------------------------------------------"
  echo "  $domain"
  echo "------------------------------------------------------------"

  # --- MX ---
  mx=$(dig +short MX "$domain" 2>/dev/null | sort -n | head -n1 || true)
  if [[ -n "$mx" ]]; then
    _ok "MX: $mx"
    PASS_MX=$(( PASS_MX + 1 ))
  else
    _fail "MX: no MX record"
    _warn "  Add DNS: $domain  MX 10  mail.$domain"
    FAIL_MX=$(( FAIL_MX + 1 ))
  fi

  # --- SPF ---
  spf=$(dig +short TXT "$domain" 2>/dev/null | grep -i 'v=spf1' | tr -d '"' | head -n1 || true)
  if [[ -z "$spf" ]]; then
    _fail "SPF: no SPF record"
    _warn "  Add DNS TXT @: v=spf1 ip4:${SERVER_IP} ~all"
    FAIL_SPF=$(( FAIL_SPF + 1 ))
  else
    # Check if server IP is obviously covered
    if echo "$spf" | grep -qE "ip4:${SERVER_IP}(\/|[[:space:]]|$)"; then
      _ok "SPF: $spf"
      PASS_SPF=$(( PASS_SPF + 1 ))
    elif echo "$spf" | grep -qE "\bmx\b|include:|ip4:[0-9]"; then
      _warn "SPF: $spf"
      _warn "  Record exists — verify ip4:${SERVER_IP} is covered"
      PASS_SPF=$(( PASS_SPF + 1 ))
    else
      _fail "SPF: record may not include $SERVER_IP"
      _warn "  Current: $spf"
      _warn "  Suggested: v=spf1 ip4:${SERVER_IP} ~all"
      FAIL_SPF=$(( FAIL_SPF + 1 ))
    fi
  fi

  # --- DKIM (selector: default — CyberPanel default) ---
  dkim=$(dig +short TXT "default._domainkey.${domain}" 2>/dev/null | tr -d '"' | head -n1 || true)
  if [[ -n "$dkim" ]]; then
    _ok "DKIM (selector=default): present"
    PASS_DKIM=$(( PASS_DKIM + 1 ))
  else
    _fail "DKIM (selector=default): no record"
    _warn "  CyberPanel → Email → DKIM Manager → Enable for $domain"
    _warn "  Copy the TXT record output into your DNS"
    FAIL_DKIM=$(( FAIL_DKIM + 1 ))
  fi

  # --- DMARC ---
  dmarc=$(dig +short TXT "_dmarc.${domain}" 2>/dev/null | tr -d '"' | head -n1 || true)
  if [[ -n "$dmarc" ]]; then
    _ok "DMARC: $dmarc"
    PASS_DMARC=$(( PASS_DMARC + 1 ))
  else
    _fail "DMARC: no record"
    _warn "  Add DNS TXT _dmarc: v=DMARC1; p=quarantine; rua=mailto:postmaster@${domain}"
    FAIL_DMARC=$(( FAIL_DMARC + 1 ))
  fi

  # --- SSL cert for mail.<domain> ---
  mail_cert="/etc/letsencrypt/live/mail.${domain}/fullchain.pem"
  bare_cert="/etc/letsencrypt/live/${domain}/fullchain.pem"
  if [[ -f "$mail_cert" ]]; then
    expiry_str=$(openssl x509 -enddate -noout -in "$mail_cert" 2>/dev/null | cut -d= -f2 || echo "")
    if [[ -n "$expiry_str" ]]; then
      days=$(( ( $(date -d "$expiry_str" +%s 2>/dev/null || echo 0) - $(date +%s) ) / 86400 ))
      if (( days > 30 )); then
        _ok "SSL (mail.${domain}): valid, expires in ${days} days"
      elif (( days > 0 )); then
        _warn "SSL (mail.${domain}): expiring soon — ${days} days left"
      else
        _fail "SSL (mail.${domain}): EXPIRED — run option 7 to renew"
      fi
    else
      _warn "SSL (mail.${domain}): cert present but could not read expiry"
    fi
  elif [[ -f "$bare_cert" ]]; then
    _warn "SSL: no mail.${domain} cert — using ${domain} as fallback"
    _warn "  Run option 7 (SSL Auto-Issue) to issue a dedicated mail.${domain} cert"
  else
    _fail "SSL: no cert found for mail.${domain} or ${domain}"
    _warn "  Run option 7 (SSL Auto-Issue) to issue certs"
  fi
done

# ---------------------------------------------------------------
# Summary
# ---------------------------------------------------------------
echo
echo "============================================================"
echo "  Summary — $(date -Is)"
echo "============================================================"
echo
printf "  %-6s  %s / %s domains passing\n" "MX"    "$PASS_MX"    "$(( PASS_MX + FAIL_MX ))"
printf "  %-6s  %s / %s domains passing\n" "SPF"   "$PASS_SPF"   "$(( PASS_SPF + FAIL_SPF ))"
printf "  %-6s  %s / %s domains passing\n" "DKIM"  "$PASS_DKIM"  "$(( PASS_DKIM + FAIL_DKIM ))"
printf "  %-6s  %s / %s domains passing\n" "DMARC" "$PASS_DMARC" "$(( PASS_DMARC + FAIL_DMARC ))"

if (( ${#BLACKLISTED[@]} > 0 )); then
  echo
  warn "IP BLACKLISTED on: ${BLACKLISTED[*]}"
fi

echo
log "Full log: $LOG_FILE"
log "Test deliverability: https://mail-tester.com  (send a test email, aim for 10/10)"
log "Done."
