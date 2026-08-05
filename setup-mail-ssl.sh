#!/usr/bin/env bash
#
# setup-mail-ssl.sh
#
# Fixes SMTP/SSL mismatch on CyberPanel mail servers so each domain's
# WordPress/WooCommerce site can send mail via mail.<domain>:587 using
# that domain's own SSL cert — not the server hostname cert.
#
# Root cause:
#   CyberPanel manages Postfix and Dovecot cert via symlinks:
#     /etc/postfix/cert.pem  → last domain cert issued via CyberPanel
#     /etc/dovecot/cert.pem  → same
#   After issuing SSL for multiple sites these symlinks point to
#   the LAST domain issued. Postfix then presents that cert for ALL
#   SMTP connections regardless of which domain the client connects to.
#
# What this script does:
#   1. Hostname cert: redirects /etc/postfix/cert.pem and
#      /etc/dovecot/cert.pem to the server HOSTNAME cert (fallback
#      when no SNI match is found)
#   2. Postfix SNI: builds /etc/postfix/sni_map so Postfix presents
#      each domain's own cert when a client connects as mail.<domain>
#      (fixes WordPress/PHPMailer "certificate verify failed" errors)
#   3. Modern TLS settings applied via postconf -e for Outlook compat
#   4. Reports Dovecot per-domain SNI count (managed by CyberPanel)
#
# What this script deliberately does NOT touch:
#   - virtual_transport — CyberPanel uses "dovecot" LDA pipe, not LMTP;
#     changing this would break mail delivery
#   - /etc/dovecot/conf.d/ — CyberPanel's dovecot.conf does not include
#     that directory; drop-in files there are never loaded
#   - /etc/dovecot/dovecot.conf — CyberPanel actively manages this file
#     and appends local_name SNI blocks automatically when you issue SSL
#     per domain via the panel; do not manually edit it
#
# Run AFTER ssl-auto-issue.sh so the hostname cert already exists.
#
# Usage:
#   bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server/main/setup-mail-ssl.sh)
#   bash <(curl -fsSL https://...) --hostname s02.lunaservers.xyz
#

set -euo pipefail

log()  { echo "[+] $*"; }
warn() { echo "[-] $*"; }
err()  { echo "[ERROR] $*" >&2; }

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  err "This script must be run as root (sudo)."
  exit 1
fi

LOG_FILE="/var/log/mail-ssl-setup.log"
mkdir -p "$(dirname "$LOG_FILE")"
exec > >(tee -a "$LOG_FILE") 2>&1

echo
echo "============================================================"
echo "  LunaServers – Mail SSL Fix (CyberPanel)"
echo "  Started: $(date -Is)"
echo "============================================================"
echo

# -------------------------------------------------------------
# Parse --hostname flag or auto-detect
# -------------------------------------------------------------

SERVER_HOSTNAME=""
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --hostname) SERVER_HOSTNAME="$2"; shift 2 ;;
    *) err "Unknown parameter: $1"; exit 1 ;;
  esac
done

if [[ -z "${SERVER_HOSTNAME:-}" ]]; then
  SERVER_HOSTNAME="$(hostname -f 2>/dev/null || hostname)"
fi
log "Mail server hostname: $SERVER_HOSTNAME"

# -------------------------------------------------------------
# Verify Postfix and Dovecot are installed (CyberPanel provides these)
# -------------------------------------------------------------

for bin in postconf dovecot; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    err "$bin is not installed. Is CyberPanel installed on this server?"
    exit 1
  fi
done

# -------------------------------------------------------------
# Locate hostname SSL cert
# CyberPanel (acme.sh) stores certs at /etc/letsencrypt/live/<domain>/
# -------------------------------------------------------------

HOSTNAME_CERT="/etc/letsencrypt/live/${SERVER_HOSTNAME}/fullchain.pem"
HOSTNAME_KEY="/etc/letsencrypt/live/${SERVER_HOSTNAME}/privkey.pem"

if [[ ! -f "$HOSTNAME_CERT" || ! -f "$HOSTNAME_KEY" ]]; then
  err "No SSL cert found for $SERVER_HOSTNAME at:"
  err "  $HOSTNAME_CERT"
  err ""
  err "Run ssl-auto-issue.sh first (option 7 in the toolkit)."
  err "It will issue the hostname cert and certs for all CyberPanel sites."
  exit 1
fi

log "Hostname cert found: $HOSTNAME_CERT"

# Verify the cert is not already expired
if ! openssl x509 -checkend 0 -noout -in "$HOSTNAME_CERT" 2>/dev/null; then
  err "The hostname cert at $HOSTNAME_CERT is EXPIRED."
  err "Re-run ssl-auto-issue.sh to renew it, then retry."
  exit 1
fi

# -------------------------------------------------------------
# Update CyberPanel's cert symlinks to point to the hostname cert
#
# CyberPanel creates these symlinks and updates them to whatever
# domain cert was last issued. We redirect them to the hostname cert
# so Postfix and Dovecot present the correct TLS identity for SMTP.
# -------------------------------------------------------------

log "Updating Postfix cert symlinks → hostname cert..."
mkdir -p /etc/postfix
ln -sf "$HOSTNAME_CERT" /etc/postfix/cert.pem
ln -sf "$HOSTNAME_KEY"  /etc/postfix/key.pem

log "Updating Dovecot cert symlinks → hostname cert..."
mkdir -p /etc/dovecot
ln -sf "$HOSTNAME_CERT" /etc/dovecot/cert.pem
ln -sf "$HOSTNAME_KEY"  /etc/dovecot/key.pem

# CyberPanel also maintains symlinks under /etc/pki/dovecot on some installs
if [[ -d /etc/pki/dovecot ]] || [[ -d /etc/pki ]]; then
  mkdir -p /etc/pki/dovecot/certs /etc/pki/dovecot/private
  ln -sf "$HOSTNAME_CERT" /etc/pki/dovecot/certs/dovecot.pem
  ln -sf "$HOSTNAME_KEY"  /etc/pki/dovecot/private/dovecot.pem
  log "Updated /etc/pki/dovecot symlinks → hostname cert."
fi

log "Cert symlinks updated. Postfix and Dovecot will now use: $SERVER_HOSTNAME"

# -------------------------------------------------------------
# Configure Postfix TLS via postconf -e
#
# postconf -e edits main.cf in place and is CyberPanel-compatible.
# We ONLY touch TLS-related settings.
# virtual_transport is left as-is ("dovecot" LDA pipe).
# -------------------------------------------------------------

log "Configuring Postfix TLS settings..."

postconf -e "myhostname = ${SERVER_HOSTNAME}"
postconf -e "smtpd_tls_cert_file = /etc/postfix/cert.pem"
postconf -e "smtpd_tls_key_file = /etc/postfix/key.pem"
postconf -e "smtpd_tls_security_level = may"
postconf -e "smtpd_tls_auth_only = yes"
postconf -e "smtpd_tls_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1"
postconf -e "smtpd_tls_mandatory_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1"
postconf -e "smtpd_tls_mandatory_ciphers = high"
postconf -e "smtpd_tls_loglevel = 1"
postconf -e "smtp_tls_security_level = may"
postconf -e "smtp_tls_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1"
postconf -e "smtp_tls_loglevel = 1"

log "Postfix TLS configured."
log "  smtpd_tls_cert_file → /etc/postfix/cert.pem → $SERVER_HOSTNAME cert (default/fallback)"
log "  virtual_transport    → $(postconf -h virtual_transport 2>/dev/null || echo '(not set)') [unchanged]"

# -------------------------------------------------------------
# Build Postfix per-domain SNI map
#
# Postfix 3.4+ supports tls_server_sni_maps: when a client connects
# to mail.example.com:587 with SNI, Postfix looks up the domain in
# this map and presents example.com's cert instead of the default.
# This is what allows WordPress to use mail.inszhangfen.com:587
# without a certificate mismatch error.
#
# Combined PEM files (key + fullchain) are stored in /etc/postfix/sni/
# and referenced by the hash map /etc/postfix/sni_map.
# -------------------------------------------------------------

log "Building Postfix per-domain SNI map..."

POSTFIX_SNI_DIR="/etc/postfix/sni"
POSTFIX_SNI_MAP="/etc/postfix/sni_map"

mkdir -p "$POSTFIX_SNI_DIR"
chmod 750 "$POSTFIX_SNI_DIR"

# Rebuild map from scratch each run (picks up newly issued certs)
> "$POSTFIX_SNI_MAP"
POSTFIX_SNI_COUNT=0

# Track which domains were successfully mapped (key = domain, value = combined PEM path)
declare -A SNI_MAPPED_PEM

for domain_path in /etc/letsencrypt/live/*/; do
  domain=$(basename "$domain_path")
  [[ "$domain" == "README" ]] && continue

  cert="${domain_path}fullchain.pem"
  key="${domain_path}privkey.pem"
  [[ -f "$cert" && -f "$key" ]] || continue

  # Skip expired certs
  if ! openssl x509 -checkend 0 -noout -in "$cert" 2>/dev/null; then
    warn "  Skipping expired cert: $domain"
    continue
  fi

  # Skip untrusted certs (staging, self-signed, or any cert whose chain is not in
  # the system CA store) — Postfix cannot serve an untrusted chain via SNI and
  # sends tlsv1 alert internal_error to the connecting SMTP client.
  if ! openssl verify -untrusted "$cert" "$cert" 2>/dev/null | grep -q ": OK"; then
    warn "  Cert for $domain not trusted by system CA (staging or self-signed) — skipping"
    warn "  Re-issue: acme.sh --issue --force --server letsencrypt --standalone -d $domain"
    continue
  fi

  # Postfix SNI needs key + fullchain concatenated in one PEM file (key first)
  combined="${POSTFIX_SNI_DIR}/${domain}.pem"
  cat "$key" "$cert" > "$combined"
  chmod 640 "$combined"

  # Validate combined PEM — bad file → Postfix sends tlsv1 alert internal_error
  if ! openssl x509 -noout -in "$combined" 2>/dev/null; then
    warn "  Combined PEM invalid for $domain (cert unreadable) — skipping"
    rm -f "$combined"
    continue
  fi

  # Verify private key matches certificate — mismatch → Postfix internal_error
  _cert_pub=$(openssl x509 -pubkey -noout -in "$combined" 2>/dev/null)
  _key_pub=$(openssl pkey -pubout -in "$combined" 2>/dev/null)
  if [[ -z "$_cert_pub" || -z "$_key_pub" || "$_cert_pub" != "$_key_pub" ]]; then
    warn "  Key/cert MISMATCH for $domain — skipping (re-issue SSL via CyberPanel)"
    rm -f "$combined"
    continue
  fi

  echo "${domain} ${combined}" >> "$POSTFIX_SNI_MAP"
  SNI_MAPPED_PEM["$domain"]="$combined"
  log "  Postfix SNI mapped: $domain"
  POSTFIX_SNI_COUNT=$(( POSTFIX_SNI_COUNT + 1 ))
done

# Ensure mail.<domain> is in the SNI map for every bare domain.
#
# WordPress SMTP connects to mail.<domain>:587 and sends SNI=mail.<domain>.
# Postfix does an EXACT lookup — if only <domain> is in the map, it misses,
# falls back to the hostname cert, and the client gets a cert mismatch error.
#
# If CyberPanel issued a dedicated cert for mail.<domain> it is already mapped
# above. If not (or if that cert was corrupted/skipped), we add a fallback
# entry pointing to the bare domain's cert so Postfix can at least serve
# a valid cert for the SNI lookup.
for domain in "${!SNI_MAPPED_PEM[@]}"; do
  # Only process bare domains (e.g. example.com, not mail.example.com)
  [[ "$domain" == mail.* || "$domain" == www.* || "$domain" == smtp.* ]] && continue
  dots="${domain//[^.]/}"
  [[ "${#dots}" -ne 1 ]] && continue  # skip multi-level subdomains

  mail_key="mail.${domain}"
  # Skip if mail.<domain> already has its own entry (dedicated cert, mapped above)
  [[ -n "${SNI_MAPPED_PEM[$mail_key]+x}" ]] && continue

  combined="${SNI_MAPPED_PEM[$domain]}"
  echo "${mail_key} ${combined}" >> "$POSTFIX_SNI_MAP"
  log "  Postfix SNI also mapped: mail.${domain} → ${domain} cert"
  POSTFIX_SNI_COUNT=$(( POSTFIX_SNI_COUNT + 1 ))
done

chmod 640 "$POSTFIX_SNI_MAP"

if (( POSTFIX_SNI_COUNT > 0 )); then
  # -F flag is required: embeds each .pem file's content as base64 in the database.
  # Plain `postmap` (no -F) stores the literal file path — Postfix cannot decode
  # that string and sends tlsv1 alert internal_error to every connecting client.
  postmap -F hash:"$POSTFIX_SNI_MAP"
  chmod 640 "${POSTFIX_SNI_MAP}.db" 2>/dev/null || true
  postconf -e "tls_server_sni_maps = hash:${POSTFIX_SNI_MAP}"
  log "Postfix SNI: $POSTFIX_SNI_COUNT entry(ies) mapped."
  log "  WordPress SMTP can now use mail.<domain>:587 with correct cert per domain."
else
  warn "No domain certs found for SNI map — hostname cert will be used for all connections."
  warn "Run ssl-auto-issue.sh first to issue domain certs, then re-run this script."
fi

# -------------------------------------------------------------
# Report Dovecot SNI status
#
# CyberPanel adds "local_name mail.<domain> { ... }" blocks to
# /etc/dovecot/dovecot.conf automatically when you issue SSL for
# a site via the panel. We do not edit dovecot.conf — CyberPanel
# owns that file and overwrites it. Just report what's there.
# -------------------------------------------------------------

DOVECOT_CONF="/etc/dovecot/dovecot.conf"
SNI_COUNT=0
SNI_DOMAINS=()

if [[ -f "$DOVECOT_CONF" ]]; then
  while IFS= read -r line; do
    if [[ "$line" =~ ^local_name[[:space:]]+(.*)[[:space:]]*\{ ]]; then
      SNI_DOMAINS+=("${BASH_REMATCH[1]// /}")
      SNI_COUNT=$(( SNI_COUNT + 1 ))
    fi
  done < "$DOVECOT_CONF"
fi

echo
log "Dovecot SNI status (local_name blocks in $DOVECOT_CONF):"
if (( SNI_COUNT == 0 )); then
  warn "  No SNI entries found. Dovecot will use the hostname cert for all"
  warn "  IMAP/POP3 connections. This is OK but clients connecting as"
  warn "  mail.example.com will see the hostname cert, not example.com's cert."
  warn "  To add per-domain SNI: issue SSL for each domain via CyberPanel"
  warn "  panel → SSL → Manage SSL → Issue SSL. CyberPanel writes the SNI"
  warn "  block to dovecot.conf automatically."
else
  for d in "${SNI_DOMAINS[@]}"; do
    log "  SNI: $d"
  done
  log "  Total: $SNI_COUNT domain(s)"
fi

# -------------------------------------------------------------
# Restart services
# -------------------------------------------------------------

log "Restarting Postfix..."
systemctl restart postfix

log "Restarting Dovecot..."
systemctl restart dovecot

log "Verifying services..."
systemctl is-active --quiet postfix \
  && log "  Postfix: running" \
  || warn "  Postfix: NOT running — check: journalctl -xeu postfix"
systemctl is-active --quiet dovecot \
  && log "  Dovecot: running" \
  || warn "  Dovecot: NOT running — check: journalctl -xeu dovecot"

touch /root/.mail_ssl_setup_last_run 2>/dev/null || true

# -------------------------------------------------------------
# Summary
# -------------------------------------------------------------

echo
echo "============================================================"
echo "  Mail SSL Fix — Summary"
echo "  Completed: $(date -Is)"
echo "============================================================"
echo
echo "  Hostname:             $SERVER_HOSTNAME"
echo "  Hostname cert:        $HOSTNAME_CERT"
echo "  Postfix default cert: /etc/postfix/cert.pem → hostname cert"
echo "  Postfix SNI:          $POSTFIX_SNI_COUNT domain(s) — mail.<domain>:587 uses own cert"
echo "  Dovecot default cert: /etc/dovecot/cert.pem → hostname cert"
echo "  Dovecot SNI:          $SNI_COUNT domain(s) (managed by CyberPanel)"
echo
echo "  WordPress SMTP setting for each hosted site:"
echo "    Host: mail.<domain>   Port: 587   Encryption: STARTTLS"
echo "    (each domain presents its own SSL cert — no mismatch)"
echo
echo "------------------------------------------------------------"
echo "  MANUAL STEPS — required for Outlook/Gmail deliverability"
echo "------------------------------------------------------------"
echo
echo "  1. REVERSE DNS (PTR) — MOST CRITICAL for Outlook"
echo "     Your server IP must resolve back to: $SERVER_HOSTNAME"
echo "     Set in Hetzner Console → Servers → IP Addresses → PTR"
echo "     Without this, Outlook/Hotmail will reject your mail."
echo
echo "  2. Per-domain Dovecot SNI (fixes IMAP/POP3 cert warnings):"
echo "     For each hosted domain, issue SSL via CyberPanel:"
echo "     CyberPanel → SSL → Manage SSL → Issue SSL → <domain>"
echo "     CyberPanel automatically adds the SNI block to Dovecot."
echo "     Then re-run this script to update both Dovecot and Postfix SNI."
echo
echo "  3. SPF — for each domain sending email:"
echo "     DNS TXT @ → v=spf1 ip4:<server-ip> ~all"
echo
echo "  4. DKIM — via CyberPanel:"
echo "     CyberPanel → Email → DKIM Manager → Enable DKIM for domain"
echo "     Copy the TXT record and add to your DNS."
echo
echo "  5. DMARC — for each domain:"
echo "     DNS TXT _dmarc → v=DMARC1; p=quarantine; rua=mailto:postmaster@<domain>"
echo
echo "  6. Test deliverability:"
echo "     https://mail-tester.com       (send a test, aim for 10/10)"
echo "     https://mxtoolbox.com/SuperTool.aspx  (check blacklists, MX, SPF)"
echo
echo "  Log: $LOG_FILE"
echo "============================================================"
echo
log "Done."
