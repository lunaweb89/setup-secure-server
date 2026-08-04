#!/usr/bin/env bash
#
# setup-mail-ssl.sh
#
# Fixes SMTP/SSL mismatch on CyberPanel mail servers.
#
# Root cause:
#   CyberPanel manages Postfix and Dovecot cert via symlinks:
#     /etc/postfix/cert.pem  → last domain cert issued via CyberPanel
#     /etc/dovecot/cert.pem  → same
#   After issuing SSL for multiple sites the symlinks point to
#   the LAST domain issued, not the server hostname. Postfix then
#   presents that domain's cert during SMTP TLS, causing Outlook/
#   Hotmail to reject mail with a "certificate mismatch" error.
#
# What this script does:
#   1. Redirects /etc/postfix/cert.pem and /etc/dovecot/cert.pem
#      to the server HOSTNAME cert (the correct TLS identity for SMTP)
#   2. Applies modern TLS settings to Postfix for Outlook compatibility
#   3. Reports how many per-domain Dovecot SNI entries CyberPanel has
#      already configured in /etc/dovecot/dovecot.conf
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
log "  smtpd_tls_cert_file → /etc/postfix/cert.pem → $SERVER_HOSTNAME cert"
log "  virtual_transport    → $(postconf -h virtual_transport 2>/dev/null || echo '(not set)') [unchanged]"

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
echo "  Hostname:          $SERVER_HOSTNAME"
echo "  Hostname cert:     $HOSTNAME_CERT"
echo "  Postfix TLS:       /etc/postfix/cert.pem → hostname cert"
echo "  Dovecot default:   /etc/dovecot/cert.pem → hostname cert"
echo "  Dovecot SNI:       $SNI_COUNT domain(s) (managed by CyberPanel)"
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
echo "  2. Per-domain Dovecot SNI (fixes client cert warnings):"
echo "     For each hosted domain, issue SSL via CyberPanel:"
echo "     CyberPanel → SSL → Manage SSL → Issue SSL → <domain>"
echo "     CyberPanel automatically adds the SNI block to Dovecot."
echo "     Then re-run this script to verify the count."
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
