#!/usr/bin/env bash
#
# setup-mail-ssl.sh
#
# Fixes SMTP/SSL mismatch on CyberPanel mail servers:
#   - Configures Postfix TLS to use the server hostname SSL cert
#   - Configures Dovecot SNI so each hosted domain presents its own
#     SSL cert for IMAP/POP3 connections (fixes Outlook/Gmail cert warnings)
#   - Ensures Dovecot LMTP delivery socket is active for Postfix
#   - Enables LMTP in Dovecot protocols if not already set
#
# Safe for CyberPanel:
#   - Uses `postconf -e` (non-destructive, CyberPanel-compatible)
#   - Writes SNI/SSL overrides to /etc/dovecot/conf.d/99-* drop-in files,
#     not CyberPanel-managed files
#   - Safe to re-run: regenerates SNI map each time (picks up new certs)
#
# Run AFTER ssl-auto-issue.sh so all domain certs already exist.
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
echo "  LunaServers – Mail SSL Fix"
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

if ! command -v postfix >/dev/null 2>&1 && ! command -v postconf >/dev/null 2>&1; then
  err "Postfix is not installed. Is CyberPanel installed on this server?"
  exit 1
fi

if ! command -v dovecot >/dev/null 2>&1; then
  err "Dovecot is not installed. Is CyberPanel installed on this server?"
  exit 1
fi

# -------------------------------------------------------------
# Find hostname SSL cert
# CyberPanel (acme.sh) and certbot both use /etc/letsencrypt/live/
# -------------------------------------------------------------

HOSTNAME_CERT=""
HOSTNAME_KEY=""

LE_CERT="/etc/letsencrypt/live/${SERVER_HOSTNAME}/fullchain.pem"
LE_KEY="/etc/letsencrypt/live/${SERVER_HOSTNAME}/privkey.pem"

if [[ -f "$LE_CERT" && -f "$LE_KEY" ]]; then
  HOSTNAME_CERT="$LE_CERT"
  HOSTNAME_KEY="$LE_KEY"
  log "Found hostname cert: $HOSTNAME_CERT"
else
  warn "No SSL cert found for $SERVER_HOSTNAME at $LE_CERT"
  warn "Run ssl-auto-issue.sh first to issue certs, then re-run this script."
  warn "Using self-signed snakeoil cert as fallback (mail will work but"
  warn "clients will see a certificate warning until a real cert is issued)."
  apt-get install -y -qq ssl-cert >/dev/null 2>&1 || true
  HOSTNAME_CERT="/etc/ssl/certs/ssl-cert-snakeoil.pem"
  HOSTNAME_KEY="/etc/ssl/private/ssl-cert-snakeoil.key"
fi

# -------------------------------------------------------------
# Configure Postfix TLS
# postconf -e is safe with CyberPanel — it edits main.cf directly
# -------------------------------------------------------------

log "Configuring Postfix TLS..."

postconf -e "myhostname = ${SERVER_HOSTNAME}"

# TLS on inbound SMTP (smtpd = server mode, used by receiving clients)
postconf -e "smtpd_tls_security_level = may"
postconf -e "smtpd_tls_auth_only = yes"
postconf -e "smtpd_tls_cert_file = ${HOSTNAME_CERT}"
postconf -e "smtpd_tls_key_file = ${HOSTNAME_KEY}"
postconf -e "smtpd_tls_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1"
postconf -e "smtpd_tls_mandatory_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1"
postconf -e "smtpd_tls_mandatory_ciphers = high"
postconf -e "smtpd_tls_loglevel = 1"

# TLS on outbound SMTP (smtp = client mode, used when sending to other servers)
postconf -e "smtp_tls_security_level = may"
postconf -e "smtp_tls_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1"
postconf -e "smtp_tls_loglevel = 1"

# Route incoming mail through Dovecot LMTP for delivery to mailboxes
postconf -e "virtual_transport = lmtp:unix:private/dovecot-lmtp"

log "Postfix TLS configured."

# -------------------------------------------------------------
# Ensure LMTP is enabled in Dovecot protocols
# CyberPanel usually enables this, but verify
# -------------------------------------------------------------

DOVECOT_MAIN_CONF="/etc/dovecot/dovecot.conf"
if [[ -f "$DOVECOT_MAIN_CONF" ]]; then
  if grep -q "^protocols" "$DOVECOT_MAIN_CONF"; then
    if ! grep "^protocols" "$DOVECOT_MAIN_CONF" | grep -q "lmtp"; then
      log "Adding lmtp to Dovecot protocols..."
      sed -i 's/^protocols = .*/& lmtp/' "$DOVECOT_MAIN_CONF"
    else
      log "LMTP already in Dovecot protocols."
    fi
  else
    log "Appending protocols line to dovecot.conf..."
    echo "protocols = imap pop3 lmtp" >> "$DOVECOT_MAIN_CONF"
  fi
fi

# -------------------------------------------------------------
# Ensure Dovecot LMTP unix socket listener exists for Postfix
# Write to a drop-in file; does not touch CyberPanel's 10-master.conf
# -------------------------------------------------------------

DOVECOT_LMTP_CONF="/etc/dovecot/conf.d/99-lmtp-postfix.conf"

if grep -rq "dovecot-lmtp" /etc/dovecot/conf.d/ 2>/dev/null || \
   grep -q "dovecot-lmtp" /etc/dovecot/dovecot.conf 2>/dev/null; then
  log "Dovecot LMTP listener already configured."
else
  log "Adding Dovecot LMTP listener for Postfix..."
  cat > "$DOVECOT_LMTP_CONF" << 'LMTPEOF'
# Postfix → Dovecot LMTP delivery socket
# Written by setup-mail-ssl.sh; safe to re-run
service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}
LMTPEOF
  chmod 640 "$DOVECOT_LMTP_CONF"
  log "LMTP listener written to $DOVECOT_LMTP_CONF"
fi

# -------------------------------------------------------------
# Write Dovecot SNI override (drop-in, loaded last)
# Maps each domain to its own SSL cert for IMAP/POP3 connections
# This is what fixes the Outlook "certificate mismatch" error
# -------------------------------------------------------------

log "Generating Dovecot SNI mapping..."

DOVECOT_SNI_CONF="/etc/dovecot/conf.d/99-sni-override.conf"

# Build SNI config header
cat > "$DOVECOT_SNI_CONF" << DOVEEOF
# Auto-generated by setup-mail-ssl.sh — $(date -Is)
# Re-run setup-mail-ssl.sh after issuing certs for new domains.

# Default SSL cert: server hostname cert
ssl = required
ssl_cert = <${HOSTNAME_CERT}
ssl_key  = <${HOSTNAME_KEY}
ssl_min_protocol = TLSv1.2
ssl_cipher_list = HIGH:!aNULL:!MD5
ssl_prefer_server_ciphers = yes

DOVEEOF

# Add DH params if the file exists (Dovecot 2.2 and some 2.3 builds need this)
if [[ -f /usr/share/dovecot/dh.pem ]]; then
  echo "ssl_dh = </usr/share/dovecot/dh.pem" >> "$DOVECOT_SNI_CONF"
  echo >> "$DOVECOT_SNI_CONF"
fi

cat >> "$DOVECOT_SNI_CONF" << 'SNIHEADER'
# Per-domain SNI: when a mail client connects using mail.example.com,
# Dovecot presents example.com's cert instead of the hostname cert.
# This eliminates the "certificate mismatch" warning in Outlook/Thunderbird.
SNIHEADER

CERT_COUNT=0
SKIPPED=0

for domain_path in /etc/letsencrypt/live/*/; do
  domain=$(basename "$domain_path")
  [[ "$domain" == "README" ]] && continue

  cert="${domain_path}fullchain.pem"
  key="${domain_path}privkey.pem"

  if [[ ! -f "$cert" || ! -f "$key" ]]; then
    SKIPPED=$(( SKIPPED + 1 ))
    continue
  fi

  cat >> "$DOVECOT_SNI_CONF" << SNIEOF

local_name ${domain} {
  ssl_cert = <${cert}
  ssl_key  = <${key}
}
SNIEOF

  CERT_COUNT=$(( CERT_COUNT + 1 ))
  log "  SNI mapped: $domain"
done

chown root:root "$DOVECOT_SNI_CONF"
chmod 640 "$DOVECOT_SNI_CONF"

log "Dovecot SNI: $CERT_COUNT domain(s) mapped, $SKIPPED skipped (cert files incomplete)."

# -------------------------------------------------------------
# Restart services
# -------------------------------------------------------------

log "Restarting Postfix..."
systemctl restart postfix

log "Restarting Dovecot..."
systemctl restart dovecot

# -------------------------------------------------------------
# Verify services are up
# -------------------------------------------------------------

log "Verifying services..."
SERVICES_OK=true

if systemctl is-active --quiet postfix; then
  log "  Postfix: running"
else
  warn "  Postfix: NOT running — check: journalctl -xeu postfix"
  SERVICES_OK=false
fi

if systemctl is-active --quiet dovecot; then
  log "  Dovecot: running"
else
  warn "  Dovecot: NOT running — check: journalctl -xeu dovecot"
  SERVICES_OK=false
fi

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
echo "  Hostname cert:     ${HOSTNAME_CERT}"
echo "  SNI domains mapped: ${CERT_COUNT}"
echo "  Postfix/Dovecot:   $(${SERVICES_OK} && echo 'both running' || echo 'CHECK LOGS')"
echo
echo "------------------------------------------------------------"
echo "  MANUAL STEPS — required to fix Outlook rejection"
echo "------------------------------------------------------------"
echo
echo "  1. REVERSE DNS (PTR record) — MOST IMPORTANT"
echo "     Your server IP must reverse-resolve to: $SERVER_HOSTNAME"
echo "     Set this in Hetzner Console → Networking → IP → PTR record"
echo "     Without this, Outlook/Hotmail WILL reject your mail."
echo
echo "  2. SPF record — for each domain sending email:"
echo "     Type: TXT   Name: @   Value: v=spf1 ip4:<your-server-ip> ~all"
echo
echo "  3. DKIM — enable per domain in CyberPanel:"
echo "     CyberPanel → Email → DKIM Manager → select domain → Add DKIM"
echo "     Then add the TXT record shown to your domain's DNS."
echo
echo "  4. DMARC — for each domain:"
echo "     Type: TXT   Name: _dmarc   Value: v=DMARC1; p=quarantine; rua=mailto:postmaster@<domain>"
echo
echo "  5. TEST your mail reputation:"
echo "     https://mail-tester.com  (send a test email, aim for 10/10)"
echo "     https://mxtoolbox.com/SuperTool.aspx (check blacklists, MX, SPF)"
echo
echo "  6. RE-RUN this script after issuing SSL for new domains"
echo "     (updates the Dovecot SNI map automatically)"
echo
echo "  Log: $LOG_FILE"
echo "============================================================"
echo
log "Done."
