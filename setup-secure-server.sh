#!/usr/bin/env bash
#
# setup-secure-server.sh
#
# One-time full-security setup for fresh Ubuntu:
#   - Install all required packages (safe for fresh server)
#   - Enable security-only automatic updates
#   - Configure daily cron update job
#   - Harden SSH configuration
#   - Install + configure fail2ban
#   - Configure + enable UFW firewall
#
# Designed to be executed directly from GitHub:
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/USER/REPO/main/setup-secure-server.sh)
#
# Safe to run once and forget.

set -euo pipefail

# ----------------- Helpers ----------------- #

log() { echo "[+] $*"; }

require_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo "[-] ERROR: This script must run as root (sudo)."
        exit 1
    fi
}

backup() {
    local f="$1"
    [[ -f "$f" ]] && cp "$f" "$f.bak.$(date +%s)" && log "Backup saved: $f.bak.*"
}

get_codename() {
    command -v lsb_release >/dev/null 2>&1 && lsb_release -sc || (
        source /etc/os-release
        echo "${VERSION_CODENAME:-}"
    )
}

# ----------------- Start ----------------- #

require_root
export DEBIAN_FRONTEND=noninteractive

log "Updating package lists..."
apt-get update -qq

log "Installing required packages..."
apt-get install -y -qq \
    lsb-release \
    ca-certificates \
    openssh-server \
    cron \
    ufw \
    fail2ban \
    unattended-upgrades \
    curl

log "Ensuring SSH service is running..."
systemctl enable ssh >/dev/null 2>&1 || systemctl enable sshd >/dev/null 2>&1
systemctl restart ssh >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1

CODENAME="$(get_codename)"
if [[ -z "$CODENAME" ]]; then
    echo "[-] Unable to detect Ubuntu codename."
    exit 1
fi
log "Ubuntu codename detected: $CODENAME"

# ----------------- Automated Security Updates ----------------- #

UU="/etc/apt/apt.conf.d/50unattended-upgrades"
AU="/etc/apt/apt.conf.d/20auto-upgrades"
CRON="/etc/cron.d/auto-security-updates"

backup "$UU"
backup "$AU"

log "Configuring unattended security upgrades..."

cat > "$UU" <<EOF
Unattended-Upgrade::Origins-Pattern {
    "origin=Ubuntu,codename=${CODENAME},label=Ubuntu-Security";
};
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
Unattended-Upgrade::MailOnlyOnError "true";
EOF

cat > "$AU" <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

log "Creating cron job for unattended-upgrade..."

cat > "$CRON" <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

0 4 * * * root unattended-upgrade -v >> /var/log/auto-security-updates.log 2>&1
EOF

chmod 644 "$CRON"

# ----------------- SSH Hardening ----------------- #

SSH_HARDEN="/etc/ssh/sshd_config.d/99-hardening.conf"
mkdir -p /etc/ssh/sshd_config.d
backup "$SSH_HARDEN"

log "Applying SSH hardening..."

cat > "$SSH_HARDEN" <<'EOF'
# SSH Hardening
Port 22
Protocol 2

PermitRootLogin prohibit-password
PasswordAuthentication yes
ChallengeResponseAuthentication no
PermitEmptyPasswords no
UsePAM yes

X11Forwarding no
AllowTcpForwarding yes
AllowAgentForwarding yes

LoginGraceTime 30
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

log "Testing SSH configuration..."
if sshd -t; then
    systemctl reload ssh >/dev/null 2>&1 || systemctl reload sshd >/dev/null 2>&1
    log "SSHD reloaded with hardened config."
else
    echo "[-] SSH config test failed — not reloading."
fi

# ----------------- Fail2Ban ----------------- #

FAIL_JAIL="/etc/fail2ban/jail.local"
backup "$FAIL_JAIL"

log "Configuring fail2ban..."

cat > "$FAIL_JAIL" <<'EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = systemd
EOF

systemctl enable fail2ban >/dev/null 2>&1
systemctl restart fail2ban

# ----------------- UFW Firewall ----------------- #

log "Configuring UFW firewall..."

ufw allow OpenSSH >/dev/null 2>&1 || ufw allow 22/tcp
ufw limit OpenSSH >/dev/null 2>&1 || true
ufw allow 80/tcp >/dev/null
ufw allow 443/tcp >/dev/null

ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null

log "Enabling firewall..."
ufw --force enable >/dev/null

# ----------------- Initial Security Patch Run ----------------- #

log "Running initial security upgrade..."
unattended-upgrade -v >> /var/log/auto-security-updates.log 2>&1 || true

# ----------------- DONE ----------------- #

log "SECURE SERVER SETUP COMPLETE!"
log ""
log "Installed & enabled:"
log " - Security-only auto-updates"
log " - SSH hardening"
log " - Fail2Ban protection"
log " - UFW firewall"
log ""
log "Log file: /var/log/auto-security-updates.log"
log "Optional: disable SSH passwords after adding your SSH key:"
log "   nano /etc/ssh/sshd_config.d/99-hardening.conf"
log "   PasswordAuthentication no"
log ""
log "Safe to reboot anytime."
