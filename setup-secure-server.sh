#!/usr/bin/env bash
#
# setup-secure-server.sh
#
# One-time full-security setup for fresh Ubuntu:
#   - Install required base packages
#   - Enable security-only automatic updates
#   - Configure daily cron job for security updates
#   - Harden SSH (root login allowed, ports 22 + 2808)
#   - Install + configure Fail2Ban (max retry 5)
#   - Configure + enable UFW firewall (SSH, web, CyberPanel, mail, FTP)
#   - Install ClamAV + Maldet (Linux Malware Detect)
#   - Configure weekly malware scan on /home
#
# Run directly from GitHub:
#   bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server.sh/main/setup-secure-server.sh)

set -uo pipefail

# ----------------- Helpers ----------------- #

log() { echo "[+] $*"; }

require_root() {
  if [[ "$EUID" -ne 0 ]]; then
    echo "[-] ERROR: This script must run as root (sudo)." >&2
    exit 1
  fi
}

backup() {
  local f="$1"
  if [[ -f "$f" ]]; then
    # Store backups under /root/config-backups to avoid APT warnings
    local rel="${f#/}"
    local dir="/root/config-backups/$(dirname "$rel")"
    mkdir -p "$dir"
    cp "$f" "$dir/$(basename "$f").bak.$(date +%s)"
    log "Backup saved: $dir/$(basename "$f").bak.*"
  fi
}

get_codename() {
  if command -v lsb_release >/dev/null 2>&1; then
    lsb_release -sc
  else
    # shellcheck disable=SC1091
    . /etc/os-release
    echo "${VERSION_CODENAME:-}"
  fi
}

# Track step results
STEP_UPDATE_BASE="OK"
STEP_AUTO_UPDATES="OK"
STEP_SSH="OK"
STEP_FAIL2BAN="OK"
STEP_UFW="OK"
STEP_CLAMAV="OK"
STEP_MALDET="OK"
STEP_CRON_MALWARE="OK"
STEP_INITIAL_UPGRADE="OK"

require_root
export DEBIAN_FRONTEND=noninteractive

# ----------------- 1. Update + Base Packages ----------------- #

(
  set -e

  log "Updating package lists..."
  apt-get update -qq

  log "Installing required base packages (may already be installed)..."
  apt-get install -y -qq \
    lsb-release \
    ca-certificates \
    openssh-server \
    cron \
    ufw \
    fail2ban \
    unattended-upgrades \
    curl \
    wget \
    tar

  log "Ensuring SSH service is enabled and running..."
  systemctl enable ssh >/dev/null 2>&1 || systemctl enable sshd >/dev/null 2>&1
  systemctl restart ssh >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1

) || STEP_UPDATE_BASE="FAILED"

# ----------------- 2. Automated Security Updates ----------------- #

(
  set -e

  CODENAME="$(get_codename)"
  if [[ -z "$CODENAME" ]]; then
    echo "[-] Unable to detect Ubuntu codename." >&2
    exit 1
  fi
  log "Ubuntu codename detected: $CODENAME"

  UU="/etc/apt/apt.conf.d/50unattended-upgrades"
  AU="/etc/apt/apt.conf.d/20auto-upgrades"
  CRON_UPDATES="/etc/cron.d/auto-security-updates"

  backup "$UU"
  backup "$AU"

  log "Configuring unattended security-only upgrades..."

  cat > "$UU" <<EOF
Unattended-Upgrade::Origins-Pattern {
  "origin=Ubuntu,codename=${CODENAME},label=Ubuntu-Security";
};
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
Unattended-Upgrade::MailOnlyOnError "true";
EOF

  cat > "$AU" <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

  log "Creating cron job for unattended-upgrade..."

  cat > "$CRON_UPDATES" <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

0 4 * * * root unattended-upgrade -v >> /var/log/auto-security-updates.log 2>&1
EOF

  chmod 644 "$CRON_UPDATES"

) || STEP_AUTO_UPDATES="FAILED"

# ----------------- 3. SSH Hardening ----------------- #

(
  set -e

  SSH_HARDEN="/etc/ssh/sshd_config.d/99-hardening.conf"
  mkdir -p /etc/ssh/sshd_config.d
  backup "$SSH_HARDEN"

  log "Applying SSH hardening (root login allowed, ports 22 & 2808, 5 attempts)..."

  cat > "$SSH_HARDEN" <<'EOF'
# SSH Hardening

# Listen on BOTH ports:
Port 22
Port 2808
Protocol 2

# Enable root login with password
PermitRootLogin yes

# Enable password authentication
PasswordAuthentication yes

ChallengeResponseAuthentication no
PermitEmptyPasswords no
UsePAM yes

# Security options
X11Forwarding no
AllowTcpForwarding yes
AllowAgentForwarding yes

LoginGraceTime 30
MaxAuthTries 5
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

  log "Testing SSH configuration..."
  if command -v sshd >/dev/null 2>&1; then
    sshd -t
    systemctl reload ssh >/dev/null 2>&1 || systemctl reload sshd >/dev/null 2>&1
    log "SSHD reloaded with hardened config."
  else
    echo "[-] sshd binary not found; verify openssh-server installation." >&2
    exit 1
  fi

) || STEP_SSH="FAILED"

# ----------------- 4. Fail2Ban ----------------- #

(
  set -e

  FAIL_JAIL="/etc/fail2ban/jail.local"
  backup "$FAIL_JAIL"

  log "Configuring Fail2Ban for SSH (maxretry = 5)..."

  cat > "$FAIL_JAIL" <<'EOF'
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled  = true
port     = 22,2808
logpath  = %(sshd_log)s
backend  = systemd
EOF

  systemctl enable fail2ban >/dev/null 2>&1
  systemctl restart fail2ban >/dev/null 2>&1

) || STEP_FAIL2BAN="FAILED"

# ----------------- 5. UFW Firewall ----------------- #

(
  set -e

  log "Configuring UFW firewall (SSH, web, CyberPanel, mail, FTP)..."

  # --- SSH (primary + fallback) ---
  ufw allow 22/tcp    >/dev/null 2>&1
  ufw limit 22/tcp    >/dev/null 2>&1

  ufw allow 2808/tcp  >/dev/null 2>&1
  ufw limit 2808/tcp  >/dev/null 2>&1

  # --- HTTP / HTTPS ---
  ufw allow 80/tcp    >/dev/null 2>&1
  ufw allow 443/tcp   >/dev/null 2>&1

  # --- CyberPanel / OpenLiteSpeed ---
  ufw allow 8090/tcp  >/dev/null 2>&1   # CyberPanel panel
  ufw allow 7080/tcp  >/dev/null 2>&1   # OpenLiteSpeed WebAdmin

  # --- DNS (if this box does DNS) ---
  ufw allow 53/tcp    >/dev/null 2>&1 || true
  ufw allow 53/udp    >/dev/null 2>&1 || true

  # --- Mail Services ---
  ufw allow 25/tcp    >/dev/null 2>&1 || true   # SMTP
  ufw allow 465/tcp   >/dev/null 2>&1 || true   # SMTPS
  ufw allow 587/tcp   >/dev/null 2>&1 || true   # Submission
  ufw allow 110/tcp   >/dev/null 2>&1 || true   # POP3
  ufw allow 995/tcp   >/dev/null 2>&1 || true   # POP3S
  ufw allow 143/tcp   >/dev/null 2>&1 || true   # IMAP
  ufw allow 993/tcp   >/dev/null 2>&1 || true   # IMAPS

  # --- FTP + Passive FTP ---
  ufw allow 21/tcp           >/dev/null 2>&1 || true
  ufw allow 40110:40210/tcp  >/dev/null 2>&1 || true

  # --- Default Policies ---
  ufw default deny incoming  >/dev/null 2>&1
  ufw default allow outgoing >/dev/null 2>&1

  log "Enabling UFW firewall..."
  ufw --force enable >/dev/null 2>&1

) || STEP_UFW="FAILED"

# ----------------- 6. ClamAV ----------------- #

(
  set -e

  log "Installing ClamAV antivirus..."
  apt-get install -y -qq clamav clamav-daemon

  log "Updating ClamAV virus database (freshclam)..."
  systemctl stop clamav-freshclam >/dev/null 2>&1 || true
  freshclam
  systemctl enable clamav-freshclam >/dev/null 2>&1
  systemctl restart clamav-freshclam >/dev/null 2>&1

  systemctl enable clamav-daemon >/dev/null 2>&1
  systemctl restart clamav-daemon >/dev/null 2>&1

) || STEP_CLAMAV="FAILED"

# ----------------- 7. Maldet (Linux Malware Detect) ----------------- #

(
  set -e

  log "Installing Linux Malware Detect (Maldet)..."

  TMP_DIR="/tmp/maldet-install"
  mkdir -p "$TMP_DIR"

  MALDET_URL="https://www.rfxn.com/downloads/maldetect-current.tar.gz"
  MALDET_TGZ="${TMP_DIR}/maldetect-current.tar.gz"

  wget -q -O "$MALDET_TGZ" "$MALDET_URL"
  tar -xzf "$MALDET_TGZ" -C "$TMP_DIR"

  MALDET_SRC_DIR="$(find "$TMP_DIR" -maxdepth 1 -type d -name 'maldetect-*' | head -n1)"
  if [[ -z "$MALDET_SRC_DIR" ]]; then
    echo "[-] Could not locate Maldet source directory after extraction." >&2
    exit 1
  fi

  ( cd "$MALDET_SRC_DIR" && bash install.sh )

  MALDET_CONF="/usr/local/maldetect/conf.maldet"
  if [[ -f "$MALDET_CONF" ]]; then
    backup "$MALDET_CONF"
    sed -i 's/^scan_clamscan=.*/scan_clamscan="1"/' "$MALDET_CONF"
    sed -i 's/^scan_clamd=.*/scan_clamd="1"/' "$MALDET_CONF"
    log "Configured Maldet to use ClamAV engine."
  else
    echo "[-] Maldet config not found at $MALDET_CONF" >&2
    exit 1
  fi

) || STEP_MALDET="FAILED"

# ----------------- 8. Weekly Malware Scan Cron ----------------- #

(
  set -e

  log "Creating weekly malware scan cron job (/home)..."

  CRON_MALWARE="/etc/cron.d/weekly-malware-scan"

  cat > "$CRON_MALWARE" <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Weekly malware scan every Sunday at 03:30
# Scans all sites/data under /home (CyberPanel layout)
30 3 * * 0 root /usr/local/maldetect/maldet -b -r /home 1 >> /var/log/weekly-malware-scan.log 2>&1
EOF

  chmod 644 "$CRON_MALWARE"

) || STEP_CRON_MALWARE="FAILED"

# ----------------- 9. Initial Security Patch Run ----------------- #

(
  set -e

  log "Running initial security upgrade (unattended-upgrade)..."
  unattended-upgrade -v >> /var/log/auto-security-updates.log 2>&1

) || STEP_INITIAL_UPGRADE="FAILED"

# ----------------- Summary ----------------- #

echo
echo "========================================================"
echo " Secure Server Setup Summary"
echo "========================================================"
printf "%-30s : %s\n" "update_base_packages"      "$STEP_UPDATE_BASE"
printf "%-30s : %s\n" "auto_security_updates"     "$STEP_AUTO_UPDATES"
printf "%-30s : %s\n" "ssh_hardening"             "$STEP_SSH"
printf "%-30s : %s\n" "fail2ban_config"           "$STEP_FAIL2BAN"
printf "%-30s : %s\n" "ufw_firewall"              "$STEP_UFW"
printf "%-30s : %s\n" "clamav_install"            "$STEP_CLAMAV"
printf "%-30s : %s\n" "maldet_install"            "$STEP_MALDET"
printf "%-30s : %s\n" "weekly_malware_cron"       "$STEP_CRON_MALWARE"
printf "%-30s : %s\n" "initial_unattended_upgrade" "$STEP_INITIAL_UPGRADE"
echo "========================================================"
echo "[INFO] Any step marked 'FAILED' should be investigated."
echo "[INFO] Check /var/log/auto-security-updates.log and /var/log/weekly-malware-scan.log for details."
echo

exit 0
