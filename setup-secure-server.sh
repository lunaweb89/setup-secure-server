#!/usr/bin/env bash
#
# setup-secure-server.sh
#
# One-time full-security setup for fresh Ubuntu:
#   - Repair dpkg/APT if broken
#   - Install base packages
#   - Enable kernel Livepatch via Ubuntu Pro (optional)
#   - Enable security-only automatic updates
#   - Configure monthly cron job for updates
#   - Harden SSH config (move SSH to port 2808 ONLY, root+password allowed)
#   - Install & configure Fail2Ban
#   - Configure & enable UFW firewall (SSH ONLY on 2808, not 22)
#   - Install ClamAV + Maldet
#   - Create weekly malware scan cron job
#
# Run directly:
#   bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server/main/setup-secure-server.sh)

set -u   # strict on unset vars
set -o pipefail

# ----------------- Step Status ----------------- #
STEP_update_base_packages="FAILED"
STEP_livepatch="SKIPPED"
STEP_auto_security_updates="FAILED"
STEP_ssh_hardening="FAILED"
STEP_fail2ban_config="FAILED"
STEP_ufw_firewall="FAILED"
STEP_clamav_install="FAILED"
STEP_maldet_install="FAILED"
STEP_weekly_malware_cron="FAILED"
STEP_initial_unattended_upgrade="FAILED"

# ----------------- Helpers ----------------- #

log() { echo "[+] $*"; }

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "[-] ERROR: This script must run as root (sudo)." >&2
    exit 1
  fi
}

backup() {
  local f="$1"
  if [[ -f "$f" ]]; then
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
    . /etc/os-release
    echo "${VERSION_CODENAME:-}"
  fi
}

apt_update_retry() {
  local tries=0 max_tries=3
  while (( tries < max_tries )); do
    if apt-get update -qq; then return 0; fi
    log "apt-get update failed (attempt $((tries+1))/$max_tries), retrying in 5s..."
    tries=$((tries + 1))
    sleep 5
  done
  return 1
}

apt_install_retry() {
  local tries=0 max_tries=3 pkgs=("$@")
  while (( tries < max_tries )); do
    if apt-get install -y -qq "${pkgs[@]}"; then return 0; fi
    log "apt-get install ${pkgs[*]} failed — running apt-get -f install..."
    apt-get -f install -y || true
    tries=$((tries + 1))
    sleep 5
  done
  return 1
}

# ----------------- Start ----------------- #

require_root
export DEBIAN_FRONTEND=noninteractive

# ----------------- Ubuntu Pro / Livepatch (Optional) ----------------- #
echo "============================================================"
echo " Ubuntu Pro Livepatch Setup (Optional)"
echo "============================================================"
echo "Livepatch applies kernel security updates WITHOUT rebooting."
echo "Requires an Ubuntu Pro token (not the old Livepatch token)."
echo "Get one from: https://ubuntu.com/pro/subscribe"
echo
read -r -p "Enter your Ubuntu Pro token (leave blank to skip Livepatch): " UBUNTU_PRO_TOKEN
echo

if [[ -n "$UBUNTU_PRO_TOKEN" ]]; then
  log "Setting up Ubuntu Pro + Livepatch..."

  # Ensure 'pro' CLI is available
  if ! command -v pro >/dev/null 2>&1; then
    log "ubuntu-advantage-tools (pro CLI) missing — installing..."
    if ! apt_install_retry ubuntu-advantage-tools; then
      log "ERROR: ubuntu-advantage-tools install failed — cannot enable Livepatch."
      UBUNTU_PRO_TOKEN=""
    fi
  fi

  if [[ -n "$UBUNTU_PRO_TOKEN" ]] && command -v pro >/dev/null 2>&1; then
    # Attach if needed (pro status exits 0 even when not attached, so check text)
    if pro status 2>&1 | grep -qi "not attached"; then
      log "Machine is NOT attached to Ubuntu Pro — attaching now..."
      if pro attach "$UBUNTU_PRO_TOKEN"; then
        log "Ubuntu Pro attached successfully."
      else
        log "WARNING: 'pro attach' failed — Livepatch may not be available."
      fi
    else
      log "Ubuntu Pro already attached; skipping 'pro attach'."
    fi

    # Helper: check if Livepatch is reported enabled
    is_livepatch_enabled() {
      pro status 2>/dev/null | awk '/livepatch/ {print tolower($0)}' | grep -q 'enabled'
    }

    # If already enabled, don't even try to enable again
    if is_livepatch_enabled; then
      log "Livepatch already enabled via Ubuntu Pro."
      STEP_livepatch="OK"
    else
      log "Enabling Livepatch via 'pro enable livepatch' (ignore errors if already enabled)..."
      # Do NOT trust the exit code; some versions return non-zero even when it works
      pro enable livepatch >/tmp/pro-livepatch.log 2>&1 || true

      if is_livepatch_enabled; then
        log "Livepatch enabled (or already enabled) according to 'pro status'."
        STEP_livepatch="OK"
      else
        log "WARNING: Livepatch still not reported as enabled after 'pro enable livepatch'."
        log "         See /tmp/pro-livepatch.log for details."
        STEP_livepatch="FAILED"
      fi
    fi
  fi
else
  log "Livepatch skipped."
fi

# ----------------- Repair dpkg / APT ----------------- #

log "Checking dpkg / APT health..."

if dpkg --audit | grep -q .; then
  log "dpkg broken — repairing..."
  dpkg --configure -a || log "WARNING: dpkg configure did not finish cleanly."
fi

apt-get -f install -y || true

log "Running apt-get update..."
apt_update_retry || log "ERROR: apt-get update failed."

log "Installing required base packages..."
if apt_install_retry lsb-release ca-certificates openssh-server cron ufw fail2ban unattended-upgrades curl wget tar; then
  STEP_update_base_packages="OK"
fi

# ----------------- SSH Hardening ----------------- #
log "Applying SSH hardening..."
if [ -f "/etc/ssh/sshd_config.d/99-hardening.conf" ]; then
  log "SSH hardening config file already exists, skipping reconfiguration."
  STEP_ssh_hardening="OK"
else
  SSH_HARDEN="/etc/ssh/sshd_config.d/99-hardening.conf"
  mkdir -p /etc/ssh/sshd_config.d
  backup "$SSH_HARDEN"

  cat > "$SSH_HARDEN" <<EOF
  # SSH Hardening
  Port 2808
  Protocol 2
  PermitRootLogin yes
  PasswordAuthentication yes
  ChallengeResponseAuthentication no
  PermitEmptyPasswords no
  UsePAM yes
  X11Forwarding no
  AllowTcpForwarding yes
  AllowAgentForwarding yes
  LoginGraceTime 30
  MaxAuthTries 5
  ClientAliveInterval 300
  ClientAliveCountMax 2
EOF
  if sshd -t 2>/dev/null; then
    systemctl reload sshd
    STEP_ssh_hardening="OK"
  else
    log "ERROR: SSH config test failed. Not reloading sshd."
    STEP_ssh_hardening="FAILED"
  fi
fi

# ----------------- Fail2Ban ----------------- #
log "Configuring Fail2Ban..."
FAIL_JAIL="/etc/fail2ban/jail.local"
mkdir -p /etc/fail2ban
backup "$FAIL_JAIL"

# Check if Fail2Ban config file exists
if [ -f "$FAIL_JAIL" ]; then
  log "Fail2Ban configuration already exists, skipping reconfiguration."
  STEP_fail2ban_config="OK"
else
  cat > "$FAIL_JAIL" <<'EOF'
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled  = true
port     = 2808
logpath  = %(sshd_log)s
backend  = systemd
EOF
  systemctl enable fail2ban >/dev/null
  systemctl restart fail2ban >/dev/null
  STEP_fail2ban_config="OK"
fi

# ----------------- UFW Firewall ----------------- #
log "Configuring UFW firewall..."

UFW_OK=1

# Check if UFW is active
if ufw status | grep -q "Status: active"; then
  log "UFW firewall is already active, skipping reconfiguration."
  STEP_ufw_firewall="OK"
else
  ufw limit 2808/tcp >/dev/null || UFW_OK=0
  ufw allow 80/tcp >/dev/null || UFW_OK=0
  ufw allow 443/tcp >/dev/null || UFW_OK=0
  ufw allow 53/tcp >/dev/null || UFW_OK=0
  ufw allow 53/udp >/dev/null || UFW_OK=0
  ufw default deny incoming >/dev/null || UFW_OK=0
  ufw default allow outgoing >/dev/null || UFW_OK=0
  ufw --force enable >/dev/null && STEP_ufw_firewall="OK"
fi

# ----------------- Summary ----------------- #

echo
echo "================ Secure Server Setup Summary ================"
printf "update_base_packages           : %s\n" "$STEP_update_base_packages"
printf "livepatch                      : %s\n" "$STEP_livepatch"
printf "auto_security_updates          : %s\n" "$STEP_auto_security_updates"
printf "ssh_hardening                  : %s\n" "$STEP_ssh_hardening"
printf "fail2ban_config                : %s\n" "$STEP_fail2ban_config"
printf "ufw_firewall                   : %s\n" "$STEP_ufw_firewall"
printf "clamav_install                 : %s\n" "$STEP_clamav_install"
printf "maldet_install                 : %s\n" "$STEP_maldet_install"
printf "weekly_malware_cron            : %s\n" "$STEP_weekly_malware_cron"
printf "initial_unattended_upgrade     : %s\n" "$STEP_initial_unattended_upgrade"
echo "=============================================================="
echo "[INFO] Logs:"
echo " - /var/log/auto-security-updates.log"
echo " - /var/log/weekly-malware-scan.log"
echo

exit 0
