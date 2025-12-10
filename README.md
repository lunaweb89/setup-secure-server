# LunaServers – Secure Setup & Performance Toolkit

This repository provides a complete toolkit to:

- Harden a fresh Ubuntu server (SSH, UFW, Fail2Ban, auto-updates, malware scanning)
- Configure automated Borg backups with a Hetzner Storage Box
- Restore websites quickly in disaster or migration scenarios
- Optimize performance for OpenLiteSpeed + CyberPanel + MariaDB + Redis
- Safely roll back optimizer changes if needed

Compatible with:
- Ubuntu 20.04 / 22.04 / 24.04
- OpenLiteSpeed + CyberPanel
- MariaDB
- Redis
- WordPress / WooCommerce workloads

------------------------------------------------------------
QUICK START (Recommended)
------------------------------------------------------------

Run the main toolkit menu:

bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server/main/server-toolkit.sh)

The menu includes:

1) Full Secure Server Setup
   - Hardens SSH (custom port), UFW, Fail2Ban
   - Enables unattended security updates
   - Installs ClamAV + Maldet
   - Optionally runs:
       * Auto Backup Setup
       * Performance Optimizer

2) Run Auto Backup Setup Only
   - Configures Borg + Hetzner Storage Box
   - Creates daily backup cronjob and helper scripts

3) Run Restore Module Only
   - Restores selected sites from Borg backups
   - Useful for migrations or disaster recovery

4) Run Performance Optimizer Only
   - Auto-detects CPU/RAM
   - Tunes:
       * sysctl, file limits
       * OpenLiteSpeed worker scaling
       * PHP LSAPI for all lsphp versions
       * MariaDB (60% RAM)
       * Redis (15% RAM, capped at 2GB)
   - Leaves ~25% RAM free for OS, cronjobs, backups, spikes
   - Only prompts if unsafe or invalid configs are detected

5) Run Performance Optimizer Rollback
   - Restores the latest backups of:
       * sysctl configs
       * OpenLiteSpeed config
       * PHP LSAPI php.ini files
       * MariaDB optimized config
       * Redis config
   - Reapplies sysctl and restarts services safely

6) View Status
   Shows markers:
       /root/.secure_server_setup_done
       /root/.backup_module_setup_done
       /root/.restore_module_last_run
       /root/.server_optimizer_last_run
       /root/.server_optimizer_rollback_last_run
   Also displays UFW and Fail2Ban status.

------------------------------------------------------------
RECOMMENDED ORDER FOR A NEW SERVER
------------------------------------------------------------

1. Run Full Secure Server Setup
2. Run Backup Module (inside or separately)
3. Run Performance Optimizer
4. Roll back only if needed (rare)

------------------------------------------------------------
DIRECT LINKS TO MODULES
------------------------------------------------------------

Secure Setup:
bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server/main/setup-secure-server.sh)

Performance Optimizer:
bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server/main/server-optimizer.sh)

Rollback:
bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server/main/server-optimizer-rollback.sh)

Backup Module:
bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server/main/setup-backup-module.sh)

Restore Module:
bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server/main/restore-backup.sh)

Toolkit Menu:
bash <(curl -fsSL https://raw.githubusercontent.com/lunaweb89/setup-secure-server/main/server-toolkit.sh)

------------------------------------------------------------
NOTES
------------------------------------------------------------

- All scripts are designed to be safe, idempotent, and production-friendly.
- The optimizer automatically creates timestamped .bak-* backups of every config it touches.
- The rollback module restores the most recent backup and restarts all relevant services.
- Ensure at least one completed Borg backup exists before making large changes.
