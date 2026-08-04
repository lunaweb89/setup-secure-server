# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.2.0] – 2026-08-04

### Added

**`ssl-auto-issue.sh`** (new script)
- Auto-issues Let's Encrypt SSL certificates for the server hostname and every website registered in CyberPanel
- Verifies DNS points to this server (`dig +short A`) before each attempt — prevents Let's Encrypt failures for domains not yet pointed here
- Installs a daily cron job (`/etc/cron.d/daily-ssl-renew`) at 02:00 to automatically renew expiring certs going forward
- CyberPanel's `issueSSL` mechanism is idempotent: skips domains with valid, non-expiring certs
- One domain failing does not abort the rest
- Logs all output to `/var/log/ssl-auto-issue.log`
- Prints a summary: issued OK / skipped (DNS mismatch) / failed
- Safe to re-run at any time

**`server-toolkit.sh`**
- New option **7 — SSL Auto-Issue & Renewal Setup** runs `ssl-auto-issue.sh`
- Exit shifted from option 7 to **option 8**

---

## [1.1.0] – 2026-08-04

### Added

**`setup-secure-server.sh`**
- **Kernel security hardening** — creates `/etc/sysctl.d/98-security-hardening.conf` with:
  - IP spoofing protection (`rp_filter`)
  - ICMP redirect blocking (prevents routing/MITM manipulation)
  - Broadcast ping / Smurf attack protection
  - SYN flood protection (`tcp_syncookies`)
  - Kernel log and symbol address restriction (`dmesg_restrict`, `kptr_restrict`)
  - ptrace scope restriction (`yama.ptrace_scope=1`)
  - Numbered `98` so the optimizer's `99-ols-optimized.conf` takes precedence on any overlapping keys
- **Fail2Ban HTTP jails** — three new jails in addition to `[sshd]`:
  - `[wordpress-bruteforce]` — 10 failed POSTs to `wp-login.php` in 10 min → 2h ban; watches OLS access log; does not affect normal shoppers
  - `[cyberpanel-bruteforce]` — 10 failed CyberPanel panel logins in 10 min → 2h ban; watches `/usr/local/CyberCP/logs/main.log`
  - `[recidive]` — IPs caught by any jail 5+ times within a day → 1-week full ban
  - Custom filter files written to `/etc/fail2ban/filter.d/`
- **Swap file setup** — idempotent, skips if swap already active:
  - 2 GB for servers with < 16 GB RAM; 4 GB for larger servers
  - Persisted in `/etc/fstab`; safe on dedicated servers since `vm.swappiness=10` (set by optimizer) keeps swap as a last-resort OOM safety net

### Fixed

**`server-toolkit.sh`**
- `show_status()` (option 6) now actually performs what the menu promised:
  - Checks presence of all three cron files (`daily-borg-backup`, `auto-security-updates`, `weekly-malware-scan`)
  - Runs a live Borg connectivity test via `borg-passphrase-test.sh` and reports the repo URL

**`server-optimizer.sh`**
- `/etc/security/limits.conf` is now backed up (`limits.conf.bak-TIMESTAMP`) before overwriting — previously no backup was created, making rollback impossible
- MariaDB config now auto-detects version and writes `innodb_redo_log_capacity` on MariaDB 10.9+ instead of the deprecated `innodb_log_file_size`
- Replaced deprecated `egrep` with `grep -E` in the health report

**`server-optimizer-rollback.sh`**
- `/etc/security/limits.conf` is now actually restored from backup (previously only printed a warning)
- PHP ini rollback now uses the same `find /usr/local/lsws -type f -name php.ini` pattern as the optimizer, ensuring all `lsphp` versions are covered

**`setup-backup-module.sh`**
- Daily Borg backup cron moved from `08:30` to `03:00` (off-hours) to reduce I/O impact on live sites
- Added `MAILTO=root` to the cron file so backup failures are emailed to root

---

## [1.0.0] – Initial release

- `setup-secure-server.sh` — full server hardening: SSH port, UFW, Fail2Ban (SSH), auto security updates, ClamAV, Maldet, Ubuntu Pro / Livepatch support
- `setup-backup-module.sh` — Borg + Hetzner Storage Box daily backups with MySQL dumps, passphrase management, and SSH key setup
- `restore-backup.sh` — full or per-site WordPress restore from Borg archives
- `server-optimizer.sh` — dynamic CPU/RAM-based tuning for sysctl, OLS, PHP LSAPI, MariaDB, and Redis
- `server-optimizer-rollback.sh` — restores timestamped config backups and restarts services
- `server-toolkit.sh` — interactive menu wrapper for all modules
