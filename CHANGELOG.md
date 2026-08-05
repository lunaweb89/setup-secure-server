# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.4.1] – 2026-08-05

### Fixed

**`wp-auto-update.sh`**
- Added `--safe` / safe mode (default ON): core updates limited to minor/security releases only (`wp core update --minor`); plugins and themes skip any update where the major version number changes (e.g. WooCommerce 8→9). Major updates are flagged in the log for manual review. Pass `--all` to include major updates.
- Weekly cron runs in safe mode by default (no `--all` flag)

**`db-maintenance.sh`**
- Eliminated duplicate `mysqlcheck` call (was running twice per database)
- Suppressed normal InnoDB output: "note: Table does not support optimize, doing recreate + analyze instead" and "status: OK" are filtered — only actual errors and warnings are shown
- Log output is now concise enough for unattended weekly cron use

---

## [1.4.0] – 2026-08-05

### Added

**`check-mail-health.sh`** (new script — option 9)
- Checks email deliverability for every CyberPanel domain via pure DNS (`dig`) queries — no external APIs
- PTR / reverse DNS match against server hostname
- IP blacklist check against 5 major DNSBLs: Spamhaus zen, Barracuda, SpamCop, SORBS, CBL
- Per-domain: MX, SPF (`v=spf1`), DKIM (`default._domainkey`), DMARC (`_dmarc`)
- SSL cert expiry for `mail.<domain>` (dedicated) or fallback bare domain cert
- Logs to `/var/log/mail-health-check.log`

**`wp-auto-update.sh`** (new script — option 10)
- Updates WordPress core, plugins, and themes across all installs under `/home/`
- Pre-update compressed MySQL dump saved to `/root/wp-update-backups/` before each site
- Post-update HTTP check (200/301/302); flags failures with the restore command
- WP-CLI auto-installed to `/usr/local/bin/wp` if not present
- Backups older than 7 days pruned automatically
- Installs a weekly cron (`/etc/cron.d/weekly-wp-updates`, Monday 03:00) on first run
- Logs to `/var/log/wp-auto-update.log`

**`db-maintenance.sh`** (new script — option 11)
- Runs `mysqlcheck --optimize --auto-repair` on all user MariaDB databases
- Reports total size per database and top 15 largest tables
- Identifies orphaned databases (no matching `websiteFunctions_websites` row in CyberPanel)
- Reports slow query log status and last 3 slow queries if logging is enabled
- Installs a weekly cron (`/etc/cron.d/weekly-db-maintenance`, Sunday 04:00) on first run
- Logs to `/var/log/db-maintenance.log`

**`server-toolkit.sh`**
- Options 9, 10, 11 added for the three new scripts
- Exit shifted from option 9 to **option 12**
- `show_status()` now tracks `.wp_auto_update_last_run` and `.db_maintenance_last_run` markers
- Cron status check extended: `daily-ssl-renew`, `weekly-wp-updates`, `weekly-db-maintenance`
- Menu prompt updated to `[1-12]`

---

## [1.3.4] – 2026-08-05

### Fixed / Added

**`ssl-auto-issue.sh`**

- **Automatic `mail.<domain>` cert issuance** — added a second daily pass that issues a dedicated Let's Encrypt cert for `mail.<domain>` for every bare domain registered in CyberPanel. Previously only the bare domain itself got a cert; the `mail.` subdomain relied on a fallback that served the bare domain cert, which fails strict hostname verification in SMTP clients because `mail.example.com` is not a SAN on the `example.com` cert. The second pass calls `issue_ssl_hostname("mail.<domain>")` (standalone mode, because `mail.*` has no OLS vhost) so the correct cert exists the morning after a new site is created in CyberPanel.

- **Trust check in `issue_ssl_hostname()`** — the "cert already valid — skipping" check now verifies CA trust via `openssl verify` in addition to expiry. Previously a non-expired self-signed or staging cert (e.g. `issuer=O=Dis, CN=mail.snsinsta.kr`) would be treated as valid and never replaced. Now, untrusted certs trigger a forced production re-issue (`--force --server letsencrypt`) automatically on the next daily cron run.

- **Root cause summary** — `tlsv1 alert internal error` on `mail.<domain>:587` had four stacked causes that applied to every domain on the server, not just one:
  1. `postmap` without `-F` → stored file paths, not cert content → all SNI lookups broken
  2. acme.sh default CA set to staging → all acme.sh-issued certs were staging certs
  3. Staging/self-signed certs in the SNI map → Postfix cannot build TLS context → `internal_error`
  4. No `mail.<domain>` entry in SNI map → bare domain cert served → hostname verification failed

  All four are now fixed and prevented from recurring by default.

---

## [1.3.3] – 2026-08-04

### Fixed (systemic bugs — would repeat on every future domain)

**`setup-mail-ssl.sh`** and **`ssl-auto-issue.sh`**

- **`postmap -F` (root cause of all `tlsv1 alert internal_error` failures)**: `tls_server_sni_maps` requires `postmap -F hash:…`, not plain `postmap hash:…`. Without `-F`, postmap stores the literal `.pem` file path string as the map value; Postfix tries to base64-decode that path string at TLS handshake time, gets garbage, and sends `internal_error` to every SNI-routed client. With `-F`, postmap reads each referenced `.pem` file and embeds its base64-encoded content in the database. Added `chmod 640` on the resulting `.db` file (contains private key material).

- **Staging CA / production CA (`--server letsencrypt`)**: acme.sh's default CA can be set to the staging environment by previous `--staging` runs. All `acme.sh --issue` calls in `issue_ssl_hostname()` now explicitly pass `--server letsencrypt`, and a `--set-default-ca --server letsencrypt` call runs before each issuance to reset the default permanently.

- **Standalone fallback for mail-only hostnames**: `mail.<domain>` subdomains have no OLS vhost, so LiteSpeed returns 404 for HTTP-01 webroot challenges regardless of where the challenge file is placed. The webroot method already falls through to standalone; added a log comment explaining why so the fallback is not mistaken for a bug.

---

## [1.3.2] – 2026-08-04

### Fixed

**`setup-mail-ssl.sh`** and **`ssl-auto-issue.sh`**
- **Root cause confirmed**: `mail.<domain>` SSL certs issued by Let's Encrypt **staging** environment (issuer contains "STAGING") cause Postfix to fail building the TLS context and send `tlsv1 alert internal_error` to connecting SMTP clients — even though the cert structure is technically valid
- Added staging/test cert detection: certs whose issuer contains "staging", "fake", "test", or "invalid" are skipped with a warning; the `mail.<domain>` fallback entry then points to the production bare-domain cert instead
- Added private-key/certificate mismatch detection (`openssl pkey -pubout` vs `openssl x509 -pubkey`): a mismatched pair is silently skipped rather than producing a Postfix `internal_error` at TLS handshake time
- Both checks applied in `setup-mail-ssl.sh` (interactive) and the nightly SNI rebuild block in `ssl-auto-issue.sh`

---

## [1.3.1] – 2026-08-04

### Fixed

**`setup-mail-ssl.sh`**
- **Root cause of `tlsv1 alert internal error`**: Postfix SNI map only had bare domain keys (`example.com`) but WordPress SMTP sends SNI=`mail.example.com` when connecting to `mail.example.com:587`. Postfix did an exact lookup, missed, and if a corrupted `mail.example.com` cert existed in `/etc/letsencrypt/live/` it would fail loading it and send an `internal_error` TLS alert to the client.
- Added `mail.<domain>` fallback entries for every bare domain that has no dedicated mail cert — Postfix now correctly serves the domain cert when the client connects via `mail.<domain>:587`
- Added combined PEM validation (`openssl x509 -noout`) after creation — a bad PEM file is detected and skipped rather than causing Postfix to send `tlsv1 alert internal_error` to all connecting clients
- `SNI_MAPPED_PEM` associative array tracks successful entries to avoid duplicate `mail.*` entries when CyberPanel already issued a valid dedicated cert for `mail.<domain>`

**`ssl-auto-issue.sh`**
- Same `mail.<domain>` fallback and combined PEM validation logic applied to the nightly SNI map rebuild block that runs after cert renewal

---

## [1.3.0] – 2026-08-04

### Added

**`setup-mail-ssl.sh`** (new script)
- Fixes SMTP/SSL mismatch that causes Outlook/Hotmail to reject mail
- Configures Postfix TLS using the server hostname's SSL cert (`postconf -e` — non-destructive, CyberPanel-compatible)
- Configures Dovecot SNI: each hosted domain presents its own SSL cert for IMAP/POP3 connections, eliminating certificate mismatch warnings in Outlook/Thunderbird/Apple Mail
- Ensures Dovecot LMTP unix socket is active so Postfix delivers mail into Dovecot mailboxes correctly
- Enables `lmtp` in Dovecot protocols if not already set
- CyberPanel-safe: writes to `/etc/dovecot/conf.d/99-*` drop-in files only, does not touch CyberPanel-managed config files
- Scans `/etc/letsencrypt/live/*/` for all issued certs (works with both CyberPanel acme.sh and certbot)
- Prints a checklist of remaining manual DNS steps: PTR record (most important for Outlook), SPF, DKIM (via CyberPanel), DMARC
- Accepts `--hostname` flag or auto-detects; falls back to snakeoil cert with a warning if hostname cert is missing
- Re-run any time after adding new domain certs to update the SNI map
- Logs to `/var/log/mail-ssl-setup.log`

**`server-toolkit.sh`**
- New option **8 — Mail SSL Fix** runs `setup-mail-ssl.sh`
- Exit shifted from option 8 to **option 9**
- Status view now tracks `.ssl_auto_issue_last_run` and `.mail_ssl_setup_last_run` markers

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
