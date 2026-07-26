---
id: postgres_cis_ru
aliases: [postgres, postgresql, psql, database, pg, постгрес, postgres cis, аудит postgres]
description: Чеклист hardening PostgreSQL (RU)
domain: cybersecurity
language: ru
family_id: postgres_cis
detect:
  binaries: [postgres, psql]
  ports: [5432]
version: "1.0"
---
# Чеклист аудита безопасности PostgreSQL

RU-вариант чеклиста для PostgreSQL. Структура требований совместима с парсером
аудитора (`REQ-NNN`, Category/Severity/How to verify/Pass criteria).

## REQ-001: Password encryption method
**Category:** Access Control
**Severity:** High
**How to verify:** Run `SHOW password_encryption;` via SQL. Prefer `scram-sha-256`.
**Pass criteria:** `password_encryption` is `scram-sha-256` (not `md5`).

## REQ-002: pg_hba remote authentication
**Category:** Access Control
**Severity:** Critical
**How to verify:** Read `pg_hba.conf` over SSH (or `SHOW hba_file` then read file). Inspect host/hostssl rules for remote clients.
**Pass criteria:** No `trust` or `md5` for remote (non-local) connections; prefer `scram-sha-256` and/or `cert`.

## REQ-003: Local peer/trust limited
**Category:** Access Control
**Severity:** Medium
**How to verify:** Inspect local and host unix-socket lines in `pg_hba.conf`.
**Pass criteria:** `trust` is not used for network hosts; local trust/peer is justified and documented if present.

## REQ-004: SSL/TLS enabled
**Category:** Encryption
**Severity:** High
**How to verify:** `SHOW ssl;` and confirm TLS-related settings; check `postgresql.conf` for `ssl = on`.
**Pass criteria:** `ssl` is `on` for any network-facing instance.

## REQ-005: SSL client certificates / hostssl
**Category:** Encryption
**Severity:** Medium
**How to verify:** Review `pg_hba.conf` for `hostssl` usage versus plain `host`.
**Pass criteria:** Remote connections use `hostssl` (or equivalent enforced TLS), not cleartext `host` for production traffic.

## REQ-006: Listen addresses
**Category:** Network
**Severity:** High
**How to verify:** `SHOW listen_addresses;` and/or read `postgresql.conf`.
**Pass criteria:** Not unnecessarily `*`; bound to required interfaces only.

## REQ-007: Port exposure
**Category:** Network
**Severity:** Medium
**How to verify:** SSH: check listening sockets (`ss -lntp` / `netstat`) for the Postgres port; confirm firewall expectations.
**Pass criteria:** Postgres port is not exposed beyond intended networks.

## REQ-008: Superuser sprawl
**Category:** Privileges
**Severity:** High
**How to verify:** SQL: list roles with `rolsuper` from `pg_roles` / `pg_authid`.
**Pass criteria:** Only a minimal set of superusers (ideally bootstrap/admin only); no application users are superuser.

## REQ-009: Login roles without password
**Category:** Access Control
**Severity:** High
**How to verify:** SQL: find roles with `rolcanlogin` and null password where password auth is expected.
**Pass criteria:** Login-capable roles that authenticate with passwords have passwords set (except justified peer/cert roles).

## REQ-010: CREATEROLE / CREATEDB hygiene
**Category:** Privileges
**Severity:** Medium
**How to verify:** SQL: list roles with `rolcreaterole` or `rolcreatedb`.
**Pass criteria:** Attribute granted only to administrative roles that require it.

## REQ-011: Public schema privileges
**Category:** Privileges
**Severity:** Medium
**How to verify:** SQL: check default privileges on schema `public` (`has_schema_privilege`, `\dn+` equivalent queries).
**Pass criteria:** `PUBLIC` does not have broad CREATE on `public` in hardened databases (PG15+ default is tighter; confirm).

## REQ-012: Dangerous extensions
**Category:** Extensions
**Severity:** High
**How to verify:** SQL: `SELECT * FROM pg_extension;` and review installed extensions.
**Pass criteria:** No unnecessary high-risk extensions (e.g. `dblink`, `postgres_fdw`, untrusted PL languages) without justification.

## REQ-013: Logging configuration
**Category:** Logging & Monitoring
**Severity:** Medium
**How to verify:** `SHOW log_connections; SHOW log_disconnections; SHOW log_statement; SHOW logging_collector;`
**Pass criteria:** Connection logging enabled; statement logging appropriate for environment; logs collected.

## REQ-014: Log destination and rotation
**Category:** Logging & Monitoring
**Severity:** Low
**How to verify:** SSH/SQL: check `log_directory`, `log_filename`, `log_rotation_age`, file permissions on log dir.
**Pass criteria:** Logs written to a managed location with sensible rotation; not world-writable.

## REQ-015: PostgreSQL version / patch level
**Category:** Patch Management
**Severity:** High
**How to verify:** `SHOW server_version;` and package version via SSH (`psql --version` / distro package).
**Pass criteria:** Running a supported major version with recent security patches.

## REQ-016: Data directory permissions
**Category:** Host Hardening
**Severity:** High
**How to verify:** SSH: resolve data directory (`SHOW data_directory`) and inspect ownership/mode (`ls -ld`).
**Pass criteria:** Data directory owned by postgres OS user; mode not group/world writable (typically `0700`).

## REQ-017: Config file permissions
**Category:** Host Hardening
**Severity:** Medium
**How to verify:** SSH: permissions on `postgresql.conf`, `pg_hba.conf`, `pg_ident.conf`.
**Pass criteria:** Config files not world-writable; readable only by intended OS users.

## REQ-018: Connection limits
**Category:** Availability
**Severity:** Low
**How to verify:** `SHOW max_connections;` and review per-role `CONNECTION LIMIT`.
**Pass criteria:** `max_connections` is set intentionally; critical roles have connection limits where appropriate.

## REQ-019: Idle session / statement timeouts
**Category:** Availability
**Severity:** Medium
**How to verify:** `SHOW idle_in_transaction_session_timeout; SHOW statement_timeout;`
**Pass criteria:** Non-zero timeouts configured where workload allows (or documented exception).

## REQ-020: Replication / archive security
**Category:** High Availability
**Severity:** Medium
**How to verify:** Check if replication is in use (`pg_stat_replication`, `archive_mode`); review replication user auth in `pg_hba.conf`.
**Pass criteria:** Replication users are not superusers unnecessarily; replication auth is scram/cert over TLS where applicable.
