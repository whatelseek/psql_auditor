-- CORE-001: Separate persistent client_id from audit_run_id
-- SQLite client registry is applied by auditor.client_registry.ClientRegistry.
-- Warehouse audit_sessions columns are also applied by ResultsStore._ensure_schema.

-- Durable clients (SQLite mirror / documentation)
CREATE TABLE IF NOT EXISTS clients (
    client_id       TEXT PRIMARY KEY,
    display_name    TEXT NOT NULL DEFAULT '',
    slug            TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    UNIQUE (slug)
);

CREATE INDEX IF NOT EXISTS clients_slug_idx ON clients (slug);

-- Warehouse: bind each session to a canonical AuditRun (secondary tracker).
-- Do not invent audit_run_id for legacy rows — leave empty and surface via
-- auditor.legacy_compat (AmbiguousLegacyRunError) instead of guessing.
ALTER TABLE audit_sessions
    ADD COLUMN IF NOT EXISTS client_id text NOT NULL DEFAULT '';

ALTER TABLE audit_sessions
    ADD COLUMN IF NOT EXISTS audit_run_id text NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS audit_sessions_audit_run_idx
    ON audit_sessions (audit_run_id)
    WHERE audit_run_id <> '';

CREATE UNIQUE INDEX IF NOT EXISTS audit_sessions_audit_run_uidx
    ON audit_sessions (audit_run_id)
    WHERE audit_run_id <> '';

-- Notes:
-- * audit_sessions is NOT the business AuditRun identity.
-- * Evidence layout is artifacts/<client_slug>/<audit_run_id>/.
-- * Legacy flat artifacts/<ClientName>/ folders without audit_run_id in
--   meta.json are reported by auditor.legacy_compat.report_legacy_without_audit_run
--   and must not be silently treated as the active run.
