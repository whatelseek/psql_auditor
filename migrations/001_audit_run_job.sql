-- CORE-002: AuditRun / AuditJob (SQLite registry)
-- Applied automatically by auditor.audit_registry.AuditRegistry._ensure_schema.
-- Mirror for documentation / external ops.

CREATE TABLE IF NOT EXISTS audit_runs (
    audit_run_id            TEXT PRIMARY KEY,
    client_id               TEXT NOT NULL DEFAULT '',
    scope_json              TEXT NOT NULL DEFAULT '{}',
    status                  TEXT NOT NULL DEFAULT 'pending',
    created_at              TEXT NOT NULL,
    started_at              TEXT,
    finished_at             TEXT,
    evidence_run_id         TEXT NOT NULL DEFAULT '',
    results_session_number  INTEGER,
    base_thread_id          TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS audit_runs_client_created_idx
    ON audit_runs (client_id, created_at DESC);
CREATE INDEX IF NOT EXISTS audit_runs_status_idx
    ON audit_runs (status);

CREATE TABLE IF NOT EXISTS audit_jobs (
    job_id              TEXT PRIMARY KEY,
    audit_run_id        TEXT NOT NULL REFERENCES audit_runs(audit_run_id)
                            ON DELETE CASCADE,
    job_type            TEXT NOT NULL DEFAULT 'assess_framework',
    logical_task_id     TEXT NOT NULL,
    attempt             INTEGER NOT NULL DEFAULT 1,
    status              TEXT NOT NULL DEFAULT 'pending',
    mandatory           INTEGER NOT NULL DEFAULT 1,
    started_at          TEXT,
    finished_at         TEXT,
    error_json          TEXT,
    thread_id           TEXT NOT NULL DEFAULT '',
    framework_id        TEXT NOT NULL DEFAULT '',
    host_id             TEXT NOT NULL DEFAULT '',
    UNIQUE (audit_run_id, logical_task_id, attempt)
);

CREATE INDEX IF NOT EXISTS audit_jobs_run_idx
    ON audit_jobs (audit_run_id, logical_task_id, attempt);
CREATE INDEX IF NOT EXISTS audit_jobs_status_idx
    ON audit_jobs (status);
