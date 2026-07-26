-- CORE-003: Canonical result identity on requirement_results
-- Applied by ResultsStore._ensure_schema (ALTER + unique indexes).
-- Do not backfill identity columns with placeholder values.

ALTER TABLE requirement_results
    ADD COLUMN IF NOT EXISTS result_id UUID;

ALTER TABLE requirement_results
    ADD COLUMN IF NOT EXISTS client_id text;

ALTER TABLE requirement_results
    ADD COLUMN IF NOT EXISTS audit_run_id text;

ALTER TABLE requirement_results
    ADD COLUMN IF NOT EXISTS asset_id text;

ALTER TABLE requirement_results
    ADD COLUMN IF NOT EXISTS framework_id text;

ALTER TABLE requirement_results
    ADD COLUMN IF NOT EXISTS framework_version text;

-- Physical identity
CREATE UNIQUE INDEX IF NOT EXISTS requirement_results_result_id_uidx
    ON requirement_results (result_id)
    WHERE result_id IS NOT NULL;

-- Full logical key (only rows that have complete identity)
CREATE UNIQUE INDEX IF NOT EXISTS requirement_results_logical_key_uidx
    ON requirement_results (
        client_id,
        audit_run_id,
        asset_id,
        framework_id,
        framework_version,
        req_id
    )
    WHERE client_id IS NOT NULL
      AND audit_run_id IS NOT NULL
      AND asset_id IS NOT NULL
      AND framework_id IS NOT NULL
      AND framework_version IS NOT NULL
      AND req_id IS NOT NULL;

ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS asset_id text;

CREATE UNIQUE INDEX IF NOT EXISTS hosts_asset_id_uidx
    ON hosts (asset_id)
    WHERE asset_id IS NOT NULL;
