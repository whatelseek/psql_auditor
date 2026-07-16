from psql_auditor.tools.postgres import _is_readonly


def test_allows_select_and_show():
    assert _is_readonly("SHOW ssl;")
    assert _is_readonly("SELECT rolname FROM pg_roles")
    assert _is_readonly("WITH x AS (SELECT 1) SELECT * FROM x")
    assert _is_readonly("-- comment\nSHOW password_encryption")


def test_rejects_mutating_sql():
    assert not _is_readonly("DELETE FROM pg_roles")
    assert not _is_readonly("DROP EXTENSION dblink")
    assert not _is_readonly("SELECT 1; DELETE FROM t")
    assert not _is_readonly("UPDATE pg_settings SET setting='x'")
