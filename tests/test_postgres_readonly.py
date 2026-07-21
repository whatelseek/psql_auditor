"""Unit tests for the shared read-only SQL gate."""

from auditor.tools.postgres import is_readonly_sql


def test_allows_select_and_show():
    assert is_readonly_sql("SHOW ssl;")
    assert is_readonly_sql("SELECT rolname FROM pg_roles")
    assert is_readonly_sql("WITH x AS (SELECT 1) SELECT * FROM x")
    assert is_readonly_sql("-- comment\nSHOW password_encryption")


def test_rejects_mutating_sql():
    assert not is_readonly_sql("DELETE FROM pg_roles")
    assert not is_readonly_sql("DROP EXTENSION dblink")
    assert not is_readonly_sql("SELECT 1; DELETE FROM t")
    assert not is_readonly_sql("UPDATE pg_settings SET setting='x'")
