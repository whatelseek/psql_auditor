"""Temporary controlled failure for AUD-002 Check 1 — do not keep."""

def test_aud002_deliberate_unit_failure():
    assert False, "AUD-002 controlled unit failure"
