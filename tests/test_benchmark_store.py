"""Tests for cumulative audit benchmark.md ledger."""

from pathlib import Path

from auditor.benchmark_store import BenchmarkStore, findings_to_benchmark_metrics
from auditor.state import Finding


def _finding(req_id: str, status: str, severity: str = "High") -> Finding:
    return Finding(
        requirement_id=req_id,
        title=req_id,
        status=status,  # type: ignore[arg-type]
        severity=severity,
    )


def test_findings_to_metrics():
    findings = {
        "REQ-001": _finding("REQ-001", "pass"),
        "REQ-002": _finding("REQ-002", "fail", "Critical"),
        "REQ-003": _finding("REQ-003", "partial"),
        "REQ-004": _finding("REQ-004", "skipped", "Low"),
    }
    metrics = findings_to_benchmark_metrics(findings)
    assert metrics["pass"] == 1
    assert metrics["fail"] == 1
    assert metrics["partial"] == 1
    assert metrics["skipped"] == 1
    # assessed = 3; score = (1 + 0.5) / 3 = 50%
    assert metrics["assessed"] == 3
    assert metrics["compliance_pct"] == 50.0


def test_benchmark_store_appends_and_rewrites(tmp_path: Path):
    path = tmp_path / "benchmark.md"
    store = BenchmarkStore(path)
    store.ensure_file()
    assert path.is_file()
    assert "No audits recorded yet" in path.read_text(encoding="utf-8")

    findings = {
        "REQ-001": _finding("REQ-001", "pass", "Medium"),
        "REQ-002": _finding("REQ-002", "fail", "Critical"),
    }
    entry = store.append_from_findings(
        run_id="run-abc",
        framework_id="ubuntu_cis",
        findings=findings,
        evidence_relpath="run-abc",
    )
    assert entry is not None
    text = path.read_text(encoding="utf-8")
    assert "ubuntu_cis" in text
    assert "run-abc" in text
    assert "compliance_%" in text
    assert path.with_suffix(".jsonl").is_file()

    # Second framework updates "Latest by framework"
    store.append_from_findings(
        run_id="run-def",
        framework_id="postgres_cis",
        findings={"REQ-001": _finding("REQ-001", "pass")},
        evidence_relpath="run-def",
    )
    text2 = path.read_text(encoding="utf-8")
    assert "postgres_cis" in text2
    assert "ubuntu_cis" in text2


def test_append_skips_empty_findings(tmp_path: Path):
    store = BenchmarkStore(tmp_path / "benchmark.md")
    assert store.append_from_findings(run_id="x", framework_id="ubuntu_cis", findings={}) is None
