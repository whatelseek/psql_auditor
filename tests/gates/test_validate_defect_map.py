"""Tests for AUD-001 defect-map completeness validation."""

from __future__ import annotations

import importlib.util
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "validate_defect_map.py"

ALLOWED_STATUSES = (
    "IMPLEMENTED — DEFECT PRESENT",
    "PARTIALLY IMPLEMENTED",
    "MODULE NOT IMPLEMENTED",
    "LOCATION NOT CONFIRMED",
    "RESOLVED",
)


def _load():
    name = "validate_defect_map"
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _map_doc(rows: list[tuple[str, str, str, str, str]]) -> str:
    header = (
        "| Defect ID | Production module(s) | Main callable/class | "
        "Implementation status | Evidence/notes |"
    )
    sep = (
        "| --------- | -------------------- | ------------------- | "
        "--------------------- | -------------- |"
    )
    lines = ["# Defect map", "", header, sep]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines) + "\n"


def _checklist(ids: list[str]) -> str:
    lines = ["# Checklist", "", "## Task register", ""]
    for defect_id in ids:
        lines.append(f"- [ ] `{defect_id}` — title")
    return "\n".join(lines) + "\n"


def test_complete_valid_mapping(tmp_path: Path) -> None:
    mod = _load()
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "demo.py").write_text("x = 1\n", encoding="utf-8")
    result = mod.validate_defect_map(
        checklist_text=_checklist(["AUD-001", "CORE-001"]),
        map_text=_map_doc(
            [
                ("AUD-001", "`src/demo.py`", "demo", "RESOLVED", "ok"),
                (
                    "CORE-001",
                    "— (capability absent)",
                    "—",
                    "MODULE NOT IMPLEMENTED",
                    "missing on purpose",
                ),
            ]
        ),
        repo_root=tmp_path,
    )
    assert result.ok, result.errors


def test_missing_defect(tmp_path: Path) -> None:
    mod = _load()
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "demo.py").write_text("x=1\n", encoding="utf-8")
    result = mod.validate_defect_map(
        checklist_text=_checklist(["AUD-001", "AUD-002"]),
        map_text=_map_doc([("AUD-001", "`src/demo.py`", "x", "PARTIALLY IMPLEMENTED", "only one")]),
        repo_root=tmp_path,
    )
    assert not result.ok
    assert any("missing mapping for checklist defect AUD-002" in e for e in result.errors)


def test_duplicate_defect(tmp_path: Path) -> None:
    mod = _load()
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "demo.py").write_text("x=1\n", encoding="utf-8")
    mapping = _map_doc(
        [
            ("AUD-001", "`src/demo.py`", "x", "RESOLVED", "a"),
            ("AUD-001", "`src/demo.py`", "x", "RESOLVED", "b"),
        ]
    )
    result = mod.validate_defect_map(
        checklist_text=_checklist(["AUD-001"]),
        map_text=mapping,
        repo_root=tmp_path,
    )
    assert not result.ok
    assert any("duplicate mapping for AUD-001" in e for e in result.errors)


def test_unknown_defect_id(tmp_path: Path) -> None:
    mod = _load()
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "demo.py").write_text("x=1\n", encoding="utf-8")
    result = mod.validate_defect_map(
        checklist_text=_checklist(["AUD-001"]),
        map_text=_map_doc(
            [
                ("AUD-001", "`src/demo.py`", "x", "RESOLVED", "a"),
                ("ZZZ-999", "`src/demo.py`", "x", "RESOLVED", "ghost"),
            ]
        ),
        repo_root=tmp_path,
    )
    assert not result.ok
    assert any("unknown defect ID ZZZ-999" in e for e in result.errors)


def test_unsupported_status(tmp_path: Path) -> None:
    mod = _load()
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "demo.py").write_text("x=1\n", encoding="utf-8")
    result = mod.validate_defect_map(
        checklist_text=_checklist(["AUD-001"]),
        map_text=_map_doc([("AUD-001", "`src/demo.py`", "x", "DONE", "bad status")]),
        repo_root=tmp_path,
    )
    assert not result.ok
    assert any("unsupported status" in e for e in result.errors)


def test_nonexistent_module_path(tmp_path: Path) -> None:
    mod = _load()
    (tmp_path / "src").mkdir()
    result = mod.validate_defect_map(
        checklist_text=_checklist(["AUD-001"]),
        map_text=_map_doc(
            [
                (
                    "AUD-001",
                    "`src/missing.py`",
                    "x",
                    "PARTIALLY IMPLEMENTED",
                    "path gone",
                )
            ]
        ),
        repo_root=tmp_path,
    )
    assert not result.ok
    assert any("does not exist: src/missing.py" in e for e in result.errors)


def test_valid_module_not_implemented_without_path(tmp_path: Path) -> None:
    mod = _load()
    result = mod.validate_defect_map(
        checklist_text=_checklist(["CORE-004"]),
        map_text=_map_doc(
            [
                (
                    "CORE-004",
                    "— (capability absent)",
                    "—",
                    "MODULE NOT IMPLEMENTED",
                    "no AssessmentResult",
                )
            ]
        ),
        repo_root=tmp_path,
    )
    assert result.ok, result.errors


def test_extracts_e2e_id_with_digit_in_prefix() -> None:
    mod = _load()
    text = textwrap.dedent(
        """
        - [ ] `CI-001` — pipeline
        - [ ] `E2E-001` — acceptance
        """
    )
    assert mod.extract_checklist_ids(text) == ["CI-001", "E2E-001"]


@pytest.mark.parametrize("status", ALLOWED_STATUSES)
def test_allowed_statuses_recognized(status: str, tmp_path: Path) -> None:
    mod = _load()
    if status == "MODULE NOT IMPLEMENTED":
        modules = "— (capability absent)"
    else:
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "x.py").write_text("x=1\n", encoding="utf-8")
        modules = "`src/x.py`"
    result = mod.validate_defect_map(
        checklist_text=_checklist(["AUD-001"]),
        map_text=_map_doc([("AUD-001", modules, "x", status, "note")]),
        repo_root=tmp_path,
    )
    assert result.ok, result.errors
