"""INPUT-002: Markdown framework registry parse / validate / retrieve."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from auditor.framework_registry import (
    FrameworkNotExecutable,
    FrameworkRegistry,
    deterministic_framework_version,
    load_framework_registry,
)
from auditor.frameworks import (
    frameworks_catalog_text,
    get_requirement_prompt_block,
    list_executable_frameworks,
    list_frameworks,
    load_framework_checklist,
    requirement_index_text,
    route_framework,
)


def _write_fw(
    directory: Path,
    name: str,
    *,
    frontmatter: str | None,
    body: str,
) -> Path:
    path = directory / name
    if frontmatter is None:
        path.write_text(body, encoding="utf-8")
    else:
        path.write_text(f"---\n{frontmatter}\n---\n{body}", encoding="utf-8")
    return path


_VALID_BODY = """# Sample Framework

## REQ-001: Auth method
**Category:** Access Control
**Severity:** High
**Applicability:** All hosts
**Evidence required:** pg_hba.conf excerpt
**How to verify:** Check authentication settings
**Pass criteria:** No trust for remote
**Fail criteria:** trust allowed remotely
**Insufficient evidence criteria:** File unreadable
**Recommendation:** Prefer scram-sha-256
"""


def test_parse_req_and_win_headings(tmp_path: Path) -> None:
    body = """# Mixed Ids

## REQ-001: Classic heading
**Category:** Demo
**Severity:** Low
**How to verify:** echo req
**Pass criteria:** ok

### WIN-001 — Windows identity
**Category:** Inventory
**Severity:** Medium
**Verification guidance:** WinRM hostname
**Pass criteria:** Hostname recorded
"""
    _write_fw(
        tmp_path,
        "mixed.md",
        frontmatter=(
            'id: mixed\nversion: "1.0"\ndescription: Mixed heading shapes\ndomain: cybersecurity\n'
        ),
        body=body,
    )
    registry = load_framework_registry(tmp_path)
    entry = registry.get("mixed")
    assert entry is not None
    assert entry.executable
    assert [r.id for r in entry.requirements] == ["REQ-001", "WIN-001"]
    win = entry.get_requirement("WIN-001")
    assert win is not None
    assert win.title == "Windows identity"
    assert win.verification_guidance == "WinRM hostname"
    assert win.content_hash


def test_no_frontmatter_derives_id_title_and_source_version(tmp_path: Path) -> None:
    body = """# Derived Title Framework

## REQ-001: Control
**Category:** Demo
**Severity:** Low
**How to verify:** echo ok
**Pass criteria:** ok
"""
    path = _write_fw(tmp_path, "derived_fw.md", frontmatter=None, body=body)
    text = path.read_text(encoding="utf-8")
    expected_version = deterministic_framework_version(
        hashlib.sha256(text.encode("utf-8")).hexdigest()
    )
    entry = load_framework_registry(tmp_path).require_executable("derived_fw")
    assert entry.framework.id == "derived_fw"
    assert entry.framework.title == "Derived Title Framework"
    assert entry.version == expected_version
    assert entry.version.startswith("src-")
    assert entry.source_hash
    assert entry.executable


def test_frontmatter_without_version_uses_source_hash(tmp_path: Path) -> None:
    _write_fw(
        tmp_path,
        "no_ver.md",
        frontmatter="id: no_ver\ndescription: Missing version\ndomain: it\n",
        body=_VALID_BODY,
    )
    entry = load_framework_registry(tmp_path).require_executable("no_ver")
    assert entry.version.startswith("src-")
    assert entry.executable


def test_multiline_sections_and_lists(tmp_path: Path) -> None:
    body = """# Multiline Framework

## REQ-001: Multi control
**Category:** Access Control
**Severity:** High
**How to verify:**
1. Collect evidence
2. Inspect configuration
- Confirm remote trust is absent

**Pass criteria:**
All remote rules use scram-sha-256
or certificate authentication

**Recommendation:**
- Prefer scram-sha-256
- Document exceptions
"""
    _write_fw(
        tmp_path,
        "multi.md",
        frontmatter='id: multi\nversion: "1.0"\ndomain: cybersecurity\n',
        body=body,
    )
    entry = load_framework_registry(tmp_path).require_executable("multi")
    req = entry.get_requirement("REQ-001")
    assert req is not None
    assert "1. Collect evidence" in req.verification_guidance
    assert "- Confirm remote trust is absent" in req.verification_guidance
    assert "scram-sha-256" in req.pass_criteria
    assert "certificate authentication" in req.pass_criteria
    assert "- Prefer scram-sha-256" in req.recommendation
    block = req.to_prompt_block()
    assert "1. Collect evidence" in block
    assert "REQ-002" not in block


def test_validate_duplicate_requirement_ids(tmp_path: Path) -> None:
    body = """# Dup Reqs

## REQ-001: First
**Category:** Demo
**Severity:** Low
**How to verify:** a
**Pass criteria:** a

## REQ-001: Second
**Category:** Demo
**Severity:** Low
**How to verify:** b
**Pass criteria:** b
"""
    _write_fw(
        tmp_path,
        "dup_req.md",
        frontmatter='id: dup_req\nversion: "1.0"\ndomain: it\n',
        body=body,
    )
    entry = load_framework_registry(tmp_path).get("dup_req")
    assert entry is not None
    assert not entry.executable
    assert any(i.code == "duplicate_requirement_id" for i in entry.issues)


def test_validate_duplicate_framework_ids(tmp_path: Path) -> None:
    fm = 'id: same_id\nversion: "1.0"\ndomain: it\n'
    _write_fw(tmp_path, "a.md", frontmatter=fm, body=_VALID_BODY)
    _write_fw(tmp_path, "b.md", frontmatter=fm, body=_VALID_BODY)
    registry = load_framework_registry(tmp_path)
    assert len(registry.list_all()) == 2
    assert all(not e.executable for e in registry.list_all())
    assert all(
        any(i.code == "duplicate_framework_id" for i in e.issues) for e in registry.list_all()
    )


def test_validate_empty_required_fields(tmp_path: Path) -> None:
    body = """# Empty Fields

## REQ-001: Has Title
**Category:** Demo
**Severity:** Low
**How to verify:**
**Pass criteria:**
"""
    _write_fw(
        tmp_path,
        "empty.md",
        frontmatter='id: empty\nversion: "1.0"\ndomain: it\n',
        body=body,
    )
    entry = load_framework_registry(tmp_path).get("empty")
    assert entry is not None
    assert not entry.executable
    codes = {i.code for i in entry.issues if i.level == "error"}
    assert "missing_verification_guidance" in codes
    assert "missing_pass_criteria" in codes


def test_invalid_visible_but_not_executable(tmp_path: Path) -> None:
    _write_fw(
        tmp_path,
        "bad.md",
        frontmatter='id: bad_fw\nversion: "1.0"\ndomain: cybersecurity\n',
        body="# Bad\n\nNo requirements here.\n",
    )
    _write_fw(
        tmp_path,
        "good.md",
        frontmatter=(
            "id: good_fw\n"
            'version: "2.0"\n'
            "description: Valid drop-in\n"
            "domain: cybersecurity\n"
            "aliases: [goodfw]\n"
        ),
        body=_VALID_BODY,
    )
    catalog = frameworks_catalog_text(tmp_path)
    assert "bad_fw" in catalog
    assert "INVALID" in catalog
    assert "good_fw" in catalog

    fw = route_framework("please audit goodfw", tmp_path)
    assert fw.id == "good_fw"
    assert fw.executable

    bad = next(f for f in list_frameworks(tmp_path) if f.id == "bad_fw")
    assert bad.executable is False
    with pytest.raises(FrameworkNotExecutable):
        load_framework_checklist(bad)
    with pytest.raises(FrameworkNotExecutable):
        load_framework_registry(tmp_path).require_executable("bad_fw")


def test_catalog_index_and_single_requirement_retrieval(tmp_path: Path) -> None:
    _write_fw(
        tmp_path,
        "demo.md",
        frontmatter=(
            "id: demo\n"
            'version: "1.0"\n'
            "description: Demo framework\n"
            "applicability: Linux servers\n"
            "discovery_guidance: Collect OS release first\n"
            "domain: cybersecurity\n"
        ),
        body=_VALID_BODY,
    )
    registry = FrameworkRegistry.load(tmp_path)
    catalog = registry.catalog_text()
    assert "`demo`" in catalog
    assert "Linux servers" in catalog
    assert "Collect OS release first" in catalog
    # Compact catalog must not embed full requirement bodies.
    assert "Prefer scram-sha-256" not in catalog

    index = requirement_index_text("demo", tmp_path)
    assert "REQ-001" in index
    assert "Auth method" in index
    assert "Prefer scram-sha-256" not in index

    block = get_requirement_prompt_block("demo", "REQ-001", tmp_path)
    assert "REQ-001" in block
    assert "Prefer scram-sha-256" in block
    assert "REQ-002" not in block

    entry = registry.require_executable("demo")
    checklist = entry.to_checklist()
    assert checklist.ids() == ["REQ-001"]
    assert checklist.requirements[0].content_hash


def test_large_framework_parses_and_indexes(tmp_path: Path) -> None:
    reqs = []
    for i in range(1, 121):
        reqs.append(
            f"## REQ-{i:03d}: Control {i}\n"
            f"**Category:** Batch\n"
            f"**Severity:** Low\n"
            f"**How to verify:** check {i}\n"
            f"**Pass criteria:** pass {i}\n"
        )
    _write_fw(
        tmp_path,
        "large.md",
        frontmatter='id: large\nversion: "9.0"\ndomain: cybersecurity\n',
        body="# Large\n\n" + "\n".join(reqs),
    )
    registry = load_framework_registry(tmp_path)
    entry = registry.require_executable("large")
    assert len(entry.requirements) == 120
    index = registry.requirement_index_text("large")
    assert "`REQ-001`" in index
    assert "`REQ-120`" in index
    # Index stays compact: no full verification text for every row.
    assert index.count("How to verify") == 0
    mid = registry.get_requirement("large", "REQ-060")
    assert mid is not None
    assert mid.verification_guidance == "check 60"
    assert mid.content_hash


def test_new_framework_drop_in_without_python_changes(tmp_path: Path) -> None:
    _write_fw(
        tmp_path,
        "brand_new.md",
        frontmatter=None,
        body="""# Brand New Drop In

## REQ-001: Example
**Category:** Demo
**Severity:** Low
**How to verify:** echo brandnew
**Pass criteria:** ok
""",
    )
    frameworks = list_executable_frameworks(tmp_path)
    assert [f.id for f in frameworks] == ["brand_new"]
    assert frameworks[0].version.startswith("src-")
    checklist = load_framework_checklist(frameworks[0])
    assert checklist.ids() == ["REQ-001"]


def test_bundled_agents_remain_executable() -> None:
    registry = load_framework_registry("agents")
    executable = {e.id: e for e in registry.list_executable()}
    assert {
        "postgres_cis",
        "ubuntu_cis_24_l2",
        "host_facts",
        "windows_server",
    } <= set(executable)
    assert all(e.version for e in executable.values())
    assert all(e.requirements for e in executable.values())
    # Bundled agents keep explicit frontmatter versions where authored.
    assert executable["postgres_cis"].version == "1.0"
    assert executable["windows_server"].version


def test_invalid_framework_prompt_retrieval_fail_closed(tmp_path: Path) -> None:
    body = """# Invalid But Parseable

## REQ-001: Leaky control
**Category:** Demo
**Severity:** Low
**How to verify:**
**Pass criteria:**
**Recommendation:** NEVER-LEAK-FROM-INVALID-FRAMEWORK
"""
    _write_fw(
        tmp_path,
        "bad.md",
        frontmatter='id: bad_fw\nversion: "1.0"\ndomain: cybersecurity\n',
        body=body,
    )
    with pytest.raises(FrameworkNotExecutable):
        get_requirement_prompt_block("bad_fw", "REQ-001", tmp_path)


def test_unknown_framework_prompt_retrieval_fail_closed(tmp_path: Path) -> None:
    _write_fw(
        tmp_path,
        "good.md",
        frontmatter='id: good\nversion: "1.0"\ndomain: cybersecurity\n',
        body=_VALID_BODY,
    )
    with pytest.raises(FrameworkNotExecutable) as exc_info:
        get_requirement_prompt_block("missing_fw", "REQ-001", tmp_path)
    assert "missing_fw" in str(exc_info.value)


def test_adhoc_path_cannot_bypass_registry_validation(tmp_path: Path) -> None:
    """Production checklist load must never skip FrameworkRegistry validation."""
    from auditor.frameworks import Framework

    path = _write_fw(
        tmp_path,
        "real.md",
        frontmatter='id: real\nversion: "1.0"\ndomain: cybersecurity\n',
        body=_VALID_BODY,
    )
    # Valid file on disk, but the Framework id is unknown to the registry.
    forged = Framework(
        id="not_registered",
        title="Forged",
        path=path,
        version="1.0",
        description="bypass attempt",
    )
    with pytest.raises(FrameworkNotExecutable):
        load_framework_checklist(forged)


def test_tool_adapter_checklist_and_defect_map_coverage() -> None:
    """TOOL-001…TOOL-005 must appear in both EN/RU checklists and the defect map."""
    import importlib.util
    import re
    import sys

    root = Path(__file__).resolve().parents[1]
    script = root / "scripts" / "validate_defect_map.py"
    spec = importlib.util.spec_from_file_location("validate_defect_map_tools", script)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)

    en = (root / "checklist" / "psql_auditor_master_refactoring_checklist (5).md").read_text(
        encoding="utf-8"
    )
    ru = (root / "checklist" / "psql_auditor_master_refactoring_checklist_ru.md").read_text(
        encoding="utf-8"
    )
    defect_map = (root / "docs" / "defect-module-map.md").read_text(encoding="utf-8")
    wanted = [f"TOOL-{i:03d}" for i in range(1, 6)]
    en_ids = set(mod.extract_checklist_ids(en))
    ru_ids = set(mod.extract_checklist_ids(ru))
    mapped = {row.defect_id for row in mod.parse_defect_map(defect_map)}
    for tool_id in wanted:
        assert tool_id in en_ids
        assert tool_id in ru_ids
        assert tool_id in mapped
        # TOOL-001 may be partial [~] after the SSH registry POC; others stay open.
        if tool_id == "TOOL-001":
            assert re.search(rf"^- \[[ ~]\] `{tool_id}`", en, re.MULTILINE)
            assert re.search(rf"^- \[[ ~]\] `{tool_id}`", ru, re.MULTILINE)
        else:
            assert re.search(rf"^- \[ \] `{tool_id}`", en, re.MULTILINE)
            assert re.search(rf"^- \[ \] `{tool_id}`", ru, re.MULTILINE)
    assert "WIN-001" not in en_ids
    assert "WIN-001" not in ru_ids
    assert "WIN-001" not in mapped
    assert len(en_ids) == 77
    assert len(ru_ids) == 77
