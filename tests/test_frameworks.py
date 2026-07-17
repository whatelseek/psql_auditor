from pathlib import Path

import pytest

from psql_auditor.frameworks import (
    frameworks_catalog_text,
    list_frameworks,
    load_framework_checklist,
    route_framework,
)


def test_discovers_agents_directory(tmp_path: Path):
    (tmp_path / "custom_cis.md").write_text(
        "---\n"
        "id: custom_cis\n"
        "aliases: [custom, acme]\n"
        "description: Acme custom benchmark\n"
        "---\n"
        "# Acme CIS\n\n"
        "## REQ-001: Example\n"
        "**Category:** Demo\n"
        "**Severity:** Low\n"
        "**How to verify:** echo ok\n"
        "**Pass criteria:** ok\n",
        encoding="utf-8",
    )
    frameworks = list_frameworks(tmp_path)
    assert len(frameworks) == 1
    assert frameworks[0].id == "custom_cis"
    assert "acme" in frameworks[0].aliases
    checklist = load_framework_checklist(frameworks[0])
    assert checklist.ids() == ["REQ-001"]


def test_route_framework_by_alias():
    agents = Path("agents")
    fw = route_framework("Please run an Ubuntu CIS host audit", agents)
    assert fw.id == "ubuntu_cis"
    fw = route_framework("windows server hardening cis", agents)
    assert fw.id == "windows_cis"
    fw = route_framework("audit postgresql scram and ssl", agents)
    assert fw.id == "postgres_cis"


def test_catalog_lists_drop_ins():
    text = frameworks_catalog_text("agents")
    assert "postgres_cis" in text
    assert "ubuntu_cis" in text
    assert "windows_cis" in text


def test_empty_agents_dir_raises():
    with pytest.raises(FileNotFoundError):
        route_framework("anything", Path("/tmp/no-agents-here-psql-auditor"))
