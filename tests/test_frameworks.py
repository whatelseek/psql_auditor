from pathlib import Path

import pytest

from auditor.frameworks import (
    frameworks_catalog_text,
    list_frameworks,
    load_framework_checklist,
    route_framework,
    route_frameworks,
    select_frameworks_for_host,
)
from auditor.host_facts import HostFacts


def test_discovers_agents_directory(tmp_path: Path):
    (tmp_path / "custom_cis.md").write_text(
        "---\n"
        "id: custom_cis\n"
        "aliases: [custom, acme]\n"
        "description: Acme custom benchmark\n"
        "domain: cybersecurity\n"
        "detect:\n"
        "  os_ids: [acmeos]\n"
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
    assert frameworks[0].domain == "cybersecurity"
    assert frameworks[0].detect.os_ids == ("acmeos",)
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
        route_framework("anything", Path("/tmp/no-agents-here-auditor"))


def test_route_frameworks_multi_postgres_and_ubuntu():
    selected = route_frameworks(
        "Conduct PostgreSQL and Ubuntu CIS audit",
        "agents",
    )
    ids = {fw.id for fw in selected}
    assert ids == {"postgres_cis", "ubuntu_cis"}


def test_route_frameworks_single_when_one_named():
    selected = route_frameworks("Windows Server CIS hardening only", "agents")
    assert [fw.id for fw in selected] == ["windows_cis"]


def test_select_frameworks_for_ubuntu_postgres_host():
    facts = HostFacts(
        hostname="db-01",
        os_id="ubuntu",
        binaries=["postgres", "psql"],
        listening_ports=[5432],
    )
    selected = select_frameworks_for_host(
        facts, domains=["it", "cybersecurity"], agents_dir="agents"
    )
    ids = [fw.id for fw in selected]
    assert ids[0] == "it_audit"
    assert "ubuntu_cis" in ids
    assert "postgres_cis" in ids
    assert "windows_cis" not in ids


def test_select_frameworks_it_domain_only():
    facts = HostFacts(hostname="db-01", os_id="ubuntu", binaries=["psql"])
    selected = select_frameworks_for_host(
        facts, domains=["it"], agents_dir="agents"
    )
    assert [fw.id for fw in selected] == ["it_audit"]


def test_select_frameworks_windows():
    facts = HostFacts(hostname="win-01", os_id="windows")
    selected = select_frameworks_for_host(
        facts, domains=["cybersecurity"], agents_dir="agents"
    )
    assert [fw.id for fw in selected] == ["windows_cis"]


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
        route_framework("anything", Path("/tmp/no-agents-here-auditor"))


def test_route_frameworks_multi_postgres_and_ubuntu():
    selected = route_frameworks(
        "Conduct PostgreSQL and Ubuntu CIS audit",
        "agents",
    )
    ids = {fw.id for fw in selected}
    assert ids == {"postgres_cis", "ubuntu_cis"}


def test_route_frameworks_single_when_one_named():
    selected = route_frameworks("Windows Server CIS hardening only", "agents")
    assert [fw.id for fw in selected] == ["windows_cis"]
