"""Tests for WinRM inventory parsing and tool formatting."""

from unittest.mock import MagicMock, patch

import pytest

from auditor.config import Settings
from auditor.runtime_target import (
    bind_runtime_target,
    effective_settings,
    runtime_target_from_winrm,
)
from auditor.secrets_file import (
    _access_kind,
    _parse_credentials_table,
    list_inventory_ssh_targets,
)
from auditor.tools.winrm import _format_winrm_result, get_winrm_tools, winrm_run


def test_access_kind_winrm():
    assert _access_kind("WinRM") == "winrm"
    assert _access_kind("Windows WinRM") == "winrm"
    assert _access_kind("windows") == "ssh"  # OpenSSH row label
    assert _access_kind("SSH") == "ssh"


def test_parse_winrm_inventory_row():
    text = """
| Access | Host | Port | Username | Password / Token | Extra |
|--------|------|------|----------|------------------|-------|
| WinRM | 10.0.0.20 | 5985 | Administrator | s3cret | transport=ntlm |
| WinRM | 10.0.0.21 | 5986 | Administrator | s3cret | |
"""
    parsed = _parse_credentials_table(text)
    # Last WinRM row wins for process-wide defaults (same as PG)
    assert parsed["WINRM_HOST"] == "10.0.0.21"
    assert parsed["WINRM_PORT"] == "5986"
    assert parsed["WINRM_USE_SSL"] == "true"
    assert parsed["WINRM_PASSWORD"] == "s3cret"

    targets = list_inventory_ssh_targets(text)
    assert len(targets) == 2
    assert targets[0].is_winrm
    assert targets[0].host == "10.0.0.20"
    assert targets[0].port == "5985"
    assert targets[0].winrm_transport == "ntlm"
    assert targets[1].port == "5986"


def test_runtime_winrm_overlay():
    settings = Settings(_env_file=None)
    with bind_runtime_target(
        runtime_target_from_winrm(
            host="10.0.0.20",
            port="5985",
            user="Administrator",
            password="pw",
            transport="ntlm",
        )
    ):
        eff = effective_settings(settings)
        assert eff.winrm_host == "10.0.0.20"
        assert eff.winrm_user == "Administrator"
        assert eff.winrm_password == "pw"
        assert eff.winrm_transport == "ntlm"


def test_format_winrm_result():
    result = MagicMock()
    result.status_code = 0
    result.std_out = b"hostname\r\n"
    result.std_err = b""
    text = _format_winrm_result(result)
    assert "exit_code=0" in text
    assert "hostname" in text


@pytest.mark.asyncio
async def test_winrm_run_requires_host():
    settings = Settings(_env_file=None, winrm_host=None)
    with patch(
        "auditor.tools.winrm.effective_settings", return_value=settings
    ):
        out = await winrm_run.ainvoke({"command": "hostname"})
    assert out.lower().startswith("winrm error")


def test_get_winrm_tools_names():
    names = [t.name for t in get_winrm_tools()]
    assert names == ["winrm_run", "winrm_read_file"]
