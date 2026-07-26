"""Regression tests for AUD-002 quality-gate scripts and LLM isolation."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import httpx
import pytest

from auditor.testing.fake_llm import use_chat_model_factory

ROOT = Path(__file__).resolve().parents[2]
RUN_GROUP = ROOT / "scripts" / "run_pytest_group.py"


def _load_run_pytest_group():
    spec = importlib.util.spec_from_file_location("run_pytest_group", RUN_GROUP)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run(cmd: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd or ROOT),
        text=True,
        capture_output=True,
        check=False,
    )


def test_parse_collected_count_detects_empty_and_nonzero() -> None:
    mod = _load_run_pytest_group()
    assert mod.parse_collected_count("no tests collected in 0.01s") == 0
    assert mod.parse_collected_count("5 tests collected in 0.12s") == 5
    assert mod.parse_collected_count("1 test collected in 0.01s") == 1


def test_zero_unit_discovery_fails_gate(tmp_path: Path) -> None:
    empty = tmp_path / "empty_unit"
    empty.mkdir()
    (empty / "conftest.py").write_text("import pytest\n", encoding="utf-8")
    proc = _run(
        [
            sys.executable,
            str(RUN_GROUP),
            "--",
            str(empty),
            "-m",
            "unit",
            "-q",
        ]
    )
    assert proc.returncode != 0
    assert "zero tests" in (proc.stderr + proc.stdout).lower()


def test_zero_integration_discovery_fails_gate(tmp_path: Path) -> None:
    empty = tmp_path / "empty_integration"
    empty.mkdir()
    proc = _run(
        [
            sys.executable,
            str(RUN_GROUP),
            "--",
            str(empty),
            "-m",
            "integration",
            "-q",
        ]
    )
    assert proc.returncode != 0
    assert "zero tests" in (proc.stderr + proc.stdout).lower()


def test_deliberately_failing_unit_makes_gate_fail(tmp_path: Path) -> None:
    suite = tmp_path / "fail_unit"
    suite.mkdir()
    (suite / "test_boom.py").write_text(
        textwrap.dedent(
            """
            def test_boom():
                assert False, "deliberate failure"
            """
        ),
        encoding="utf-8",
    )
    proc = _run(
        [
            sys.executable,
            str(RUN_GROUP),
            "--",
            str(suite),
            "-q",
        ]
    )
    assert proc.returncode != 0


def test_format_check_fails_on_violation(tmp_path: Path) -> None:
    bad = tmp_path / "bad_fmt.py"
    bad.write_text("x=1+2\n", encoding="utf-8")
    proc = _run([sys.executable, "-m", "ruff", "format", "--check", str(bad)])
    assert proc.returncode != 0


def test_lint_fails_on_violation(tmp_path: Path) -> None:
    bad = tmp_path / "bad_lint.py"
    bad.write_text("import os\n", encoding="utf-8")
    proc = _run([sys.executable, "-m", "ruff", "check", str(bad)])
    assert proc.returncode != 0


def test_typecheck_fails_on_violation(tmp_path: Path) -> None:
    bad = tmp_path / "bad_types.py"
    bad.write_text(
        textwrap.dedent(
            """
            def add(a: int, b: int) -> int:
                return a + b

            reveal = add("x", "y")
            """
        ),
        encoding="utf-8",
    )
    proc = _run([sys.executable, "-m", "mypy", str(bad), "--no-error-summary"])
    assert proc.returncode != 0


@pytest.mark.asyncio
async def test_deterministic_llm_fake_without_network(canonical_scenario) -> None:
    fake = canonical_scenario.build_fake_llm("valid_structured_en")
    previous = use_chat_model_factory(lambda _settings: fake)
    try:
        from auditor.llm import build_chat_model

        model = build_chat_model()
        result = await model.ainvoke([{"role": "user", "content": "ping"}])
        assert "SSH root login enabled" in str(result.content)
        assert fake.calls, "fake must record prompts/calls"
        assert fake.calls[0]["messages"]
    finally:
        use_chat_model_factory(previous)


def test_external_llm_http_is_rejected_in_mandatory_tests() -> None:
    assert os.environ.get("AUDITOR_ALLOW_EXTERNAL_LLM", "") != "1"
    with pytest.raises(RuntimeError, match="External LLM"):
        httpx.get("https://api.openai.com/v1/models", timeout=1.0)
