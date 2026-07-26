#!/usr/bin/env python3
"""Run a pytest selection and fail when zero tests are collected.

Used by ``make test-unit``, ``make test-integration``, and ``make test`` so an
empty selection cannot succeed via pytest exit code 5 or shell remapping.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from typing import Sequence

_COLLECTED_RE = re.compile(
    r"(?P<count>\d+)\s+tests?\s+collected",
    re.IGNORECASE,
)
_NO_TESTS_RE = re.compile(r"no tests collected", re.IGNORECASE)
# Quiet collect-only lines look like: ``tests/test_foo.py: 3``
_FILE_COUNT_RE = re.compile(r"^[^\s:][^:]*:\s*(?P<count>\d+)\s*$", re.MULTILINE)
_QUIET_FLAGS = {"-q", "-qq", "--quiet"}


def parse_collected_count(collect_output: str) -> int:
    """Return the number of tests pytest reported during collection."""
    text = collect_output or ""
    if _NO_TESTS_RE.search(text):
        return 0
    matches = list(_COLLECTED_RE.finditer(text))
    if matches:
        return int(matches[-1].group("count"))
    file_counts = [int(m.group("count")) for m in _FILE_COUNT_RE.finditer(text)]
    if file_counts:
        return sum(file_counts)
    return 0


def collect_count(pytest_args: Sequence[str], *, python: str) -> tuple[int, str]:
    """Run ``pytest --collect-only`` and return ``(count, combined_output)``."""
    # Drop quiet flags so pytest emits the standard ``N tests collected`` line.
    # Keep a quiet fallback parser for environments that still suppress it.
    collect_args = [a for a in pytest_args if a not in _QUIET_FLAGS]
    cmd = [python, "-m", "pytest", "--collect-only", *collect_args]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    combined = (proc.stdout or "") + (proc.stderr or "")
    return parse_collected_count(combined), combined


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry: enforce non-empty collection, then run the real suite."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="Python interpreter used to invoke pytest (default: current).",
    )
    parser.add_argument(
        "pytest_args",
        nargs=argparse.REMAINDER,
        help="Arguments forwarded to pytest (prefix with --).",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)
    pytest_args = list(args.pytest_args)
    if pytest_args and pytest_args[0] == "--":
        pytest_args = pytest_args[1:]

    count, collect_out = collect_count(pytest_args, python=args.python)
    if count <= 0:
        sys.stderr.write(
            "ERROR: pytest selected zero tests; refusing to treat this as success.\n"
            f"Selection: {pytest_args!r}\n"
            "--- collect-only output ---\n"
            f"{collect_out}\n"
        )
        return 1

    cmd = [args.python, "-m", "pytest", *pytest_args]
    proc = subprocess.run(cmd, check=False)
    return int(proc.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
