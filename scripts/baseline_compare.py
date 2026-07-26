#!/usr/bin/env python3
"""Compare full pytest failures against the documented CORE-000 baseline set.

Exit codes:
  0 — failures ⊆ known baseline (no new regressions)
  1 — new unexpected failures, or baseline file missing expected failures
  2 — pytest / tooling error

Does not hide failures: prints the full pytest summary and the diff against
``docs/baseline-failures.txt``.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "docs" / "baseline-failures.txt"
_FAILED = re.compile(r"^FAILED\s+(\S+)", re.M)


def _load_baseline() -> set[str]:
    if not BASELINE.is_file():
        print(f"ERROR: missing {BASELINE}", file=sys.stderr)
        sys.exit(2)
    out: set[str] = set()
    for line in BASELINE.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        # nodeid [optional comment]
        node = text.split("#", 1)[0].strip()
        if node:
            out.add(node)
    return out


def main() -> int:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "--tb=line"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    output = (proc.stdout or "") + (proc.stderr or "")
    print(output, end="" if output.endswith("\n") else "\n")

    actual = set(_FAILED.findall(output))
    expected = _load_baseline()

    new = sorted(actual - expected)
    missing = sorted(expected - actual)

    print("--- baseline comparison ---")
    print(f"actual failures:   {len(actual)}")
    print(f"baseline failures: {len(expected)}")
    if new:
        print("NEW regressions (not in baseline):")
        for n in new:
            print(f"  + {n}")
    if missing:
        print("baseline entries that now pass (update docs/baseline-failures.txt):")
        for n in missing:
            print(f"  - {n}")
    if not new and not missing:
        print("failures match documented baseline exactly.")
    elif not new:
        print("no new regressions (baseline has stale entries).")

    if new:
        return 1
    # Stale baseline entries are informational; do not fail CI solely for fixes.
    if proc.returncode not in (0, 1):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
