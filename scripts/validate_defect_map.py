#!/usr/bin/env python3
"""Validate docs/defect-module-map.md against the canonical checklist.

Extracts defect IDs from checklist checkbox lines and compares them to the
markdown mapping table. Failures exit non-zero for ``make validate-defect-map``.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ALLOWED_STATUSES = frozenset(
    {
        "IMPLEMENTED — DEFECT PRESENT",
        "PARTIALLY IMPLEMENTED",
        "MODULE NOT IMPLEMENTED",
        "LOCATION NOT CONFIRMED",
        "RESOLVED",
    }
)

# Checkbox task lines in the English register, e.g. ``- [x] `AUD-002` — …``
# Prefix may include digits (``E2E-001``).
_CHECKBOX_ID_RE = re.compile(
    r"^- \[[ x~]\] `([A-Z][A-Z0-9]*-\d+)`",
    re.MULTILINE,
)

# Table data rows: | ID | modules | callable | status | evidence |
_TABLE_ROW_RE = re.compile(
    r"^\|\s*(?P<id>[A-Z][A-Z0-9]*-\d+)\s*\|"
    r"(?P<modules>[^|]*)\|"
    r"(?P<callable>[^|]*)\|"
    r"(?P<status>[^|]*)\|"
    r"(?P<evidence>[^|]*)\|?\s*$",
    re.MULTILINE,
)

# Repo-relative path tokens inside the modules cell.
_PATH_RE = re.compile(
    r"(?:^|[\s,;`(\[])("
    r"(?:src|migrations|docs|scripts|\.github)"
    r"/[A-Za-z0-9_./\-]+"
    r"(?:\.[A-Za-z0-9]+)?"
    r")"
)

_ABSENT_MARKERS = (
    "—",
    "-",
    "n/a",
    "na",
    "none",
    "absent",
    "module not implemented",
    "capability absent",
    "(none",
)


@dataclass(frozen=True)
class MapRow:
    """One defect-map table row."""

    defect_id: str
    modules: str
    callable: str
    status: str
    evidence: str
    line_no: int


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of validating a checklist against a defect map."""

    errors: tuple[str, ...]
    checklist_ids: tuple[str, ...]
    mapped_ids: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.errors


def extract_checklist_ids(checklist_text: str) -> list[str]:
    """Return ordered unique defect IDs from checklist checkbox lines."""
    seen: set[str] = set()
    ordered: list[str] = []
    for match in _CHECKBOX_ID_RE.finditer(checklist_text or ""):
        defect_id = match.group(1)
        if defect_id in seen:
            continue
        seen.add(defect_id)
        ordered.append(defect_id)
    return ordered


def parse_defect_map(map_text: str) -> list[MapRow]:
    """Parse defect-map markdown table rows (skips header / separator)."""
    rows: list[MapRow] = []
    for line_no, line in enumerate((map_text or "").splitlines(), start=1):
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        # Skip markdown separator and header.
        if re.match(r"^\|\s*-+", stripped):
            continue
        if re.match(r"^\|\s*Defect ID\s*\|", stripped, re.IGNORECASE):
            continue
        match = _TABLE_ROW_RE.match(stripped)
        if not match:
            continue
        rows.append(
            MapRow(
                defect_id=match.group("id").strip(),
                modules=match.group("modules").strip(),
                callable=match.group("callable").strip(),
                status=match.group("status").strip(),
                evidence=match.group("evidence").strip(),
                line_no=line_no,
            )
        )
    return rows


def extract_module_paths(modules_cell: str) -> list[str]:
    """Return repo-relative production paths referenced in a modules cell."""
    text = modules_cell or ""
    return [m.group(1).rstrip(")`.,;") for m in _PATH_RE.finditer(text)]


def _modules_claim_absent(modules_cell: str) -> bool:
    text = (modules_cell or "").strip().lower()
    if not text:
        return True
    return any(marker in text for marker in _ABSENT_MARKERS)


def validate_defect_map(
    *,
    checklist_text: str,
    map_text: str,
    repo_root: Path,
) -> ValidationResult:
    """Compare checklist IDs to the defect map and validate each row."""
    checklist_ids = extract_checklist_ids(checklist_text)
    rows = parse_defect_map(map_text)
    errors: list[str] = []

    if not checklist_ids:
        errors.append("no defect IDs extracted from checklist checkbox lines")

    mapped_ids = [row.defect_id for row in rows]
    mapped_set = set(mapped_ids)
    checklist_set = set(checklist_ids)

    for defect_id in checklist_ids:
        if defect_id not in mapped_set:
            errors.append(f"missing mapping for checklist defect {defect_id}")

    seen: dict[str, int] = {}
    for row in rows:
        if row.defect_id in seen:
            errors.append(
                f"duplicate mapping for {row.defect_id} "
                f"(lines {seen[row.defect_id]} and {row.line_no})"
            )
        else:
            seen[row.defect_id] = row.line_no

    for defect_id in mapped_ids:
        if defect_id not in checklist_set:
            errors.append(f"map contains unknown defect ID {defect_id}")

    for row in rows:
        if row.status not in ALLOWED_STATUSES:
            errors.append(
                f"{row.defect_id}: unsupported status {row.status!r} (line {row.line_no})"
            )
            continue

        paths = extract_module_paths(row.modules)
        absent_ok = row.status == "MODULE NOT IMPLEMENTED" or _modules_claim_absent(row.modules)

        if not paths and not absent_ok:
            errors.append(
                f"{row.defect_id}: modules cell has neither a production path "
                f"nor an explicit absent-module confirmation (line {row.line_no})"
            )

        if row.status == "MODULE NOT IMPLEMENTED" and paths:
            # Allowed to list related scaffolding paths, but require they exist.
            pass

        for rel in paths:
            target = (repo_root / rel).resolve()
            root = repo_root.resolve()
            try:
                target.relative_to(root)
            except ValueError:
                errors.append(
                    f"{row.defect_id}: path escapes repository root: {rel} (line {row.line_no})"
                )
                continue
            if not target.exists():
                errors.append(
                    f"{row.defect_id}: referenced path does not exist: {rel} (line {row.line_no})"
                )

        if (
            row.status == "MODULE NOT IMPLEMENTED"
            and not paths
            and not _modules_claim_absent(row.modules)
        ):
            errors.append(
                f"{row.defect_id}: MODULE NOT IMPLEMENTED requires an absent "
                f"marker in the modules cell (line {row.line_no})"
            )

    return ValidationResult(
        errors=tuple(errors),
        checklist_ids=tuple(checklist_ids),
        mapped_ids=tuple(mapped_ids),
    )


def default_paths(repo_root: Path) -> tuple[Path, Path]:
    """Resolve canonical checklist and defect-map paths."""
    checklist = repo_root / "checklist" / "psql_auditor_master_refactoring_checklist (5).md"
    defect_map = repo_root / "docs" / "defect-module-map.md"
    return checklist, defect_map


def main(argv: list[str] | None = None) -> int:
    """CLI entry for ``make validate-defect-map``."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository root (default: parent of scripts/).",
    )
    parser.add_argument(
        "--checklist",
        type=Path,
        default=None,
        help="Override checklist path.",
    )
    parser.add_argument(
        "--map",
        dest="map_path",
        type=Path,
        default=None,
        help="Override defect-map path.",
    )
    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve()
    checklist_path, map_path = default_paths(repo_root)
    if args.checklist is not None:
        checklist_path = args.checklist
    if args.map_path is not None:
        map_path = args.map_path

    if not checklist_path.is_file():
        sys.stderr.write(f"ERROR: checklist not found: {checklist_path}\n")
        return 1
    if not map_path.is_file():
        sys.stderr.write(f"ERROR: defect map not found: {map_path}\n")
        return 1

    result = validate_defect_map(
        checklist_text=checklist_path.read_text(encoding="utf-8"),
        map_text=map_path.read_text(encoding="utf-8"),
        repo_root=repo_root,
    )
    sys.stdout.write(
        f"checklist={checklist_path.relative_to(repo_root)} "
        f"ids={len(result.checklist_ids)} "
        f"mapped={len(result.mapped_ids)}\n"
    )
    if result.ok:
        sys.stdout.write("validate-defect-map: OK\n")
        return 0
    sys.stderr.write("validate-defect-map: FAILED\n")
    for err in result.errors:
        sys.stderr.write(f"  - {err}\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
